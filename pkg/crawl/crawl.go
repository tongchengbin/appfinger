package crawl

import (
	"context"
	"errors"
	"fmt"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/retryablehttp-go"
	"net/http"
	"net/url"
	"sync"
)

// Crawler 定义爬虫的核心结构
type Crawler struct {
	options      *Options
	httpClient   *retryablehttp.Client
	clientInitMu sync.Once
}

// NewCrawler 创建新的爬虫实例
func NewCrawler(options *Options) *Crawler {
	c := &Crawler{options: options}
	c.initClient()
	return c
}

// initClient 初始化HTTP客户端
func (c *Crawler) initClient() {
	c.clientInitMu.Do(func() {
		opts := retryablehttp.DefaultOptionsSpraying
		opts.Timeout = c.options.Timeout
		opts.KillIdleConn = true
		transport := retryablehttp.DefaultReusePooledTransport()
		if c.options.Proxy != "" {
			transport.Proxy = func(request *http.Request) (*url.URL, error) {
				return url.Parse(c.options.Proxy)
			}
		}
		opts.HttpClient = retryablehttp.DefaultClient()
		opts.HttpClient.Transport = transport
		c.httpClient = retryablehttp.NewClient(opts)
	})
}

// GetClient 获取HTTP客户端
func (c *Crawler) GetClient() *retryablehttp.Client {
	c.initClient()
	return c.httpClient
}

// GetBanners 实现BannerProvider接口
func (c *Crawler) GetBanners(ctx context.Context, uri string) ([]*Banner, error) {
	var banners []*Banner
	var nextURI = uri
	var banner *Banner
	var err error
	// 处理重定向，最多跟踪3次
RedirectLoop:
	for ret := 0; ret < 3; ret++ {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
			banner, nextURI, err = RequestOnce(c.httpClient, nextURI)
			if err != nil {
				gologger.Debug().Msgf("Req Error:%v", err)
				break RedirectLoop
			}

			// 如果nextURI为空，则不再继续请求
			if nextURI == "" {
				banners = append(banners, banner)
				break RedirectLoop
			}
			if c.options.DebugResp {
				if banner.Certificate != "" {
					fmt.Println("Dump Cert For " + banner.Uri + "\r\n" + banner.Certificate)
				}
				fmt.Println("Dump Response For " + banner.Uri + "\r\n" + banner.Response)
			}
			banners = append(banners, banner)
			if nextURI == "" {
				break
			}
		}
	}
	if len(banners) == 0 {
		return nil, errors.New(fmt.Sprintf("Get %s Error!", uri))
	}
	// 获取最后一个Banner（最终页面）
	finalBanner := banners[len(banners)-1]
	// 获取网站图标
	if !c.options.DisableIcon {
		_, err = readICON(c.httpClient, finalBanner)
		if err != nil {
			gologger.Debug().Msg(err.Error())
		}
	}
	return banners, nil
}

func (c *Crawler) GetBanner(ctx context.Context, uri string) (*Banner, error) {
	banners, err := c.GetBanners(ctx, uri)
	if err != nil {
		return nil, err
	}
	return banners[0], nil
}
