package crawl

import (
	"fmt"
	"github.com/pkg/errors"
	"github.com/projectdiscovery/gologger"
	"github.com/tongchengbin/appfinger/pkg/rule"
	"net/http"
	"net/url"
)

type Crawl struct {
	options *Options
	finger  *rule.Finger
}

func NewCrawl(options *Options, finger *rule.Finger) *Crawl {
	return &Crawl{
		finger:  finger,
		options: options,
	}
}

func (c *Crawl) Match(uri string) (banner *rule.Banner, m map[string]map[string]string, err error) {
	// fix url
	u, err := url.Parse(uri)
	if err != nil {
		return nil, m, err
	}
	if (u.Scheme == "http" && u.Port() == "80") || (u.Scheme == "https" && u.Port() == "443") {
		u.Host = u.Hostname()
	}
	uri = u.String()
	opts := []ClientOption{
		WithTimeout(c.options.Timeout),
	}
	if c.options.Proxy != "" {
		opts = append(opts, WithProxy(c.options.Proxy))
	}
	client, err := NewClient(opts...)
	if err != nil {
		return nil, m, err
	}
	defer client.CloseIdleConnections()
	var banners []*rule.Banner
	var nextURI = uri
	for ret := 0; ret < 3; ret++ {
		banner, nextURI, err = RequestOnce(client, nextURI)
		if err != nil {
			gologger.Debug().Msgf("Req Error:%v", err)
			break
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
	if banner == nil {
		return nil, nil, errors.New(fmt.Sprintf("Get %s Error!", uri))
	}
	// fetch icon
	_, err = readICON(client, banners[len(banners)-1])
	if err != nil {
		gologger.Debug().Msg(err.Error())
	}
	// 匹配插件
	fingerprints := map[string]map[string]string{}
	for index, b := range banners {
		if index > 10 {
			break
		}
		for _, r := range c.finger.Rules["http"] {
			ok, extract := r.Match(b)
			if ok && len(r.Plugins) > 0 {
				// 插件匹配
				for _, plugin := range r.Plugins {
					pluginBanners, err := c.ExecuteWithPlugin(client, b.Uri, plugin)
					if err != nil {
						gologger.Debug().Msgf("Err %s", err.Error())
					}
					banners = append(banners, pluginBanners...)
				}

			} else if ok {
				// 规则匹配
				if fingerprints[r.Name] == nil {
					fingerprints[r.Name] = extract
				} else {
					for k, v := range extract {
						fingerprints[r.Name][k] = v
					}
				}
			}
		}
	}
	if len(banners) == 0 {
		return nil, nil, nil
	}
	// merge result
	if _, ok := fingerprints["honeypot"]; ok {
		return banners[len(banners)-1], map[string]map[string]string{"honeypot": make(map[string]string)}, nil
	}
	if _, ok := fingerprints["Wordpress"]; ok {
		fingerprints = mergeMaps(fingerprints, rule.MatchWpPlugin(banners[len(banners)-1]))
	}
	return banners[len(banners)-1], fingerprints, nil
}

func (c *Crawl) ExecuteWithPlugin(client *http.Client, baseURL string, plugin *rule.Plugin) ([]*rule.Banner, error) {
	gologger.Debug().Msgf("Execute with Plugin: %s", plugin.Path)
	newURl := urlJoin(baseURL, plugin.Path)
	var banners []*rule.Banner
	var nextURI = newURl
	var banner *rule.Banner
	var err error
	for ret := 0; ret < 3; ret++ {
		banner, nextURI, err = RequestOnce(client, nextURI)
		if err != nil {
			break
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
	return banners, nil

}

func mergeMaps(map1, map2 map[string]map[string]string) map[string]map[string]string {
	result := make(map[string]map[string]string)
	// 遍历第一个 map
	for key, value := range map1 {
		result[key] = value
	}
	// 遍历第二个 map
	for key, value := range map2 {
		// 如果键已存在，则根据需求选择合并或覆盖值
		// 这里选择覆盖
		result[key] = value
	}
	return result
}
