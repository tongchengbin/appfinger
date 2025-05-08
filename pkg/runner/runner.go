package runner

import (
	"context"
	"fmt"
	"github.com/projectdiscovery/gologger"
	"github.com/tongchengbin/appfinger/pkg/crawl"
	"github.com/tongchengbin/appfinger/pkg/rule"
	"net/url"
	"path"
)

// Result 表示指纹识别结果
type Result struct {
	Banner      interface{}
	Fingerprint map[string]map[string]string
}

// Runner 负责协调爬虫和规则匹配的执行流程
type Runner struct {
	crawler     *crawl.Crawler
	ruleManager *rule.RuleManager
}

// NewRunner 创建新的Runner实例
func NewRunner(crawler *crawl.Crawler, ruleManager *rule.RuleManager) *Runner {
	return &Runner{
		crawler:     crawler,
		ruleManager: ruleManager,
	}
}

// NewDefaultRunner 创建默认的Runner实例
func NewDefaultRunner(options *crawl.Options, finger *rule.Finger) *Runner {
	crawler := crawl.NewCrawler(options)
	var ruleManager *rule.RuleManager
	if finger == nil {
		ruleManager = rule.GetRuleManager()
	}

	return &Runner{
		crawler:     crawler,
		ruleManager: ruleManager,
	}
}

// Scan 扫描URL
func (r *Runner) Scan(uri string) (*Result, error) {
	return r.ScanWithContext(context.Background(), uri)
}

// ScanWithContext 执行指纹识别流程
func (r *Runner) ScanWithContext(ctx context.Context, uri string) (*Result, error) {
	// 获取网站信息
	banner, err := r.crawler.GetBanner(ctx, uri)
	if err != nil {
		return nil, err
	}
	// get matcher
	finger := rule.GetRuleManager().GetFinger()
	println("FFF", finger)
	// 创建Banner适配器
	getMatchPart := func(part string) string {
		println(">>>", part)
		switch part {
		case "url":
			return banner.Uri
		case "body":
			return banner.Body
		case "header":
			return banner.Header
		case "cert":
			return banner.Certificate
		case "title":
			return banner.Title
		case "response":
			return banner.Response
		case "icon_hash":
			return fmt.Sprintf("%v", banner.IconHash)
		case "body_hash":
			return fmt.Sprintf("%v", banner.BodyHash)
		case "server":
			return banner.Headers["Server"]
		}
		return ""
	}
	println("12333")
	result := finger.Match("http", getMatchPart)
	return &Result{
		Banner:      banner,
		Fingerprint: result,
	}, nil
}

// RunWithPlugins 执行带插件的指纹识别流程
//func (r *Runner) RunWithPlugins(ctx context.Context, uri string) (*Result, error) {
//	// 获取网站信息
//	banner, err := r.crawler.GetBanner(ctx, uri)
//	if err != nil {
//		return nil, err
//	}
//
//	// 匹配规则并处理插件
//	var banners []*common.Banner
//	banners = append(banners, banner)
//
//	// 匹配指纹
//	fingerprints := map[string]map[string]string{}
//
//	// 最多处理10个Banner（包括插件生成的）
//	for index, b := range banners {
//		if index > 10 {
//			break
//		}
//
//		// 匹配规则
//		matched, err := r.matcher.Match(b)
//		if err != nil {
//			gologger.Debug().Msgf("Error matching rules: %v", err)
//			continue
//		}
//
//		// 合并结果
//		for name, values := range matched {
//			if fingerprints[name] == nil {
//				fingerprints[name] = values
//			} else {
//				for k, v := range values {
//					fingerprints[name][k] = v
//				}
//			}
//
//			// 处理插件
//			if r.ruleManager != nil {
//				rule := r.ruleManager.FindRuleByName(name)
//				if rule != nil && len(rule.Plugins) > 0 {
//					for _, plugin := range rule.Plugins {
//						pluginBanners, err := r.crawler.ExecuteWithPlugin(ctx, b.Uri, plugin)
//						if err != nil {
//							gologger.Debug().Msgf("Plugin execution error: %s", err.Error())
//							continue
//						}
//						banners = append(banners, pluginBanners...)
//					}
//				}
//			}
//		}
//	}
//
//	// 特殊处理
//	if _, ok := fingerprints["honeypot"]; ok {
//		return &Result{
//			Banner:      banner,
//			Fingerprint: map[string]map[string]string{"honeypot": make(map[string]string)},
//		}, nil
//	}
//
//	// WordPress插件匹配 - 这里需要修改为使用适当的方法
//	if _, ok := fingerprints["Wordpress"]; ok {
//		// 使用公共合并方法，但需要处理WordPress插件匹配
//		// 在实际实现中，可以将这部分逻辑移到专门的WordPress处理模块
//		// 这里暂时不处理
//	}
//
//	return &Result{
//		Banner:      banner,
//		Fingerprint: fingerprints,
//	}, nil
//}

// urlJoin 连接基础URL和路径
func urlJoin(baseURL, urlPath string) string {
	parsedURL, err := url.Parse(baseURL)
	if err != nil {
		return baseURL
	}

	parsedURL.Path = path.Join(parsedURL.Path, urlPath)
	return parsedURL.String()
}

// ExecuteWithPlugin 使用插件执行额外请求
func (r *Runner) ExecuteWithPlugin(ctx context.Context, baseURL string, plugin *rule.Plugin) ([]*crawl.Banner, error) {
	gologger.Debug().Msgf("Execute with Plugin: %s", plugin.Path)
	newURL := urlJoin(baseURL, plugin.Path)

	var banners []*crawl.Banner
	var nextURI = newURL
	var banner *crawl.Banner
	var err error

	for ret := 0; ret < 3; ret++ {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
			banner, nextURI, err = crawl.RequestOnce(r.crawler.GetClient(), nextURI)
			if err != nil {
				break
			}
			banners = append(banners, banner)

			if nextURI == "" {
				break
			}
		}
	}

	return banners, nil
}

// Match 兼容旧版API的匹配方法
func (r *Runner) Match(uri string) (banner *crawl.Banner, m map[string]map[string]string, err error) {
	// 使用背景上下文，以便与旧API兼容
	ctx := context.Background()

	// 执行爬取
	banner, err = r.crawler.GetBanner(ctx, uri)
	if err != nil {
		return nil, nil, err
	}

	// 执行匹配
	result, err := r.ScanWithContext(ctx, uri)
	if err != nil {
		return banner, nil, err
	}

	return banner, result.Fingerprint, nil
}

// MergeMaps 合并两个指纹映射
func MergeMaps(map1, map2 map[string]map[string]string) map[string]map[string]string {
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
