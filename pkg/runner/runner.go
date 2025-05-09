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

type ExecutorsPlugin struct {
	Plugin *rule.Plugin
	Banner *crawl.Banner
}

// Runner 负责协调爬虫和规则匹配的执行流程
type Runner struct {
	crawler     *crawl.Crawler
	ruleManager *rule.Manager
}

// NewRunner 创建新的Runner实例
func NewRunner(crawler *crawl.Crawler, ruleManager *rule.Manager) *Runner {
	return &Runner{
		crawler:     crawler,
		ruleManager: ruleManager,
	}
}

// NewDefaultRunner 创建默认的Runner实例
func NewDefaultRunner(options *crawl.Options, finger *rule.Finger) *Runner {
	crawler := crawl.NewCrawler(options)
	var ruleManager *rule.Manager
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
	banners, err := r.crawler.GetBanners(ctx, uri)
	if err != nil {
		return nil, err
	}
	// 获取指纹库
	finger := r.ruleManager.GetFinger()
	// 最终结果
	results := make(map[string]map[string]string)
	// 对每个banner进行匹配
	matchResults, matchPlugins := r.matchBanners(finger, banners)
	results = MergeMaps(results, matchResults)
	// 特殊处理
	if _, ok := results["honeypot"]; ok {
		results = map[string]map[string]string{"honeypot": make(map[string]string)}
	}
	// 获取最后一个banner作为默认banner
	lastBanner := banners[len(banners)-1]
	// WordPress插件匹配
	if _, ok := results["Wordpress"]; ok {
		// 如果匹配到Wordpress，使用最后一个banner来匹配WordPress插件
		wpPlugins := MatchWpPlugin(lastBanner.Body)
		results = MergeMaps(wpPlugins, results)
	}
	// 最后再匹配插件
	if len(matchPlugins) > 0 {
		for _, executePlugin := range matchPlugins {
			pluginBanners, err := r.ExecuteWithPlugin(ctx, executePlugin.Banner.Uri, executePlugin.Plugin)
			if err != nil {
				gologger.Debug().Msgf("Execute With Plugin Error: %v", err)
				continue
			}
			// 对插件返回的banners进行匹配
			matchResults, _ = r.matchBanners(finger, pluginBanners)
			results = MergeMaps(results, matchResults)
			lastBanner = pluginBanners[len(pluginBanners)-1]
		}
	}
	return &Result{
		Banner:      lastBanner,
		Fingerprint: results,
	}, nil
}

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
	banners, err := r.crawler.GetBanners(ctx, newURL)
	return banners, err
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

// matchBanners 对一组banner进行匹配并返回结果和插件
func (r *Runner) matchBanners(finger *rule.Finger, banners []*crawl.Banner) (map[string]map[string]string, []ExecutorsPlugin) {
	var plugins = make([]ExecutorsPlugin, 0)
	var results = make(map[string]map[string]string)
	// 对每个banner进行匹配
	for _, banner := range banners {
		// 创建banner适配器
		getMatchPart := createMatchPartGetter(banner)
		// 执行匹配
		matchResults := finger.Match("http", getMatchPart)
		// 记录每个规则匹配到的banner和插件
		for _, matchResult := range matchResults {
			//	提取结果
			if matchResult.IsPlugin() {
				for _, plugin := range matchResult.Rule.Plugins {
					plugins = append(plugins, ExecutorsPlugin{Plugin: plugin, Banner: banner})
				}
			} else {
				results = MergeMaps(map[string]map[string]string{matchResult.Rule.Name: matchResult.Extracted}, results)
			}
		}
	}
	return results, plugins
}

// createMatchPartGetter 创建一个从banner中提取匹配部分的函数
func createMatchPartGetter(banner *crawl.Banner) rule.MatchPartGetter {
	return func(part string) string {
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
			return banner.Headers["server"]
		}
		return ""
	}
}

// MergeMaps 合并两个map
func MergeMaps(m1, m2 map[string]map[string]string) map[string]map[string]string {
	result := make(map[string]map[string]string)

	// 遍历第一个 map
	for key, value := range m1 {
		result[key] = value
	}

	// 遍历第二个 map
	for key, value := range m2 {
		// 如果键已存在，则根据需求选择合并或覆盖值
		// 这里选择覆盖
		result[key] = value
	}

	return result
}
