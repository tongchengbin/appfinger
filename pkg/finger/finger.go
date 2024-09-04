package finger

import (
	"fmt"
	"github.com/projectdiscovery/gologger"
	"github.com/tongchengbin/appfinger"
	"gopkg.in/yaml.v3"
	"net/url"
	"os"
	"strings"
	"time"
)

type Options struct {
	Timeout           time.Duration
	Home              string
	Proxy             string
	DisableJavaScript bool
	DisableIcon       bool
	DebugResp         bool
}

type AppFinger struct {
	Rules   []*Rule
	Plugins []*Rule
	timeout time.Duration
	Proxy   string
	options *Options
}

func New(options *Options) *AppFinger {
	app := &AppFinger{
		Proxy:   options.Proxy,
		timeout: options.Timeout,
		options: options,
	}
	app.LoadAppFinger(options.Home)
	return app
}

func (f *AppFinger) LoadAppFinger(directory string) {
	// 判断指纹目录是否存在  如果存在就使用指纹目录 否则使用内置
	var contents []string
	if directory != "" {
		//	 判断文件夹是否存在
		_, err := os.Stat(directory)
		if err == nil {
			contents = append(contents, appfinger.LoadDirectoryRule(directory, f.options.DisableJavaScript)...)
		}
	}
	if len(contents) == 0 {
		gologger.Info().Msgf("Load AppFinger From Built-in")
		files, err := appfinger.RulesFiles.ReadDir("app")
		if err != nil {
			panic(err)
		}
		for _, file := range files {
			content, err := appfinger.RulesFiles.ReadFile("app/" + file.Name())
			if err != nil {
				gologger.Warning().Msgf("ReadFile Error:%v", err.Error())
				continue
			}
			contents = append(contents, string(content))
		}
	}

	for _, content := range contents {
		err := f.AddFinger(content)
		if err != nil {
			gologger.Error().Msgf("%v:%v", err.Error(), content)
		}
	}
	gologger.Info().Msgf("Load AppFinger rules %v", len(f.Rules))
}

func (f *AppFinger) AddFinger(content string) error {
	var rules []*Rule
	err := yaml.Unmarshal([]byte(content), &rules)
	if err != nil {
		return err
	}
	for _, rule := range rules {
		for _, matcher := range rule.Matchers {
			err := matcher.CompileMatchers()
			if err != nil {
				gologger.Error().Msgf("Compile matcher:%s -> %s", err.Error(), rule.Name)
				continue
			}
		}
		if len(rule.Plugins) > 0 {
			f.Plugins = append(f.Plugins, rule)
		} else {
			f.Rules = append(f.Rules, rule)
		}
	}
	return nil
}

func getMatchPart(part string, banner *Banner) string {
	if part == "" {
		part = "body"
	}
	if strings.HasPrefix(part, "headers.") {
		return banner.Headers[strings.ToLower(strings.TrimPrefix(part, "headers."))]
	}
	switch part {
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
	}
	return ""
}

func isRequire(requires []string, results map[string]map[string]string) bool {
	for _, require := range requires {
		if _, ok := results[require]; ok {
			return true
		}
	}
	return false
}

func (f *AppFinger) MatchPlugin(banner *Banner) []*RulePlugin {
	return f.Match(banner, f.Plugins).Plugins
}

func (f *AppFinger) MatchRule(banner *Banner) RuleResult {
	return f.Match(banner, f.Rules)
}

func (f *AppFinger) Match(banner *Banner, rules []*Rule) RuleResult {
	result := RuleResult{Extract: map[string]map[string]string{}}
	for _, rule := range rules {
		if len(rule.Require) > 0 && !isRequire(rule.Require, result.Extract) {
			continue
		}
		ok, extract := rule.Match(banner)
		if ok {
			if len(rule.Plugins) > 0 {
				result.Plugins = append(result.Plugins, rule.Plugins...)
				continue
			}
			if result.Extract[rule.Name] == nil {
				result.Extract[rule.Name] = extract
			} else {
				for k, v := range extract {
					result.Extract[rule.Name][k] = v
				}
			}
		}
	}
	return result
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

func (f *AppFinger) ExecuteWithPlugin(banner *Banner, plugin *RulePlugin) ([]*Banner, error) {
	gologger.Debug().Msgf("Execute with Plugin: %s", plugin.Path)
	newURl := urlJoin(banner.Uri, plugin.Path)
	return Request(newURl, f.timeout, f.Proxy, f.options.DisableIcon, f.options.DebugResp)
}

func (f *AppFinger) MatchURI(uri string) (banner *Banner, fingerprints map[string]map[string]string, err error) {
	// fix url
	u, err := url.Parse(uri)
	if err != nil {
		return nil, nil, err
	}
	if (u.Scheme == "http" && u.Port() == "80") || (u.Scheme == "https" && u.Port() == "443") {
		u.Host = u.Hostname()
	}
	uri = u.String()
	banners, err := Request(uri, f.timeout, f.Proxy, f.options.DisableIcon, f.options.DebugResp)
	if err != nil {
		return banner, fingerprints, err
	}
	// 匹配插件
	// todo 插件去重
	var currentBanners []*Banner
	for _, b := range banners {
		bannerPlugins := f.MatchPlugin(b)
		if len(bannerPlugins) > 0 {
			for _, plugin := range bannerPlugins {
				currentBanners, err = f.ExecuteWithPlugin(b, plugin)
				if err != nil {
					continue
				}
				banners = append(banners, currentBanners...)
			}
		}
	}
	// 匹配规则
	for _, b := range banners {
		result := f.MatchRule(b)
		fingerprints = mergeMaps(fingerprints, result.Extract)
		// free memory
		b.Response = ""
	}

	if _, ok := fingerprints["honeypot"]; ok {
		return banners[len(banners)-1], map[string]map[string]string{"honeypot": make(map[string]string)}, nil
	}
	if _, ok := fingerprints["Wordpress"]; ok {
		fingerprints = mergeMaps(fingerprints, MatchWpPlugin(banners[len(banners)-1]))
	}
	return banners[len(banners)-1], fingerprints, nil
}
