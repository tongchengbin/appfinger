package finger

import (
	"fmt"
	"github.com/projectdiscovery/gologger"
	"github.com/tongchengbin/appfinger"
	"github.com/tongchengbin/appfinger/pkg/matchers"
	"gopkg.in/yaml.v3"
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
}

type Rule struct {
	Name              string              `json:"name,omitempty"`
	MatchersCondition string              `yaml:"matchers-condition" json:"matchers_condition,omitempty"`
	Matchers          []*matchers.Matcher `json:"matchers,omitempty"`
}

type Banner struct {
	BodyHash    int32
	Body        string
	Header      string
	Headers     map[string]string
	Title       string
	StatusCode  int
	Response    string
	SSL         bool
	Certificate string
	IconHash    int32
}

type AppFinger struct {
	Rules   []*Rule
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

func (r *Rule) Match(banner *Banner) (bool, map[string]string) {
	var matchedString []string
	matchedMapString := make(map[string]string)
	// 为了保证数据都被提取到 所以需要匹配所有的规则
	var matched bool
	var ok bool
	for _, matcher := range r.Matchers {
		if matched && !matcher.HasExtra {
			continue
		}
		switch matcher.GetType() {
		case matchers.StatusMatcher:
			matched = matcher.MatchStatusCode(banner.StatusCode)
		case matchers.SizeMatcher:
			matched = false
		case matchers.WordsMatcher:
			matched, matchedString = matcher.MatchWords(getMatchPart(matcher.Part, banner))
		case matchers.RegexMatcher:
			matched, matchedString = matcher.MatchRegex(getMatchPart(matcher.Part, banner))
		}
		if matcher.Name != "" && len(matchedString) > 0 {
			matchedMapString[matcher.Name] = matchedString[0]
		}

		if (r.MatchersCondition == "" || r.MatchersCondition == "or") && matched {
			ok = true
			continue
		}
		if r.MatchersCondition == "and" && !matched {
			return false, nil
		}
	}
	if matched && r.MatchersCondition == "and" {
		return true, matchedMapString
	}
	return ok, matchedMapString
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
			}
		}
		f.Rules = append(f.Rules, rule)

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
	}
	return ""
}

func (f *AppFinger) Match(banner *Banner) map[string]map[string]string {
	result := make(map[string]map[string]string)
	for _, rule := range f.Rules {
		ok, extract := rule.Match(banner)
		if ok {
			if result[rule.Name] == nil {
				result[rule.Name] = extract
			} else {
				for k, v := range extract {
					result[rule.Name][k] = v
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
func (f *AppFinger) MatchURI(uri string) (*Banner, map[string]map[string]string) {
	banners, err := Request(uri, f.timeout, f.Proxy, f.options.DisableIcon)
	var fingerprints map[string]map[string]string
	if err != nil && banners == nil {
		gologger.Warning().Msg(err.Error())
		return nil, nil
	}
	for _, banner := range banners {
		// is honeypot.yaml
		fingerprints = mergeMaps(fingerprints, f.Match(banner))
	}
	if _, ok := fingerprints["honeypot"]; ok {
		return banners[len(banners)-1], map[string]map[string]string{"honeypot": make(map[string]string)}
	}
	return banners[len(banners)-1], fingerprints
}
