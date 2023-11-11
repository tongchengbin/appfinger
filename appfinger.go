package appfinger

import (
	"github.com/projectdiscovery/gologger"
	"github.com/tongchengbin/appfinger/pkg/matchers"
	"gopkg.in/yaml.v3"
	"os"
	"strings"
	"time"
)

type Options struct {
	Timeout time.Duration
	Home    string
	Proxy   string
}

type Rule struct {
	Name              string              `json:"name,omitempty"`
	MatchersCondition string              `yaml:"matchers-condition" json:"matchers_condition,omitempty"`
	Matchers          []*matchers.Matcher `json:"matchers,omitempty"`
}

type Banner struct {
	Body       string
	Header     string
	Headers    map[string]string
	Title      string
	Icon       string
	StatusCode int
	Response   string
	SSL        bool
}

type AppFinger struct {
	Rules   []*Rule
	timeout time.Duration
	Proxy   string
}

func New(options *Options) *AppFinger {
	app := &AppFinger{
		Proxy:   options.Proxy,
		timeout: options.Timeout,
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
			contents = append(contents, LoadDirectoryRule(directory)...)
		}
	}
	if len(contents) == 0 {
		gologger.Info().Msgf("Load AppFinger From Built-in")
		files, err := rulesFiles.ReadDir("app")
		if err != nil {
			panic(err)
		}
		for _, file := range files {
			content, err := rulesFiles.ReadFile("app/" + file.Name())
			if err != nil {
				gologger.Warning().Msgf("ReadFile Error:%v", err.Error())
				continue
			}
			contents = append(contents, string(content))
		}
	}

	for _, content := range contents {
		f.AddFinger(content)
	}
	gologger.Info().Msgf("Load AppFinger rules %v", len(f.Rules))
}

func (r *Rule) Match(banner *Banner) (bool, map[string]string) {
	var ok bool
	var matchedString []string
	matchedMapString := make(map[string]string)
	for _, matcher := range r.Matchers {
		switch matcher.GetType() {
		case matchers.StatusMatcher:
			ok = matcher.MatchStatusCode(banner.StatusCode)
		case matchers.SizeMatcher:
			ok = false
		case matchers.WordsMatcher:
			ok, matchedString = matcher.MatchWords(getMatchPart(matcher.Part, banner))
		case matchers.RegexMatcher:
			ok, matchedString = matcher.MatchRegex(getMatchPart(matcher.Part, banner))
		}
		if matcher.Name != "" && len(matchedString) > 0 {
			matchedMapString[matcher.Name] = matchedString[0]
		}
		if r.MatchersCondition == "or" && ok {
			return true, matchedMapString
		}
		if r.MatchersCondition == "and" && !ok {
			return false, nil
		}
	}
	return ok, matchedMapString
}

func (f *AppFinger) AddFinger(content string) {
	var rules []*Rule
	err := yaml.Unmarshal([]byte(content), &rules)
	if err != nil {
		gologger.Debug().Msgf(err.Error())
		return
	}
	for _, rule := range rules {
		for _, matcher := range rule.Matchers {
			err := matcher.CompileMatchers()
			if err != nil {
				gologger.Info().Msgf("Compile matcher:%s", err.Error())
			}
		}
	}
	f.Rules = append(f.Rules, rules...)
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

	case "title":
		return banner.Title
	case "response":
		return banner.Response

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

func (f *AppFinger) MatchURI(uri string) (*Banner, map[string]map[string]string) {
	banner, err := Request(uri, f.timeout, f.Proxy)
	if err != nil {
		gologger.Debug().Msg(err.Error())
		return nil, nil
	}
	fingerprints := f.Match(banner)
	return banner, fingerprints
}
