package rule

import (
	"fmt"
	"github.com/projectdiscovery/gologger"
	"github.com/tongchengbin/appfinger/pkg/matchers"
	"strings"
)

type Plugin struct {
	Path string `yaml:"path" json:"path,omitempty"`
}

type Rule struct {
	Name              string `json:"name,omitempty"`
	Service           string `yaml:"service" json:"service,omitempty"`
	MatchersCondition string `yaml:"matchers-condition" json:"matchers_condition,omitempty"`
	// 组件太多  采用层级匹配 优化匹配速度
	Require  []string            `json:"require,omitempty"`
	Matchers []*matchers.Matcher `json:"matchers,omitempty"`
	Plugins  []*Plugin           `yaml:"plugins"`
}

// Finger 根据协议分组
type Finger struct {
	Rules map[string][]*Rule `yaml:"rules"`
}

func (f Finger) AddRules(rules []*Rule) {
	for _, rule := range rules {
		if rule.Service == "" {
			rule.Service = "http"
		}
		f.Rules[rule.Service] = append(f.Rules[rule.Service], rule)
	}
}

func (f Finger) Match(service string, banner *Banner) map[string]map[string]string {
	rules, ok := f.Rules[service]
	if !ok {
		gologger.Debug().Msgf("No rules found for %s", service)
		return nil
	}
	results := map[string]map[string]string{}
	for _, rule := range rules {
		ok, extract := rule.Match(banner)
		if ok {
			if results[rule.Name] == nil {
				results[rule.Name] = extract
			} else {
				for k, v := range extract {
					results[rule.Name][k] = v
				}
			}
		}
	}
	return results

}

func NewFinger() *Finger {
	return &Finger{Rules: make(map[string][]*Rule)}
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
		default:
			panic("unhandled default case")
		}
		if matcher.Name != "" && len(matchedString) > 0 {
			matchedMapString[matcher.Name] = matchedString[0]
		}
		if matched {
			ok = true
			continue
		}
		if r.MatchersCondition == "and" {
			return false, nil
		}
	}
	return ok, matchedMapString
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
