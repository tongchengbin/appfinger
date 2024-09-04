package finger

import "github.com/tongchengbin/appfinger/pkg/matchers"

type RulePlugin struct {
	Path string `yaml:"path" json:"path,omitempty"`
}

type Rule struct {
	Name              string `json:"name,omitempty"`
	MatchersCondition string `yaml:"matchers-condition" json:"matchers_condition,omitempty"`
	// 组件太多  采用层级匹配 优化匹配速度
	Require  []string            `json:"require,omitempty"`
	Matchers []*matchers.Matcher `json:"matchers,omitempty"`
	Plugins  []*RulePlugin       `yaml:"plugins"`
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
		if matched {
			ok = true
			continue
		}
		if r.MatchersCondition == "and" && !matched {
			return false, nil
		}
	}
	return ok, matchedMapString
}

type RuleResult struct {
	Extract map[string]map[string]string
	Plugins []*RulePlugin
}
