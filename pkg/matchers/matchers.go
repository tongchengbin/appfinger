package matchers

import "regexp"

type ConditionType int

const (
	ANDCondition ConditionType = iota + 1
	ORCondition
)

type Matcher struct {
	Name            string            `json:"name,omitempty"`
	Type            MatcherTypeHolder `yaml:"type" json:"type"`
	Words           []string          `yaml:"words" json:"words,omitempty"`
	Part            string            `yaml:"part" json:"part,omitempty"`
	Regex           []string          `yaml:"regex" json:"regex,omitempty"`
	Encoding        string            `yaml:"encoding" json:"encoding,omitempty"`
	MatchAll        bool              `yaml:"matchAll" json:"match_all,omitempty"`
	Condition       string            `yaml:"condition" json:"condition,omitempty"`
	Group           int               `yaml:"group"`
	Status          []int             `yaml:"status,omitempty" jsonschema:"title=status to match,description=Status to match for the response" json:"status,omitempty"`
	CaseInsensitive bool              `yaml:"case-insensitive,omitempty" json:"case-insensitive,omitempty" jsonschema:"title=use case insensitive match,description=use case insensitive match"`
	regexCompiled   []*regexp.Regexp
	condition       ConditionType
	matcherType     MatcherType
	HasExtra        bool
}

var ConditionTypes = map[string]ConditionType{
	"and": ANDCondition,
	"or":  ORCondition,
}
