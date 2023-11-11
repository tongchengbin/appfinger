package matchers

import "regexp"

// ConditionType is the type of condition for matcher
type ConditionType int

const (
	// ANDCondition matches responses with AND condition in arguments.
	ANDCondition ConditionType = iota + 1
	// ORCondition matches responses with AND condition in arguments.
	ORCondition
)

type Matcher struct {
	Name      string            `json:"name,omitempty"`
	Type      MatcherTypeHolder `yaml:"type" json:"type"`
	Words     []string          `yaml:"words" json:"words,omitempty"`
	Part      string            `yaml:"part" json:"part,omitempty"`
	Regex     []string          `yaml:"regex" json:"regex,omitempty"`
	Encoding  string            `yaml:"encoding" json:"encoding,omitempty"`
	MatchAll  bool              `yaml:"matchAll" json:"match_all,omitempty"`
	Condition string            `yaml:"condition" json:"condition,omitempty"`
	Group     int               `yaml:"group"`
	// description: |
	//   Status are the acceptable status codes for the response.
	// examples:
	//   - value: >
	//       []int{200, 302}
	Status        []int            `yaml:"status,omitempty" jsonschema:"title=status to match,description=Status to match for the response" json:"status,omitempty"`
	regexCompiled []*regexp.Regexp `json:"regex_compiled,omitempty"`
	condition     ConditionType    `json:"condition,omitempty"`
	matcherType   MatcherType      `json:"matcher_type,omitempty"`
}

var ConditionTypes = map[string]ConditionType{
	"and": ANDCondition,
	"or":  ORCondition,
}
