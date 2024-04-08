package matchers

import (
	"encoding/hex"
	"fmt"
	"regexp"
	"strings"
)

// CompileMatchers performs the initial setup operation on a matcher
func (matcher *Matcher) CompileMatchers() error {
	var ok bool
	// Support hexadecimal encoding for matchers too.
	if matcher.Encoding == "hex" {
		for i, word := range matcher.Words {
			if decoded, err := hex.DecodeString(word); err == nil && len(decoded) > 0 {
				matcher.Words[i] = string(decoded)
			}
		}
	}

	// Set up the matcher type
	computedType, err := toMatcherTypes(matcher.GetType().String())
	if err != nil {
		return fmt.Errorf("unknown matcher %s type specified: %s", matcher.Name, matcher.Type)
	}

	matcher.matcherType = computedType

	// By default, match on body if user hasn't provided any specific items
	if matcher.Part == "" {
		matcher.Part = "body"
	}

	// Compile the regexes
	for _, regex := range matcher.Regex {
		compiled, err := regexp.Compile(regex)
		if err != nil {
			return fmt.Errorf("could not compile regex: %s", regex)
		}
		matcher.regexCompiled = append(matcher.regexCompiled, compiled)
	}
	if matcher.CaseInsensitive {
		for index, word := range matcher.Words {
			matcher.Words[index] = strings.ToLower(word)
		}
	}
	// Set up the condition type, if any.
	if matcher.Condition != "" {
		matcher.condition, ok = ConditionTypes[matcher.Condition]
		if !ok {
			return fmt.Errorf("unknown condition specified: %s", matcher.Condition)
		}
	} else {
		matcher.condition = ORCondition
	}
	if matcher.Name != "" {
		matcher.HasExtra = true

	}
	return nil
}
