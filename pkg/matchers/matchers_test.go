package matchers

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestWordsMatcher(t *testing.T) {
	// Test basic word matching
	matcher := &Matcher{
		Type:  MatcherTypeHolder{WordsMatcher},
		Words: []string{"test", "example"},
	}

	matched, matchedStrings := matcher.MatchWords("this is a test string")
	assert.True(t, matched, "Should match when word is present")
	assert.Equal(t, []string{"test"}, matchedStrings, "Should return matched word")

	matched, matchedStrings = matcher.MatchWords("this contains example text")
	assert.True(t, matched, "Should match when word is present")
	assert.Equal(t, []string{"example"}, matchedStrings, "Should return matched word")

	matched, _ = matcher.MatchWords("this has no matching words")
	assert.False(t, matched, "Should not match when no words are present")

	// Test case sensitivity
	matcher = &Matcher{
		Type:  MatcherTypeHolder{WordsMatcher},
		Words: []string{"Test"},
	}

	matched, _ = matcher.MatchWords("this is a test string")
	assert.False(t, matched, "Should not match when case is different")

	matcher.CaseSensitive = true
	matched, matchedStrings = matcher.MatchWords("this is a test string")
	assert.True(t, matched, "Should match when case insensitive is enabled")
	assert.Equal(t, []string{"test"}, matchedStrings, "Should return matched word")

	// Test condition matching
	matcher = &Matcher{
		Type:      MatcherTypeHolder{WordsMatcher},
		Words:     []string{"test", "example"},
		Condition: "and",
	}

	matched, _ = matcher.MatchWords("this is a test string")
	assert.False(t, matched, "Should not match when condition is AND and not all words are present")

	matched, matchedStrings = matcher.MatchWords("this is a test example string")
	assert.True(t, matched, "Should match when condition is AND and all words are present")
	assert.Equal(t, []string{"test", "example"}, matchedStrings, "Should return all matched words")

	// Test negative matching
	matcher = &Matcher{
		Type:  MatcherTypeHolder{WordsMatcher},
		Words: []string{"test"},
	}

	matched, _ = matcher.MatchWords("this is a test string")
	assert.False(t, matched, "Should not match when negative and word is present")

	matched, _ = matcher.MatchWords("this has no matching words")
	assert.True(t, matched, "Should match when negative and word is not present")
}

func TestRegexMatcher(t *testing.T) {
	// Test basic regex matching
	matcher := &Matcher{
		Type:  MatcherTypeHolder{RegexMatcher},
		Regex: []string{`test\d+`, `example\d+`},
	}

	matched, matchedStrings := matcher.MatchRegex("this is a test123 string")
	assert.True(t, matched, "Should match when regex pattern matches")
	assert.Equal(t, []string{"test123"}, matchedStrings, "Should return matched string")

	matched, matchedStrings = matcher.MatchRegex("this contains example456 text")
	assert.True(t, matched, "Should match when regex pattern matches")
	assert.Equal(t, []string{"example456"}, matchedStrings, "Should return matched string")

	matched, _ = matcher.MatchRegex("this has no matching patterns")
	assert.False(t, matched, "Should not match when no patterns match")

	// Test condition matching
	matcher = &Matcher{
		Type:      MatcherTypeHolder{RegexMatcher},
		Regex:     []string{`test\d+`, `example\d+`},
		Condition: "and",
	}

	matched, _ = matcher.MatchRegex("this is a test123 string")
	assert.False(t, matched, "Should not match when condition is AND and not all patterns match")

	matched, matchedStrings = matcher.MatchRegex("this is a test123 example456 string")
	assert.True(t, matched, "Should match when condition is AND and all patterns match")
	assert.Equal(t, []string{"test123", "example456"}, matchedStrings, "Should return all matched strings")

	// Test negative matching
	matcher = &Matcher{
		Type:  MatcherTypeHolder{RegexMatcher},
		Regex: []string{`test\d+`},
	}

	matched, _ = matcher.MatchRegex("this is a test123 string")
	assert.False(t, matched, "Should not match when negative and pattern matches")

	matched, _ = matcher.MatchRegex("this has no matching patterns")
	assert.True(t, matched, "Should match when negative and pattern doesn't match")

	// Test with extraction
	matcher = &Matcher{
		Type:  MatcherTypeHolder{RegexMatcher},
		Regex: []string{`version:(\d+\.\d+\.\d+)`},
		Name:  "version",
	}

	matched, matchedStrings = matcher.MatchRegex("software version:2.3.4 installed")
	assert.True(t, matched, "Should match and extract version")
	assert.Equal(t, []string{"2.3.4"}, matchedStrings, "Should extract the version number")
}

func TestStatusMatcher(t *testing.T) {
	// Test basic status code matching
	matcher := &Matcher{
		Type:   MatcherTypeHolder{StatusMatcher},
		Status: []int{200, 301},
	}

	matched := matcher.MatchStatusCode(200)
	assert.True(t, matched, "Should match when status code is in the list")

	matched = matcher.MatchStatusCode(301)
	assert.True(t, matched, "Should match when status code is in the list")

	matched = matcher.MatchStatusCode(404)
	assert.False(t, matched, "Should not match when status code is not in the list")

	// Test negative matching
	matcher = &Matcher{
		Type:   MatcherTypeHolder{StatusMatcher},
		Status: []int{404, 500},
	}

	matched = matcher.MatchStatusCode(200)
	assert.True(t, matched, "Should match when negative and status code is not in the list")

	matched = matcher.MatchStatusCode(404)
	assert.False(t, matched, "Should not match when negative and status code is in the list")
}
