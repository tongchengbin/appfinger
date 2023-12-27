package matchers

import (
	"strings"
)

// MatchWords matches a word check against a corpus.
func (matcher *Matcher) MatchWords(corpus string) (bool, []string) {
	var matchedWords []string
	if matcher.CaseInsensitive {
		corpus = strings.ToLower(corpus)
	}
	// Iterate over all the words accepted as valid
	for i, word := range matcher.Words {
		// Continue if the word doesn't match
		if !strings.Contains(corpus, word) {
			// If we are in an AND request and a match failed,
			// return false as the AND condition fails on any single mismatch.
			switch matcher.condition {
			case ANDCondition:
				return false, []string{}
			case ORCondition:
				continue
			}
		}

		// If the condition was an OR, return on the first match.
		if matcher.condition == ORCondition && !matcher.MatchAll {
			return true, []string{word}
		}
		matchedWords = append(matchedWords, word)

		// If we are at the end of the words, return with true
		if len(matcher.Words)-1 == i && !matcher.MatchAll {
			return true, matchedWords
		}
	}
	if len(matchedWords) > 0 && matcher.MatchAll {
		return true, matchedWords
	}
	return false, []string{}
}

// MatchRegex matches a regex check against a corpus
func (matcher *Matcher) MatchRegex(corpus string) (bool, []string) {
	var matchedRegexes []string
	var ok bool
	// Iterate over all the regexes accepted as valid
	for i, regex := range matcher.regexCompiled {
		var currentMatches []string
		items := regex.FindStringSubmatch(corpus)
		if len(items) > 1 && items[0] != "" {
			ok = true
		}
		if matcher.Group > 0 && (len(items) > matcher.Group-1) {
			currentMatches = []string{items[matcher.Group]}
		} else if matcher.Name != "" && len(items) > 1 {
			currentMatches = []string{items[1]}
		}
		// Continue if the regex doesn't match
		if !ok {
			// If we are in an AND request and a match failed,
			// return false as the AND condition fails on any single mismatch.
			switch matcher.condition {
			case ANDCondition:
				return false, []string{}
			case ORCondition:
				continue
			}
		}
		// If the condition was an OR, return on the first match.
		if matcher.condition == ORCondition && !matcher.MatchAll {
			return true, currentMatches
		}

		matchedRegexes = append(matchedRegexes, currentMatches...)

		// If we are at the end of the regex, return with true
		if len(matcher.regexCompiled)-1 == i && !matcher.MatchAll {
			return true, matchedRegexes
		}
	}
	if len(matchedRegexes) > 0 && matcher.MatchAll {
		return true, matchedRegexes
	}
	return false, []string{}
}

// MatchStatusCode matches a status code check against a corpus
func (matcher *Matcher) MatchStatusCode(statusCode int) bool {
	// Iterate over all the status codes accepted as valid
	//
	// Status codes don't support AND conditions.
	for _, status := range matcher.Status {
		// Continue if the status codes don't match
		if statusCode != status {
			continue
		}
		// Return on the first match.
		return true
	}
	return false
}
