package matchers

import (
	"strings"
)

// MatchWords matches a word check against a corpus.
func (matcher *Matcher) MatchWords(corpus string) (bool, []string) {
	var matchedWords []string
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
	if corpus == "" {
		return false, []string{}
	}
	// 预分配结果切片，减少内存分配
	matchedRegexes := make([]string, 0, len(matcher.regexCompiled))
	
	// 遍历所有正则表达式
	for i, regex := range matcher.regexCompiled {
		// 使用 FindAllStringSubmatch 一次性获取所有匹配和捕获组
		// 这比单独调用 FindStringSubmatch 更高效
		matches := regex.FindAllStringSubmatch(corpus, -1)
		
		// 如果没有匹配
		if len(matches) == 0 {
			// 对于 AND 条件，任何一个不匹配就返回失败
			if matcher.condition == ANDCondition {
				return false, []string{}
			}
			// 对于 OR 条件，继续检查下一个
			continue
		}
		
		// 提取匹配的内容
		var currentMatches []string
		for _, match := range matches {
			// 根据 Group 参数提取指定捕获组
			if matcher.Group > 0 && len(match) > matcher.Group {
				currentMatches = append(currentMatches, match[matcher.Group])
			} else if matcher.Name != "" && len(match) > 1 {
				currentMatches = append(currentMatches, match[1])
			} else if len(match) > 0 {
				// 如果没有指定捕获组，使用整个匹配
				currentMatches = append(currentMatches, match[0])
			}
		}
		
		// 如果是 OR 条件且不需要匹配所有，第一个匹配就返回
		if matcher.condition == ORCondition && !matcher.MatchAll {
			return true, currentMatches
		}
		
		// 添加当前匹配到结果集
		matchedRegexes = append(matchedRegexes, currentMatches...)
		
		// 如果不需要匹配所有且已处理完最后一个正则，返回结果
		if !matcher.MatchAll && i == len(matcher.regexCompiled)-1 {
			return true, matchedRegexes
		}
	}
	
	// 如果需要匹配所有且有匹配结果，返回成功
	if matcher.MatchAll && len(matchedRegexes) > 0 {
		return true, matchedRegexes
	}
	
	// 默认返回失败
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
