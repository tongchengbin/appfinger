package rule

import (
	"fmt"
	"strings"
	"sync"
	"testing"

	"github.com/hexbay/appfinger/pkg/matchers"
)

func TestRuleSetWordCorpusCache(t *testing.T) {
	set := NewRuleSet()
	set.AddRules([]*Rule{
		wordRule("unicode", "body", "ÄPP", false),
		wordRule("second", "body", "finger", false),
		wordRule("header", "header", "SERVER", false),
		wordRule("sensitive", "body", "ÄppFinger", true),
		wordRule("wrong-case", "body", "äppfinger", true),
	})
	for range 2 {
		calls := make(map[string]int)
		results := set.Match("http", func(part string, sensitive bool) string {
			if !sensitive {
				calls[part]++
			}
			if part == "body" {
				return "ÄppFinger"
			}
			return "SERVER"
		})
		if len(results) != 4 {
			t.Fatalf("matched %d rules, want 4", len(results))
		}
		if calls["body"] != 1 || calls["header"] != 1 {
			t.Fatalf("getter calls = %v, want once per part", calls)
		}
	}
	// Another response must not reuse content from an earlier scan.
	if results := set.Match("http", func(string, bool) string { return "" }); len(results) != 0 {
		t.Fatal("cached corpus leaked across scans")
	}
}

func TestRuleSetWordCacheConcurrentScans(t *testing.T) {
	set := NewRuleSet()
	set.AddRules([]*Rule{wordRule("app", "body", "APP", false)})
	var wait sync.WaitGroup
	for i := 0; i < 16; i++ {
		wait.Add(1)
		go func(i int) {
			defer wait.Done()
			body, want := "App", 1
			if i%2 == 0 {
				body, want = "other", 0
			}
			if got := len(set.Match("http", func(string, bool) string { return body })); got != want {
				t.Errorf("results = %d, want %d", got, want)
			}
		}(i)
	}
	wait.Wait()
}

func wordRule(name, part, word string, sensitive bool) *Rule {
	return &Rule{Name: name, Service: "http", Matchers: []*matchers.Matcher{{
		Type: matchers.MatcherTypeHolder{MatcherType: matchers.WordsMatcher},
		Part: part, Words: []string{word}, CaseSensitive: sensitive,
	}}}
}

func BenchmarkRuleSetSharedWordCorpus(b *testing.B) {
	set := NewRuleSet()
	for i := 0; i < 256; i++ {
		set.AddRules([]*Rule{wordRule(fmt.Sprint(i), "body", "absent-signature", false)})
	}
	corpus := strings.Repeat("Mixed CASE 页面内容 ", 4096)
	// MatchPartGetter implementations may already return normalized content.
	lower := strings.ToLower(corpus)
	getter := func(_ string, sensitive bool) string {
		if sensitive {
			return corpus
		}
		return lower
	}
	b.ReportAllocs()
	b.SetBytes(int64(len(corpus)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		set.Match("http", getter)
	}
}
