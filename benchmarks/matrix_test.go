package benchmarks

import (
	"fmt"
	"strings"
	"testing"

	"github.com/hexbay/appfinger/pkg/matchers"
	"github.com/hexbay/appfinger/pkg/rule"
)

func matrixRules(b testing.TB, count int, kind string) *rule.RuleSet {
	b.Helper()
	s := rule.NewRuleSet()
	for i := 0; i < count; i++ {
		m := &matchers.Matcher{Type: matchers.MatcherTypeHolder{MatcherType: matchers.WordsMatcher}, Part: "body", Words: []string{fmt.Sprintf("signature-%06d!", i)}}
		if kind == "regex" || kind == "mixed" && i%2 == 0 {
			m.Type.MatcherType = matchers.RegexMatcher
			m.Words = nil
			m.Regex = []string{fmt.Sprintf(`signature-%06d! release-([0-9.]+)`, i)}
			m.Name, m.Group = "version", 1
		}
		if err := m.CompileMatchers(); err != nil {
			b.Fatal(err)
		}
		s.AddRules([]*rule.Rule{{Name: fmt.Sprintf("component-%06d", i), Service: "http", Matchers: []*matchers.Matcher{m}}})
	}
	return s
}

func BenchmarkMatchMatrix(b *testing.B) {
	for _, count := range []int{128, 1024, 4096} {
		for _, kind := range []string{"word", "regex", "mixed"} {
			for _, hits := range []int{0, 1, 64} {
				b.Run(fmt.Sprintf("rules%d/%s/hits%d", count, kind, hits), func(b *testing.B) {
					s := matrixRules(b, count, kind)
					corpus := body(32768, false)
					for i := 0; i < hits; i++ {
						corpus += fmt.Sprintf(" signature-%06d! release-1.2", i)
					}
					getter := func(part string, _ bool) string {
						if part == "body" {
							return corpus
						}
						return ""
					}
					verify := func(results []*rule.MatchResult) {
						if len(results) != hits {
							b.Fatalf("got %d hits, want %d", len(results), hits)
						}
						seen := map[string]bool{}
						for _, r := range results {
							seen[r.Rule.Name] = true
							if len(r.Rule.Matchers[0].Regex) > 0 && r.Extracted["version"] != "1.2" {
								b.Fatalf("incorrect extraction: %v", r.Extracted)
							}
						}
						for i := 0; i < hits; i++ {
							if !seen[fmt.Sprintf("component-%06d", i)] {
								b.Fatal("missing expected component")
							}
						}
					}
					verify(s.Match("http", getter))
					b.ReportAllocs()
					b.SetBytes(int64(len(corpus)))
					b.ResetTimer()
					for i := 0; i < b.N; i++ {
						s.Match("http", getter)
					}
					b.StopTimer()
					verify(s.Match("http", getter))
				})
			}
		}
	}
}

func BenchmarkMatcherLogic(b *testing.B) {
	for _, scenario := range []string{"and-first-miss", "and-last-miss", "or-first-hit", "or-last-hit", "case-sensitive", "regex-extraction"} {
		b.Run(scenario, func(b *testing.B) {
			corpus := body(32768, false) + " ExactCase release-1.2"
			m := &matchers.Matcher{Type: matchers.MatcherTypeHolder{MatcherType: matchers.WordsMatcher}, Part: "body", Condition: "and", Words: []string{"Mixed", "页面", "absent"}}
			want := false
			switch scenario {
			case "and-first-miss":
				m.Words = []string{"absent", "Mixed", "页面"}
			case "or-first-hit":
				m.Condition, m.Words, want = "or", []string{"ExactCase", "absent"}, true
			case "or-last-hit":
				m.Condition, m.Words, want = "or", []string{"absent", "ExactCase"}, true
			case "case-sensitive":
				m.CaseSensitive, m.Words, want = true, []string{"ExactCase"}, true
			case "regex-extraction":
				m.Type.MatcherType, m.Regex, m.Name, m.Group, want = matchers.RegexMatcher, []string{`release-([0-9.]+)`}, "version", 1, true
			}
			if err := m.CompileMatchers(); err != nil {
				b.Fatal(err)
			}
			r := &rule.Rule{Name: scenario, Matchers: []*matchers.Matcher{m}}
			getter := func(_ string, sensitive bool) string {
				if sensitive {
					return corpus
				}
				return strings.ToLower(corpus)
			}
			ok, values := r.Match(getter)
			if ok != want || scenario == "regex-extraction" && values["version"] != "1.2" {
				b.Fatalf("match=%v extraction=%v", ok, values)
			}
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				r.Match(getter)
			}
		})
	}
}
