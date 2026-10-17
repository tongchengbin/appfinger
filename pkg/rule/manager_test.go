package rule

import (
	"strings"
	"testing"
)

func TestRuleLoadSummaryReportsRulesAndCategories(t *testing.T) {
	ruleSet := NewRuleSet()
	ruleSet.AddRules([]*Rule{
		{Name: "one", Service: "http"},
		{Name: "two", Service: "http"},
		{Name: "three", Service: "ssh"},
	})

	summary := ruleLoadSummary("test-rules", ruleSet)
	for _, want := range []string{"3 条", "2 个协议分类", "test-rules"} {
		if !strings.Contains(summary, want) {
			t.Fatalf("rule load summary %q does not contain %q", summary, want)
		}
	}
}
