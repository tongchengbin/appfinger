package rule

import "testing"

func TestLoadRule(t *testing.T) {
	group, err := ScanRuleDirectory("D:\\code\\github.com\\whatapp-rules")
	if err != nil {
		t.Error(err)
	}
	for name, rules := range group.Rules {
		t.Log("load", name, "rules:", len(rules))
	}
}

func TestRuleMatch(t *testing.T) {
	group, err := ScanRuleDirectory("D:\\code\\github.com\\whatapp-rules")
	if err != nil {
		t.Error(err)
	}
	results := group.Match("http", &Banner{
		Title: "Adobe Media Server",
	})
	t.Log(results)

	results = group.Match("ftp", &Banner{
		Body: "220 Microsoft FTP Service\n214-The following commands are recognized (* ==>'s unimplemented).\nABOR\nACCT",
	})
	t.Log(results)
}
