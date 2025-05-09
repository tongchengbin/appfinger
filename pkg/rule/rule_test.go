package rule

import (
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/gologger/levels"
	"testing"
)

func TestLoadRule(t *testing.T) {
	group, err := ScanRuleDirectory("D:\\code\\github.com\\finger-rules")
	if err != nil {
		t.Error(err)
	}
	for name, rules := range group.Rules {
		t.Log("load", name, "rules:", len(rules))
	}
}

func TestRuleMatchFtp(t *testing.T) {
	group, err := ScanRuleDirectory("D:\\code\\github.com\\finger-rules")
	if err != nil {
		t.Error(err)
	}
	results := group.Match("http", func(part string) string {
		return "Adobe Media Server"
	})
	t.Log(results)

	results = group.Match("ftp", func(part string) string {
		return "220 Microsoft FTP Service\n214-The following commands are recognized (* ==>'s unimplemented).\nABOR\nACCT"
	})
	t.Log(results)
}

func TestRuleMatchCpe(t *testing.T) {
	gologger.DefaultLogger.SetMaxLevel(levels.LevelDebug)
	group, err := ScanRuleDirectory("D:\\code\\github.com\\finger-rules\\ssh.yaml")
	if err != nil {
		t.Error(err)
		return
	}
	results := group.Match("ssh", func(part string) string { return "SSH-2.0-OpenSSH_7.2p2 Ubuntu-4kord2.8" })
	t.Log(results)
}
