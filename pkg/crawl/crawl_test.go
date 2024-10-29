package crawl

import (
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/gologger/levels"
	"github.com/tongchengbin/appfinger/pkg/rule"
	"testing"
	"time"
)

func TestCrawl(t *testing.T) {
	gologger.DefaultLogger.SetMaxLevel(levels.LevelDebug)
	finger, err := rule.ScanRuleDirectory("D:\\code\\github.com\\whatapp-rules")
	if err != nil {
		t.Fatal(err.Error())
	}
	crawl := NewCrawl(&Options{
		Timeout: 6 * time.Second,
	}, finger)

	banner, fingerPrint, err := crawl.Match("http://192.168.2.22")
	if err != nil {
		t.Fatal(err.Error())
	}
	t.Log(banner)
	t.Log(fingerPrint)
}
