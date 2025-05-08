package runner

import (
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/gologger/levels"
	"github.com/stretchr/testify/assert"
	"github.com/tongchengbin/appfinger/pkg/crawl"
	"github.com/tongchengbin/appfinger/pkg/rule"
	"net/http"
	"testing"
)

func TestRunnerNew(t *testing.T) {
	gologger.DefaultLogger.SetMaxLevel(levels.LevelDebug)
	spider := crawl.NewCrawler(crawl.DefaultOption())
	ruleManager := rule.GetRuleManager()
	runner := NewRunner(spider, ruleManager)
	result, err := runner.Scan("https://www.hackerone.com")
	assert.NoError(t, err)
	println(result.Banner)
}

func TestHTTPURL(t *testing.T) {
	client := http.Client{}
	req, _ := http.NewRequest("GET", "https://www.hackone.com", nil)
	response, err := client.Do(req)
	if err != nil {
		println(err.Error())
		return
	}
	println(response.Header)

}
