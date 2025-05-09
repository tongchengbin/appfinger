package runner

import (
	"encoding/json"
	"fmt"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/gologger/levels"
	"github.com/stretchr/testify/assert"
	"github.com/tongchengbin/appfinger/pkg/crawl"
	"github.com/tongchengbin/appfinger/pkg/external/customrules"
	"github.com/tongchengbin/appfinger/pkg/rule"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestRunnerSSL(t *testing.T) {
	gologger.DefaultLogger.SetMaxLevel(levels.LevelDebug)
	spider := crawl.NewCrawler(crawl.DefaultOption())
	ruleManager := rule.GetRuleManager()
	_ = ruleManager.LoadRules(customrules.GetDefaultDirectory())
	runner := NewRunner(spider, ruleManager)
	result, err := runner.Scan("https://www.hackerone.com")
	assert.NoError(t, err)
	assert.True(t, len(result.Fingerprint) > 0)
}

func TestRunnerWordPress(t *testing.T) {
	gologger.DefaultLogger.SetMaxLevel(levels.LevelDebug)
	spider := crawl.NewCrawler(crawl.DefaultOption())
	ruleManager := rule.GetRuleManager()
	_ = ruleManager.LoadRules(customrules.GetDefaultDirectory())
	runner := NewRunner(spider, ruleManager)
	result, err := runner.Scan("https://cn.wordpress.org/")
	assert.NoError(t, err)
	assert.True(t, len(result.Fingerprint) > 2)
}

func TestRunnerPlugin(t *testing.T) {
	// 模拟插件匹配 etcd server
	gologger.DefaultLogger.SetMaxLevel(levels.LevelDebug)
	// 创建一个测试服务器来模拟API响应
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")

		switch r.URL.Path {
		case "/":
			// 返回404 not found
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte(`404 page not found`))
		case "/version":
			// 返回版本信息
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(map[string]string{
				"etcdserver":  "3.4.21",
				"etcdcluster": "3.4.0",
			})
		default:
			w.WriteHeader(http.StatusNotFound)
			_ = json.NewEncoder(w).Encode(map[string]string{"message": "404 page not found"})
		}
	}))
	defer ts.Close()
	// 创建规则管理器并设置指纹识别器
	ruleManager := rule.NewManager()
	err := ruleManager.LoadRules(customrules.GetDefaultDirectory())
	assert.NoError(t, err)
	// 创建爬虫
	spider := crawl.NewCrawler(crawl.DefaultOption())
	// 创建Runner
	runner := NewRunner(spider, ruleManager)
	// 执行扫描
	//time.Sleep(100 * time.Second)
	result, err := runner.Scan(ts.URL)
	// 验证结果
	assert.NoError(t, err)
	assert.NotNil(t, result)
	fmt.Printf("%v", result.Fingerprint)
	assert.Contains(t, result.Fingerprint, "ETCD")
}
