package main

import (
	"context"
	"fmt"
	_ "net/http/pprof"
	"time"

	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/gologger/levels"
	"github.com/tongchengbin/appfinger/internal"
	"github.com/tongchengbin/appfinger/pkg/crawl"
	"github.com/tongchengbin/appfinger/pkg/external/customrules"
	"github.com/tongchengbin/appfinger/pkg/rule"
	"github.com/tongchengbin/appfinger/pkg/runner"
)

const Version = "v0.3.4"

var Banner = fmt.Sprintf(`
______          %s             ________  __                                         
 /      \                     |        \|  \                                        
|  $$$$$$\  ______    ______  | $$$$$$$$ \$$ _______    ______    ______    ______  
| $$__| $$ /      \  /      \ | $$__    |  \|       \  /      \  /      \  /      \ 
| $$    $$|  $$$$$$\|  $$$$$$\| $$  \   | $$| $$$$$$$\|  $$$$$$\|  $$$$$$\|  $$$$$$\
| $$$$$$$$| $$  | $$| $$  | $$| $$$$$   | $$| $$  | $$| $$  | $$| $$    $$| $$   \$$
| $$  | $$| $$__/ $$| $$__/ $$| $$      | $$| $$  | $$| $$__| $$| $$$$$$$$| $$      
| $$  | $$| $$    $$| $$    $$| $$      | $$| $$  | $$ \$$    $$ \$$     \| $$      
 \$$   \$$| $$$$$$$ | $$$$$$$  \$$       \$$ \$$   \$$ _\$$$$$$$  \$$$$$$$ \$$      
          | $$      | $$                              |  \__| $$                    
          | $$      | $$                               \$$    $$                    
           \$$       \$$                                \$$$$$$                     
`, Version)

func main() {
	gologger.DefaultLogger.SetMaxLevel(levels.LevelWarning)
	options := internal.ParseOptions()
	if options.Debug {
		gologger.DefaultLogger.SetMaxLevel(levels.LevelDebug)
	}
	if options.Version {
		gologger.Info().Msgf("AppFinger Version: %s", Version)
		return
	}
	if options.UpdateRule {
		customrules.DefaultProvider.Update(context.Background(), options.FingerHome)
		return
	}
	crawlOptions := crawl.DefaultOption()
	crawlOptions.DebugResp = options.DebugResp
	crawlOptions.Timeout = time.Duration(options.Timeout) * time.Second
	crawlOptions.Proxy = options.Proxy
	spider := crawl.NewCrawler(crawlOptions)
	manager := rule.GetRuleManager()
	err := manager.LoadRules(options.FingerHome)
	if err != nil {
		gologger.Print().Msgf(err.Error())
		return
	}
	// 计算规则总数
	totalRules := 0
	for _, rules := range manager.GetFinger().Rules {
		totalRules += len(rules)
	}
	gologger.Info().Msgf("Loaded %d rule categories with %d total rules", len(manager.GetFinger().Rules), totalRules)
	// 将internal.Options转换为runner.Options
	runnerOptions := &runner.Options{
		// 输入相关
		Targets: options.URL,
		File:    options.UrlFile,
		Stdin:   options.Stdin,
		// 运行相关
		Threads:  options.Threads,
		Timeout:  options.Timeout,
		Verbose:  options.Debug,
		Silent:   false,
		RulePath: options.FingerHome,

		// 输出相关
		Output:    options.OutputFile,
		JSON:      options.OutputType == "json",
		NoColor:   false,
		OutputAll: true,
	}

	appRunner, err := runner.NewRunner(spider, manager, runnerOptions)
	if err != nil {
		gologger.Print().Msgf(err.Error())
		return
	}
	err = appRunner.Enumerate()
	if err != nil {
		gologger.Error().Msgf(err.Error())
		return
	}
}
