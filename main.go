package main

import (
	"context"
	"fmt"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/gologger/levels"
	"github.com/tongchengbin/appfinger/internal"
	"github.com/tongchengbin/appfinger/pkg/external/customrules"
	_ "net/http/pprof"
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
	appRunner, err := internal.NewRunner(options)
	if err != nil {
		gologger.Error().Msgf(err.Error())
		return
	}
	fmt.Printf(Banner)
	err = appRunner.Enumerate()
	if err != nil {
		gologger.Error().Msgf(err.Error())
		return
	}
}
