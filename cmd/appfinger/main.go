package main

import (
	"context"
	"fmt"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/gologger/levels"
	"github.com/tongchengbin/appfinger/pkg/external/customrules"
	"github.com/tongchengbin/appfinger/pkg/runner"
)

const Banner = `  ______                       ________  __                                         
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
`

func main() {
	gologger.DefaultLogger.SetMaxLevel(levels.LevelWarning)
	options := runner.ParseOptions()
	if options.Debug {
		gologger.DefaultLogger.SetMaxLevel(levels.LevelDebug)
	}
	if options.UpdateRule {
		customrules.DefaultProvider.Update(context.Background(), options.FingerHome)
		return
	}
	appRunner, err := runner.NewRunner(options)
	if err != nil {
		panic(err)
	}
	fmt.Printf(Banner)
	err = appRunner.Enumerate()
	if err != nil {
		panic(err)
	}
}
