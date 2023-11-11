package main

import (
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/gologger/levels"
	"github.com/tongchengbin/appfinger/pkg/runner"
)

func main() {
	gologger.DefaultLogger.SetMaxLevel(levels.LevelWarning)
	options := runner.ParseOptions()
	appRunner, err := runner.NewRunner(options)
	if err != nil {
		panic(err)
	}
	err = appRunner.Enumerate()
	if err != nil {
		panic(err)
	}
}
