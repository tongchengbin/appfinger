package runner

import (
	"fmt"
	"github.com/logrusorgru/aurora"
	"github.com/projectdiscovery/gologger"
	"github.com/tongchengbin/appfinger"
	"strings"
	"time"
)

type Runner struct {
	options  *Options
	finger   *appfinger.AppFinger
	callback func(url string, banner *appfinger.Banner, extract map[string]map[string]string)
}

func formatExtract(extract map[string]map[string]string) string {
	var s []string
	for key, value := range extract {
		var s2 []string
		for v, vv := range value {
			s2 = append(s2, aurora.Blue(fmt.Sprintf("%s=%s", v, vv)).String())
		}
		s = append(s, fmt.Sprintf("%s:{%s}", aurora.Cyan(key).String(), strings.Join(s2, ",")))
	}
	return strings.Join(s, ",")
}

func NewRunner(options *Options) (*Runner, error) {
	runner := &Runner{
		options: options,
		finger:  appfinger.New(&appfinger.Options{Timeout: time.Second * time.Duration(options.Timeout), Proxy: options.Proxy, Home: options.FingerHome}),
		callback: func(url string, banner *appfinger.Banner, extract map[string]map[string]string) {
			gologger.Info().Msgf("[%s] %v", aurora.Green(url).String(), formatExtract(extract))
		},
	}
	return runner, nil

}
