package runner

import (
	"encoding/json"
	"fmt"
	"github.com/logrusorgru/aurora"
	"github.com/projectdiscovery/gologger"
	"github.com/tongchengbin/appfinger/pkg/finger"
	"io"
	"strings"
	"time"
)

type Runner struct {
	options  *Options
	finger   *finger.AppFinger
	callback func(runner *Runner, url string, banner *finger.Banner, extract map[string]map[string]string)
	outputs  []io.Writer
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
		finger: finger.New(&finger.Options{Timeout: time.Second * time.Duration(options.Timeout),
			Proxy:             options.Proxy,
			Home:              options.FingerHome,
			DisableJavaScript: options.DisableJavaScript,
			DisableIcon:       options.DisableIcon,
		}),
		callback: func(r *Runner, url string, banner *finger.Banner, extract map[string]map[string]string) {
			for _, output := range r.outputs {
				out := &OutputFields{URL: url, Extract: extract}
				s, _ := json.Marshal(out)
				_, _ = output.Write(append(s, "\n"...))
			}
			gologger.Info().Msgf("[%s] %v", aurora.Green(url).String(), formatExtract(extract))
		},
	}
	var outputs []io.Writer
	if options.OutputFile != "" {
		outputWriter := NewOutputWriter(true)
		file, err := outputWriter.createFile(options.OutputFile, true)
		if err != nil {
			gologger.Error().Msgf("Could not create file for %s: %s\n", options.OutputFile, err)
			return nil, err
		}
		outputs = append(outputs, file)
	}
	runner.outputs = outputs
	return runner, nil

}
