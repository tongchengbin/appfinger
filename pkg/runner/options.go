package runner

import (
	"errors"
	"fmt"
	"github.com/projectdiscovery/goflags"
	"io"
	"os"
	"path"
	"strings"
)

func GetDefaultDirectory() string {
	d, _ := os.UserHomeDir()
	return path.Join(d, "finger")
}

type Options struct {
	UrlFile           string
	URL               goflags.StringSlice
	Threads           int
	Timeout           int
	Proxy             string
	Output            io.Writer
	OutputFile        string
	OutputType        string
	Stdin             bool
	FingerHome        string
	Debug             bool
	UpdateRule        bool
	DisableIcon       bool
	DisableJavaScript bool
}

func ParseOptions() *Options {
	options := &Options{}
	flagSet := goflags.NewFlagSet()
	flagSet.SetDescription(`AppFinger is a web application fingerprint scanner.`)
	flagSet.CreateGroup("AppFinger", "AppFinger",
		flagSet.StringVarP(&options.UrlFile, "url-file", "l", "", "File containing urls to scan"),
		flagSet.StringSliceVarP(&options.URL, "url", "u", nil, "target url to scan (-u INPUT1 -u INPUT2)", goflags.CommaSeparatedStringSliceOptions),
		flagSet.IntVarP(&options.Threads, "threads", "t", 10, "Number of concurrent threads (default 10)"),
		flagSet.IntVar(&options.Timeout, "timeout", 10, "Timeout in seconds (default 10)"),
		flagSet.StringVarP(&options.Proxy, "proxy", "x", "", "HTTP proxy to use for requests (e.g. http://127.0.0.1:7890)"),
		flagSet.BoolVarP(&options.Stdin, "stdin", "s", false, "Read urls from stdin"),
		flagSet.StringVarP(&options.FingerHome, "finger-home", "d", GetDefaultDirectory(), "finger yaml directory home default is built-in"),
		flagSet.BoolVarP(&options.UpdateRule, "update-rule", "ur", false, "update rule from github.com/tongchengbin/appfinger"),
		flagSet.BoolVarP(&options.DisableIcon, "disable-icon", "di", false, "disabled icon request to matcher"),
		flagSet.BoolVarP(&options.DisableJavaScript, "disable-js", "dj", false, "disabled matcher javascript rule"),
	)
	flagSet.CreateGroup("Help", "Help",
		flagSet.BoolVar(&options.Debug, "debug", false, "debug"),
	)
	flagSet.CreateGroup("output", "Output",
		flagSet.StringVarP(&options.OutputFile, "output", "o", "", "file to write output to"),
		flagSet.StringVar(&options.OutputType, "output-format", "txt", "输出文件格式"),
	)
	if err := flagSet.Parse(); err != nil {
		fmt.Println(err.Error())
		os.Exit(1)
	}
	return options
}

var (
	ErrEmptyInput = errors.New("empty data")
)

func sanitize(data string) (string, error) {
	data = strings.Trim(data, "\n\t\"' ")
	if data == "" {
		return "", ErrEmptyInput
	}
	return data, nil
}
