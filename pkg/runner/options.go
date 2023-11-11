package runner

import (
	"errors"
	"fmt"
	"github.com/projectdiscovery/goflags"
	"io"
	"os"
	"strings"
)

type Options struct {
	UrlFile    string
	URL        goflags.StringSlice
	Threads    int
	Timeout    int
	Proxy      string
	Output     io.Writer
	OutputFile string
	Stdin      bool
	FingerHome string
	Debug      bool
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
		flagSet.StringVarP(&options.FingerHome, "finger-home", "d", "", "finger yaml directory home default is built-in"),
	)
	flagSet.CreateGroup("Help", "Help",
		flagSet.BoolVar(&options.Debug, "debug", false, "debug"),
	)
	flagSet.CreateGroup("output", "Output",
		flagSet.StringVarP(&options.OutputFile, "output", "o", "", "file to write output to"))
	if err := flagSet.Parse(); err != nil {
		fmt.Println(err.Error())
		os.Exit(1)
	}

	// Default output is stdout
	options.Output = os.Stdout
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
