package crawl

import "time"

type Options struct {
	DisableIcon bool
	Proxy       string
	DebugResp   bool
	Timeout     time.Duration
}

func DefaultOption() *Options {
	return &Options{
		DisableIcon: false,
		Proxy:       "",
		DebugResp:   false,
		Timeout:     6 * time.Second,
	}

}
