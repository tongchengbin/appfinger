package crawl

import "time"

type Options struct {
	DisableIcon bool
	Proxy       string
	DebugReq    bool
	DebugResp   bool
	Timeout     time.Duration
	RetryMax    int // 重试次数
}

func DefaultOption() *Options {
	return &Options{
		DisableIcon: false,
		Proxy:       "",
		DebugReq:    false,
		DebugResp:   false,
		Timeout:     6 * time.Second,
		RetryMax:    1,
	}

}
