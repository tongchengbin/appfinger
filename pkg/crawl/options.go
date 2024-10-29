package crawl

import "time"

type Options struct {
	DisableIcon bool
	Proxy       string
	DebugResp   bool
	Timeout     time.Duration
}
