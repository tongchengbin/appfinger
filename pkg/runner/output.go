package runner

import (
	"fmt"
	"github.com/logrusorgru/aurora/v4"
	"github.com/tongchengbin/appfinger/pkg/crawl"
)

func formatConsole(banner *crawl.Banner, components map[string]map[string]string) string {
	var s string
	s += aurora.Cyan(banner.Uri).String()
	if banner.Title != "" {
		s += aurora.Blue(banner.Title).String()
	}
	for name, component := range components {
		v := name
		for k, kv := range component {
			v += fmt.Sprintf(" %s=%s", k, kv)
		}
		s += fmt.Sprintf(" [%s]", aurora.Green(v))
	}

	if server, ok := banner.Headers["server"]; ok {
		s += fmt.Sprintf(" [%s]", aurora.Yellow(server).String())
	}
	if banner.Cert != nil {
		s += fmt.Sprintf(" [%s]", aurora.Red(banner.Cert.ServerName))
	}
	return s
}
