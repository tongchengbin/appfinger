package rule

import (
	"regexp"
)

// 单独匹配wordpress 插件
var pluginReg = regexp.MustCompile(`/wp-content/(plugins|themes)/([\w-]+)/(?:.*\?ver=([\d.]+))?`)

func MatchWpPlugin(banner *Banner) map[string]map[string]string {
	matchedPaths := pluginReg.FindAllStringSubmatch(banner.Body, -1)
	pluginInfo := make(map[string]map[string]string)
	for _, matches := range matchedPaths {
		if len(matches) > 2 {
			pluginInfo[matches[2]] = map[string]string{}
			if len(matches) > 2 {
				pluginVersion := matches[3]
				pluginInfo[matches[2]]["version"] = pluginVersion
				pluginInfo[matches[2]]["type"] = matches[1]
			}
		}
	}
	return pluginInfo
}
