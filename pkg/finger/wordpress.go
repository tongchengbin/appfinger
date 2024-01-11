package finger

import (
	"fmt"
	"regexp"
)

// 单独匹配wordpress 插件
var pluginReg = regexp.MustCompile(`/wp-content/plugins/([\w-]+)/(?:.*\?ver=([\d.]+))?`)

func MatchWpPlugin(banner *Banner) map[string]map[string]string {
	matchedPaths := pluginReg.FindAllStringSubmatch(banner.Body, -1)
	pluginInfo := make(map[string]map[string]string)
	for _, matches := range matchedPaths {
		fmt.Printf("%v\n", matches)
		if len(matches) > 1 {
			pluginInfo[matches[1]] = map[string]string{}
			if len(matches) > 2 {
				pluginVersion := matches[2]
				pluginInfo[matches[1]]["version"] = pluginVersion
			}
		}
	}
	fmt.Printf("%v", pluginInfo)
	return pluginInfo
}
