package finger

import "regexp"

func parseJavaScript(scriptContent string) string {
	// 在这里解析JavaScript，提取跳转信息
	re := regexp.MustCompile(`location\.replace\(["'](.+?)["']\)`)
	matches := re.FindStringSubmatch(scriptContent)

	if len(matches) >= 2 {
		return matches[1]
	}

	re = regexp.MustCompile(`location\.href[ ]=[ ]["'](.+?)["']`)
	matches = re.FindStringSubmatch(scriptContent)

	if len(matches) >= 2 {
		return matches[1]
	}
	// window.onload=function(){ url ='/webui';window.location.href=url;}
	re = regexp.MustCompile(`location\.href\s*=\s*(.+?)`)
	matches = re.FindStringSubmatch(scriptContent)
	if len(matches) >= 2 {
		// 匹配url
		ure := regexp.MustCompile(`["'](.+?)["']`)
		m2 := ure.FindStringSubmatch(scriptContent)
		if len(m2) >= 2 {
			return m2[1]
		}
	}
	return ""
}

func urlJoin(base, path string) string {
	if base[len(base)-1] != '/' && path[0] != '/' {
		base += "/"
	}

	return base + path
}
