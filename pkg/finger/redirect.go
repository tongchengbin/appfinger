package finger

import (
	"golang.org/x/net/html"
	"regexp"
	"strings"
)

func extractUri(n *html.Node) string {
	// 处理 <meta http-equiv="Refresh" content="0;url=/yyoa/index.jsp"> 标签
	for _, attr := range n.Attr {
		if attr.Key == "content" {
			parts := strings.Split(attr.Val, ";")
			for _, part := range parts {
				if strings.Contains(part, "url=") {
					redirectURL := strings.TrimPrefix(strings.TrimSpace(strings.Split(part, "=")[1]), "/")
					return redirectURL
				}
			}
		}
	}
	return ""
}

func findRefresh(n *html.Node) string {
	var uri string
	if n.Type == html.ElementNode && n.Data == "meta" {
		for _, attr := range n.Attr {
			if attr.Key == "http-equiv" && attr.Val == "Refresh" {
				uri = extractUri(n)
				if uri != "" {
					return uri

				}
				//return
			}
		}
	}

	for c := n.FirstChild; c != nil; c = c.NextSibling {
		uri = findRefresh(c)
		if uri != "" {
			return uri
		}
	}
	return ""
}

func parseJavaScript(scriptContent string) string {
	// 在这里解析JavaScript，提取跳转信息
	//<meta http-equiv="Refresh"content="0;url=/yyoa/index.jsp">
	doc, err := html.Parse(strings.NewReader(scriptContent))
	if err != nil {
		return ""
	}
	var uri string
	for c := doc.FirstChild; c != nil; c = c.NextSibling {
		uri = findRefresh(c)
		if uri != "" {
			return uri
		}
	}

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
	return ""
}

func urlJoin(base, path string) string {
	if base[len(base)-1] != '/' && path[0] != '/' {
		base += "/"
	}
	if base[len(base)-1] == '/' && path[0] == '/' {
		path = path[1:]
	}
	return base + path
}
