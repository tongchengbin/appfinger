package finger

import (
	"fmt"
	"github.com/projectdiscovery/gologger"
	"github.com/robertkrimen/otto"
	"golang.org/x/net/html"
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
			if strings.ToLower(attr.Key) == "http-equiv" && strings.ToLower(attr.Val) == "refresh" {
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
func getExecRedirect(url string, jsCodes []string) string {
	vm := otto.New()
	if url[len(url)-1] != '/' {
		url += "/"
	}
	initWindowsCode := fmt.Sprintf(`
		var window = {
			location: {href: '%s'}
			open: function(url, target) {
				window.href =url;
		}
};
`, url)
	_, err := vm.Run(initWindowsCode)
	var consoleLogs []string
	_ = vm.Set("console", map[string]interface{}{
		"log": func(call otto.FunctionCall) otto.Value {
			for _, arg := range call.ArgumentList {
				value, _ := arg.Export()
				consoleLogs = append(consoleLogs, fmt.Sprint(value))
			}
			return otto.Value{}
		},
	})
	if err != nil {
		fmt.Println("JavaScript execution error:", err)
		return ""
	}
	for _, code := range jsCodes {
		_, err = vm.Run(code)
		if err != nil {
			gologger.Debug().Msgf("Error getting result:%v", err)
			return ""
		}
	}
	_, err = vm.Run(`
		if (window.onload) {
			window.onload();
		}
	`)
	// 获取执行后的地址
	result, err := vm.Get("window")
	if err != nil {
		gologger.Debug().Msgf("Error getting result:%v", err)
		return ""
	}
	if result.IsObject() {
		// 获取对象的属性和值
		properties, err := result.Object().Get("location")
		if err != nil {
			return ""
		}
		if properties.IsObject() {
			href, _ := result.Object().Get("href")
			if href.IsString() {
				return href.String()
			} else {
				return ""
			}

		} else if properties.IsString() {
			return properties.String()
		} else {
			return ""
		}
	} else if result.IsString() {
		return ""
	} else {
		gologger.Debug().Msg("指定的变量不是 JavaScript 对象")
	}
	return ""
}
func parseJavaScript(url string, htmlContent string) string {
	// 在这里解析JavaScript，提取跳转信息
	//<meta http-equiv="Refresh"content="0;url=/yyoa/index.jsp">
	doc, err := html.Parse(strings.NewReader(htmlContent))
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
	var visitNode func(n *html.Node)
	var scripts []string
	visitNode = func(n *html.Node) {
		// 如果节点是一个script标签并且包含JavaScript代码，则将其添加到切片中
		if n.Type == html.ElementNode && n.Data == "script" {
			var jsCode string

			// 提取script标签内的文本内容
			for c := n.FirstChild; c != nil; c = c.NextSibling {
				if c.Type == html.TextNode {
					jsCode += c.Data
				}
			}

			// 将JavaScript代码添加到切片中
			if jsCode != "" {
				scripts = append(scripts, jsCode)
			}
		}

		// 递归遍历子节点
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			visitNode(c)
		}
	}
	visitNode(doc)
	if len(scripts) > 2 {
		return ""
	} else {
		return getExecRedirect(url, scripts)
	}
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
