package finger

import (
	"fmt"
	"github.com/projectdiscovery/gologger"
	"github.com/robertkrimen/otto"
	"golang.org/x/net/html"
	"net/url"
	"strings"
)

func extractUri(n *html.Node) string {
	// 处理 <meta http-equiv="Refresh" content="0;url=/yyoa/index.jsp"> 标签
	for _, attr := range n.Attr {
		if attr.Key == "content" {
			parts := strings.Split(attr.Val, ";")
			for _, part := range parts {
				if strings.Contains(strings.ToLower(part), "url=") {
					redirectURL := strings.TrimSpace(strings.SplitN(part, "=", 2)[1])
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
func getExecRedirect(uri string, jsCodes []string, onload string) string {
	vm := otto.New()
	parsed, _ := url.Parse(uri)
	initWindowsCode := fmt.Sprintf(`
		var location = {href:"%s",hostname:"%s","protocol":"%s"};
		var window = {
			location: location,
			open: function(url, target) {
				window.location.href =url;
			}
		};
		var top = {
			window: window,
			location: location,
			document: {
				location: window.location		
			}
		}
		var document = {
			location: window.location,	
		};
		window.top = top;
`, uri, parsed.Hostname(), parsed.Scheme)
	_, err := vm.Run(initWindowsCode)
	if err != nil {
		gologger.Debug().Msgf("Error getting result:%v", err)
	}
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
	_, err = vm.Run(fmt.Sprintf(`
		%s
		if (window.onload) {
			window.onload();
		}
		if(location.href){
			window.location.href = location.href;
		}
		if(top.document.location.href){
			window.location.href = top.document.location.href;
		}
		var finalHref = window.location.href;
		//console.log(JSON.stringify(window))
	`, onload))
	if err != nil {
		gologger.Debug().Msgf("Error getting result:%v", err)
		return ""
	}
	//for _, log := range consoleLogs {
	//	fmt.Println(">>|", log)
	//}
	// 获取执行后的地址
	result, err := vm.Get("finalHref")
	if err != nil {
		gologger.Debug().Msgf("Error getting result:%v", err)
		return ""
	}
	r2 := result.String()
	if r2 == uri {
		return ""
	}
	return result.String()
}
func findAttribute(attrs []html.Attribute, key string) string {
	for _, attr := range attrs {
		if attr.Key == key {
			return attr.Val
		}
	}
	return ""
}
func extractCharset(htmlContent string) string {
	reader := strings.NewReader(htmlContent)
	doc, err := html.Parse(reader)
	if err != nil {
		return "UTF-8"
	}

	var charset string
	var traverse func(*html.Node)
	traverse = func(n *html.Node) {
		if n.Type == html.ElementNode && n.Data == "meta" {
			for _, attr := range n.Attr {
				if attr.Key == "http-equiv" && strings.EqualFold(attr.Val, "Content-Type") {
					contentAttr := findAttribute(n.Attr, "content")
					charsetIndex := strings.Index(contentAttr, "charset=")
					if charsetIndex != -1 {
						charset = contentAttr[charsetIndex+len("charset="):]
						break
					}
				}
			}
		}

		for c := n.FirstChild; c != nil; c = c.NextSibling {
			traverse(c)
		}
	}
	traverse(doc)
	return strings.ToUpper(strings.TrimSpace(charset))
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
	var onload string
	visitNode = func(n *html.Node) {
		if n.Type == html.ElementNode && n.Data == "body" {
			for _, attr := range n.Attr {
				if attr.Key == "onload" {
					onload = attr.Val
				}
			}
		}
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
		// parse onload
		if strings.HasPrefix(onload, "javascript:") {
			return getExecRedirect(url, scripts, strings.Split(onload, ":")[1])
		} else {
			return getExecRedirect(url, scripts, "")
		}
	}
}

func urlJoin(base, path string) string {
	if strings.HasPrefix(path, "http://") || strings.HasPrefix(path, "https://") {
		return path
	}
	if base[len(base)-1] != '/' && path[0] != '/' {
		base += "/"
	}
	if base[len(base)-1] == '/' && path[0] == '/' {
		path = path[1:]
	}
	return base + path
}
func joinURL(baseURL, path string) string {
	base, err := url.Parse(baseURL)
	if err != nil {
		return ""
	}
	// 使用 ResolveReference 方法拼接路径
	fullURL := base.ResolveReference(&url.URL{Path: path})
	return fullURL.String()
}
