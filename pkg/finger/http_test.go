package finger

import (
	"crypto/tls"
	"fmt"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/gologger/levels"
	"github.com/stretchr/testify/assert"
	"golang.org/x/net/html/charset"
	"io"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"net/http/cookiejar"
	"os"
	"regexp"
	"strings"
	"testing"
	"time"
)

func TestMatch(t *testing.T) {
	content := `- name: nginx
  matchers:
  - type: word
    words:
      - <title>Jupyter Notebook</title>
- name: php
  matchers:
    - type: regex
      name: version
      part: header
      group: 1
      regex:
        - "X-Powered-By: PHP/([0-9.]+)"`
	a := assert.New(t)
	appFinger := AppFinger{}
	_ = appFinger.AddFinger(content)
	a.True(len(appFinger.Rules) > 0)
	banner := &Banner{Header: `HTTP/1.0 301 Moved Permanently
Date: Mon, 21 Aug 2023 11:51:58 GMT
Server: Apache/2.4.51 (Debian)
X-Powered-By: PHP/7.4.24
X-Redirect-By: WordPress
Location: https:///
Content-Length: 0
Connection: close
Content-Type: text/html; charset=UTF-8`}
	appFinger.Match(banner, appFinger.Rules)

}

func TestAppFinger2(t *testing.T) {
	a := assert.New(t)
	appFinger := AppFinger{}
	_ = appFinger.AddFinger(`- matchers:
  - part: header
    type: regex
    name: version
    group: 1
    regex:
      - 'Server: [A-Za-z0-9. \/]+CPython/([0-9.]+)'
  name: Apache HTTP`)
	a.True(len(appFinger.Rules) > 0)
	t.Logf("Load Finger Count:%d", len(appFinger.Rules))
	banner := &Banner{Header: `HTTP/1.1 200 OK
Accept-Ranges: bytes
Content-Type: text/html
Date: Tue, 22 Aug 2023 03:08:52 GMT
Etag: "29cd-5d90af6b0e00e-gzip"
Last-Modified: Mon, 28 Feb 2022 02:39:55 GMT
Server: WSGIServer/0.2 CPython/3.8.0
Vary: Accept-Encoding
`}
	m := appFinger.Match(banner, appFinger.Rules)
	println(m.Extract)
}

func TestAppFingerMatchRegex(t *testing.T) {
	banner := `Accept-Ranges: bytes
Cache-Control: no-cache
Content-Type: text/html
Date: Sun, 22 Oct 2023 19:05:02 GMT
Keep-Alive: timeout=15, max=94
Pragma: no-cache
Server: Boa/0.94.14rc21
Set-Cookie: 000c280b20b0_USER=;
Set-Cookie: 000c280b20b0_POLICY=;`

	regex, _ := regexp.Compile("Server: Boa(?:/([\\d.]+\\w*))")
	matched := regex.FindStringSubmatch(banner)
	if len(matched) > 1 {
		version := matched[1]
		fmt.Printf("%v\n", version)
	} else {
		fmt.Println("No version found")
	}
}

func TestAppFinger(t *testing.T) {
	gologger.DefaultLogger.SetMaxLevel(levels.LevelVerbose)
	finger := New(&Options{Timeout: time.Second * 3})
	finger.Rules = nil
	_ = finger.AddFinger(`- name: Boa
  matchers:
    - part: header
      type: regex
      name: version
      regex:
        - "Server: Boa(?:/(.*))"
`)

	for _, rule := range finger.Rules {
		matched, extract := rule.Match(&Banner{Header: `HTTP/1.1 200 OK
Content-Length: 364
Accept-Ranges: bytes
Connection: Keep-Alive
Content-Type: text/html
Date: Fri, 03 Nov 2023 09:05:20 GMT
Keep-Alive: timeout=30, max=100
Last-Modified: Sat, 06 Jun 2015 04:23:20 GMT
Server: Boa/0.94.14rc21`,
		})
		gologger.Info().Msgf("Matched:%v Extract:%v", matched, extract)
	}
}

func TestRegex(t *testing.T) {
	gologger.DefaultLogger.SetMaxLevel(levels.LevelVerbose)
	finger := New(&Options{Timeout: time.Second * 3})
	finger.Rules = nil
	_ = finger.AddFinger(`- matchers:
    - part: headers.server
      type: regex
      name: version
      regex:
        - bfe/([\d.]+)
`)

	for _, rule := range finger.Rules {
		matched, extract := rule.Match(&Banner{Headers: map[string]string{"headers.server": "bfe/1.0.8.18"}})
		gologger.Info().Msgf("Matched:%v Extract:%v", matched, extract)
	}
}

func TestRedirect(t *testing.T) {
	uri := parseJavaScript("", `<!DOCTYPE html PUBLIC "-//W3C//DTD HTML 4.01 Frameset//EN">
<html lang="ja" oncontextmenu="return false">
<head>
<meta finger-equiv="pragma" content="no-cache">
<meta finger-equiv="cache-control" content="no-cache">
<meta finger-equiv="Content-Type" content="text/html; charset=UTF-8">
<title>BB-SW172 Network Camera</title>
</head>
<body leftmargin="0" topmargin="0" marginwidth="0" marginheight="0">
<script type="text/javascript">
<!--
location.replace("./live/index2.html?Language=1")
//-->
</script>
</body>`)
	println(uri)
}

func TestRedirect2(t *testing.T) {
	uri := parseJavaScript("", `<!doctype html>
<html>
<head>
	<title></title>
	<meta finger-equiv="Content-Type" content="text/html; charset=utf-8" />
	<meta finger-equiv="X-UA-Compatible" content="IE=edge" >
	<meta finger-equiv="Pragma" content="no-cache" />
	<meta finger-equiv="Cache-Control" content="no-cache, must-revalidate" />
	<meta finger-equiv="Expires" content="0" />
</head>
<body>
</body>
<script>
	window.location.href = "./doc/page/login.asp?_" + (new Date()).getTime();
</script>
</html>`)
	println(uri)
}

func TestLocalFile(t *testing.T) {
	serverAddr := "127.0.0.1:3333"
	listener, err := net.Listen("tcp", serverAddr)
	if err != nil {
		log.Fatal("Unable to listen on ", serverAddr, ": ", err)
	}
	defer listener.Close()
	// 接受客户端连接
	client, err := listener.Accept()
	if err != nil {
		log.Println("Error accepting client connection:", err)
		return
	}
	// 读取文件内容
	file, err := os.Open("/tmp/1.txt")
	if err != nil {
		return
	}
	fileContent, err := io.ReadAll(file)
	if err != nil {
		return
	}
	if err != nil {
		log.Println("Error reading file:", err)
		client.Close()
		return
	}
	// 将文件内容发送给客户端
	_, err = client.Write(fileContent)
	if err != nil {
		log.Println("Error sending file content to client:", err)
		return
	}
}

func TestRegex2(t *testing.T) {
	regex, _ := regexp.Compile(`/wp-content/plugins/([\w-]+)/(?:.*\?ver=([\d.]+))?`)
	matched := regex.FindAllStringSubmatch(`<script type='text/javascript' src='https://care.cz/wp-content/plugins/salient-portfolio/js/third-party/imagesLoaded.min.js?ver=4.1.4' id='imagesLoaded-js'></script>
<script type='text/javascript' src='https://care.cz/wp-content/plugins/interactive-geo-maps/assets/maps-service/assets/js/app.min.js?' id='interactive-geo-maps_map_service-js'></script>`, -1)
	fmt.Printf("%v\n", matched)
}

func TestMurmurhash(t *testing.T) {
	assert.Equal(t, int32(851989093), mmh3([]byte("foo")))
}

func TestCharset(t *testing.T) {
	req, err := http.Get("http://1.180.157.154:8087/login.jsp")
	if err != nil {
		return
	}
	//println(req.TransferEncoding)
	body, err := io.ReadAll(req.Body)
	if err != nil {
		return
	}
	r, err := charset.NewReaderLabel("gb2312", strings.NewReader(string(body)))
	if err != nil {
		return
	}

	decodedBody, err := io.ReadAll(r)
	if err != nil {
		return
	}
	println(string(decodedBody))
}

func TestReqOnce(t *testing.T) {
	client, err := NewClient(WithTimeout(time.Second * time.Duration(2)))
	assert.Nil(t, err)
	_, _, err = RequestOnce(client, "http://finger.lostpeach.cn")
	assert.Nil(t, err)
}

func TestRequest(t *testing.T) {
	_, err := Request("https://91.208.57.30:443", time.Second*time.Duration(2), "", true, false)
	assert.Nil(t, err)

}

func TestClient(t *testing.T) {
	client, err := NewClient(WithTimeout(time.Second * time.Duration(2)))
	assert.Nil(t, err)
	response, err := client.Get("https://91.208.57.30:443")
	assert.Nil(t, err)
	defer response.Body.Close()
	body, _ := io.ReadAll(response.Body)
	fmt.Println(string(body))
}

func TestRequestOnce(t *testing.T) {
	gologger.DefaultLogger.SetMaxLevel(levels.LevelDebug)
	client, err := NewClient(WithTimeout(time.Second * time.Duration(2)))
	assert.Nil(t, err)
	_, _, err = RequestOnce(client, "https://91.208.57.30:443")
	assert.Nil(t, err)
}

func TestHTTP(t *testing.T) {
	// 创建一个 HTTP 客户端
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{
			MinVersion:           tls.VersionTLS10,
			InsecureSkipVerify:   true,
			GetClientCertificate: nil,
		},
	}
	// 创建一个共享的 CookieJar
	jar, err := cookiejar.New(nil)
	if err != nil {
		return
	}
	client := &http.Client{
		Transport: tr,
		Jar:       jar,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		}}

	// 创建一个 GET 请求
	req, err := http.NewRequest("GET", "https://91.208.57.30:443", nil)
	if err != nil {
		log.Fatalf("创建请求失败: %v", err)
	}

	// 发送请求
	resp, err := client.Do(req)
	if err != nil {
		log.Fatalf("发送请求失败: %v", err)
	}
	defer resp.Body.Close()

	// 读取响应
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		log.Fatalf("读取响应失败: %v", err)
	}

	// 输出响应内容
	fmt.Println("响应状态:", resp.Status)
	fmt.Println("响应体:", string(body))
}
