package finger

import (
	"fmt"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/gologger/levels"
	"github.com/stretchr/testify/assert"
	"gopkg.in/yaml.v3"
	"regexp"
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
	appFinger.Match(banner)

}

func TestRule(t *testing.T) {
	content := `- name: nginx
  matchers-condition: or
  matchers:
  - type: word
    name: Jupyter
    words:
      - <title>Jupyter Notebook</title>
    part: body
`
	a := assert.New(t)
	var rules []*Rule
	err := yaml.Unmarshal([]byte(content), &rules)
	a.Nil(err)
	a.Equal(rules[0].Name, "nginx")
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
	m := appFinger.Match(banner)
	println(len(m))
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
	uri := parseJavaScript(`<!DOCTYPE html PUBLIC "-//W3C//DTD HTML 4.01 Frameset//EN">
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
	uri := parseJavaScript(`<!doctype html>
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
