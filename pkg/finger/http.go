package finger

import (
	"bytes"
	"crypto/tls"
	"errors"
	"github.com/projectdiscovery/gologger"
	"golang.org/x/net/html"
	"golang.org/x/text/encoding/charmap"
	"golang.org/x/text/encoding/simplifiedchinese"
	"golang.org/x/text/transform"
	"net/http"
	"net/url"
	"strings"
	"time"
)

func getTitle(body []byte) string {
	var title string

	// Tokenize the HTML document and check for fingerprints as required
	tokenizer := html.NewTokenizer(bytes.NewReader(body))

	for {
		tt := tokenizer.Next()
		switch tt {
		case html.ErrorToken:
			return title
		case html.StartTagToken:
			token := tokenizer.Token()
			switch token.Data {
			case "title":
				// Next text token will be the actual title of the page
				if tokenType := tokenizer.Next(); tokenType != html.TextToken {
					continue
				}
				title = tokenizer.Token().Data
			}
		}
	}
}

func ResponseDecoding(body []byte, charset string) string {
	// 根据编码 对响应结果进行解码
	var str string
	charset = strings.Trim(strings.Trim(strings.ToUpper(charset), "\""), ";")
	switch charset {
	case "UTF-8":
		str = string(body)
	case "UTF8":
		str = string(body)
	case "GBK":
		// 解码为GBK编码
		decoder := simplifiedchinese.GB18030.NewDecoder()
		decodedBody, _, err := transform.Bytes(decoder, body)
		if err != nil {
			return ""
		}
		str = string(decodedBody)
	case "ISO-8859-1":
		decoder := charmap.ISO8859_1.NewDecoder()
		decodedBody, _, err := transform.Bytes(decoder, body)
		if err != nil {
			return ""
		}
		str = string(decodedBody)
	case "GB18030":
		decoder := simplifiedchinese.GB18030.NewDecoder()
		decodedBody, _, err := transform.Bytes(decoder, body)
		if err != nil {
			return ""
		}
		str = string(decodedBody)
	case "GB2312":
		decoder := simplifiedchinese.HZGB2312.NewDecoder()
		decodedBody, _, err := transform.Bytes(decoder, body)
		if err != nil {
			return ""
		}
		str = string(decodedBody)
	case "US-ASCII":
		str = string(body)
	default:
		str = string(body)
	}
	return str
}

func Request(uri string, timeout time.Duration, proxy string) ([]*Banner, error) {
	var proxyURl *url.URL
	var err error
	if proxy != "" {
		proxyURl, err = url.Parse(proxy)
		if err != nil {
			return nil, err
		}
	}

	client := &http.Client{
		Transport: &http.Transport{Proxy: http.ProxyURL(proxyURl)},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 10 {
				return http.ErrUseLastResponse
			}
			if via[0].URL.Host != req.URL.Host {
				return http.ErrUseLastResponse
			}
			// 在这里可以自定义重定向策略
			// 例如，你可以修改请求头，记录重定向次数等
			// 默认行为是跟随重定向
			return nil
		},
		Timeout: timeout,
	}
	if strings.HasPrefix(uri, "https://") {
		tr := &http.Transport{
			Proxy:           http.ProxyURL(proxyURl),
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		}
		client.Transport = tr
	}
	var banners []*Banner
	var nextURI = uri
	for ret := 0; ret < 3; ret++ {
		var rawResp bytes.Buffer
		// 开始请求数据
		req, err := http.NewRequest("GET", nextURI, nil)
		if err != nil {
			return banners, err
		}
		req.Header.Set("Accept", "*/*")
		req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36 Edg/114.0.1823.58")
		resp, err := client.Do(req)
		if err != nil && err.Error() != http.ErrUseLastResponse.Error() {
			return banners, err
		}
		//rawResp.
		_ = resp.Write(&rawResp)
		var charset = "UTF-8"
		contentType := resp.Header.Get("Content-Type")
		if strings.Contains(contentType, "charset=") {
			charsetIndex := strings.Index(contentType, "charset=")
			charset = strings.Trim(contentType[charsetIndex+len("charset="):], " ")
		}
		RawData := ResponseDecoding(rawResp.Bytes(), charset)
		separator := []byte("\r\n\r\n")
		gologger.Debug().Msg("Dump HTTP Response For " + uri + "\r\n" + RawData)
		index := strings.Index(RawData, "\r\n\r\n")
		if index == -1 {
			gologger.Warning().Msg("无法找到响应头和响应体的分割点:" + uri + "\r\n\r\n" + RawData)
			return banners, errors.New("不是标准HTTP响应")
		}
		// 分割响应头和响应体
		headerBytes := RawData[:index]
		bodyBytes := RawData[index+len(separator):]
		banner := &Banner{Body: RawData, Header: headerBytes, StatusCode: resp.StatusCode, Response: RawData, Headers: map[string]string{}}
		banner.Title = getTitle([]byte(bodyBytes))
		for k, v := range resp.Header {
			banner.Headers[strings.ToLower(k)] = strings.Join(v, ",")
		}
		banners = append(banners, banner)
		// 解析JavaScript跳转

		jsRedirectUri := parseJavaScript(bodyBytes)
		if jsRedirectUri == "" {
			break
		} else {
			nextURI = uri + "/" + jsRedirectUri
			gologger.Debug().Msgf("redirect URL:%s", nextURI)
		}

	}
	return banners, nil
}