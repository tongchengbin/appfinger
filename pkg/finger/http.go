package finger

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"fmt"
	"github.com/PuerkitoBio/goquery"
	"github.com/projectdiscovery/gologger"
	"golang.org/x/net/html/charset"
	"golang.org/x/net/proxy"
	"golang.org/x/text/encoding/charmap"
	"golang.org/x/text/encoding/simplifiedchinese"
	"golang.org/x/text/transform"
	"io"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"regexp"
	"strings"
	"time"
)

func getTitle(body []byte) []byte {
	re := regexp.MustCompile(`(?i)<title[^>]*>([^<]+)</title>`)
	matches := re.FindSubmatch(body)
	if len(matches) >= 2 {
		return matches[1]
	}
	return nil
}

func ResponseDecoding(body []byte, label string) string {
	// 根据编码 对响应结果进行解码
	var str string
	label = strings.Trim(strings.Trim(strings.ToUpper(label), "\""), ";")
	switch label {
	case "UTF-8", "UTF8", "US-ASCII":
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
		r, err := charset.NewReaderLabel("gb2312", strings.NewReader(string(body)))
		if err != nil {
			return ""
		}
		data, _ := io.ReadAll(r)
		str = string(data)
	case "BIG5":
		r, err := charset.NewReaderLabel("big5", strings.NewReader(string(body)))
		if err != nil {
			return ""
		}
		data, _ := io.ReadAll(r)
		str = string(data)
	default:
		str = string(body)
	}
	return str
}

func parseCertificateInfo(ts *tls.ConnectionState) string {
	cert := ts.PeerCertificates[0]
	ss := fmt.Sprintf("SSL Certificate\nVersion: TLS 1.%d\nCipherSuit:%s\nCertificate:\n\tSignature Algorithm: %s\n",
		cert.Version,
		tls.CipherSuiteName(ts.CipherSuite),
		cert.SignatureAlgorithm.String())
	var isUser []string
	if cert.Issuer.Country != nil {
		isUser = append(isUser, fmt.Sprintf("C=%s", strings.Join(cert.Issuer.Country, ",")))
	}
	if len(cert.Issuer.CommonName) > 0 {
		isUser = append(isUser, fmt.Sprintf("CN=%s", cert.Issuer.CommonName))
	}
	if len(cert.Issuer.Organization) > 0 {
		isUser = append(isUser, fmt.Sprintf("O=%s", strings.Join(cert.Issuer.Organization, ",")))
	}
	ss += fmt.Sprintf("\t\tIssuer: %s", strings.Join(isUser, ","))
	//Validity
	ss += fmt.Sprintf("\n\tValidity:\n\t\tNot Before: %s\n\t\tNot After : %s\n", cert.NotBefore.Format("2006-01-02 15:04:05"), cert.NotAfter.Format("2006-01-02 15:04:05"))
	// Subject
	ss += fmt.Sprintf("\tSubject: %s\n", cert.Subject.String())
	return ss
}

func parseIconFile(body string) string {
	// 解析HTML
	reader := strings.NewReader(body)
	doc, err := goquery.NewDocumentFromReader(reader)
	if err != nil {
		return ""
	}
	iconURL := ""
	doc.Find("link[rel*='icon']").Each(func(i int, s *goquery.Selection) {
		href, exists := s.Attr("href")
		if exists {
			iconURL = href
		}
	})
	// 如果找不到图标标签，使用默认路径
	if iconURL == "" {
		iconURL = "/favicon.ico"
	}
	return strings.Replace(iconURL, "./", "/", 1)

}
func isAbsoluteURL(url string) bool {
	return !(strings.HasPrefix(url, "http://") || strings.HasPrefix(url, "https://"))
}

func NewTransport(proxyURL string) (transport *http.Transport, err error) {
	// proxy
	transport = &http.Transport{
		TLSClientConfig: &tls.Config{
			MinVersion:           tls.VersionTLS10,
			InsecureSkipVerify:   true,
			GetClientCertificate: nil}}
	if proxyURL != "" {
		proxyURl, err := url.Parse(proxyURL)
		if err != nil {
			return nil, err
		}
		if strings.HasPrefix(proxyURL, "http://") || strings.HasPrefix(proxyURL, "https://") {
			transport.Proxy = http.ProxyURL(proxyURl)
		} else {
			socksURL, proxyErr := url.Parse(proxyURL)
			if proxyErr != nil {
				return nil, err
			}
			dialer, err := proxy.FromURL(socksURL, proxy.Direct)
			if err != nil {
				return nil, err
			}
			dc := dialer.(interface {
				DialContext(ctx context.Context, network, addr string) (net.Conn, error)
			})
			transport.DialContext = dc.DialContext
		}
	}
	return transport, nil
}
func NewClient(proxy string, timeout time.Duration) (*http.Client, error) {
	transport, err := NewTransport(proxy)
	if err != nil {
		return nil, err
	}
	return &http.Client{
		Transport: transport,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 10 {
				return http.ErrUseLastResponse
			}
			//if via[0].URL.Hostname() != req.URL.Hostname() {
			//	return http.ErrUseLastResponse
			//}
			// 在这里可以自定义重定向策略
			// 例如，你可以修改请求头，记录重定向次数等
			// 默认行为是跟随重定向
			return nil
		},
		Timeout: timeout,
	}, nil
}

func ExtractContentTypeCharset(contentType string) (charset string) {
	//	 从content-type 中提取Charset
	re := regexp.MustCompile(`(?i)charset=([\w-]+)`)
	matches := re.FindStringSubmatch(contentType)
	if len(matches) >= 2 {
		charset = matches[1]
	}
	return
}

func RequestOnce(client *http.Client, uri string) (banner *Banner, redirectURL string, err error) {
	// 开始请求数据
	var resp *http.Response
	req, err := http.NewRequest("GET", uri, nil)
	if err != nil {
		return banner, redirectURL, err
	}
	req.Header.Set("Accept", "*/*")
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36 Edg/114.0.1823.58")
	resp, err = client.Do(req)
	if err != nil && err.Error() != http.ErrUseLastResponse.Error() {
		return banner, redirectURL, err
	}
	// get raw headers
	headers, _ := httputil.DumpResponse(resp, false)
	// get body
	body, _ := io.ReadAll(resp.Body)
	label := ExtractContentTypeCharset(resp.Header.Get("Content-Type"))
	if label == "" {
		label = ExtractCharset(string(body))
	}
	bodyString := ResponseDecoding(body, label)
	banner = &Banner{
		Uri:        resp.Request.URL.String(),
		Body:       bodyString,
		BodyHash:   mmh3(body),
		Header:     string(headers),
		StatusCode: resp.StatusCode,
		Response:   string(headers) + bodyString,
		Headers:    map[string]string{},
		Charset:    label,
	}
	banner.Title = ResponseDecoding(getTitle(body), label)
	for k, v := range resp.Header {
		banner.Headers[strings.ToLower(k)] = strings.Join(v, ",")
	}
	// 获取服务器证书信息
	if resp.TLS != nil {
		banner.Certificate = parseCertificateInfo(resp.TLS)
		banner.Cert = resp.TLS
	}
	//解析JavaScript跳转
	jsRedirectUri := parseJavaScript(uri, string(body))
	if jsRedirectUri != "" {
		if jsRedirectUri[0] == '/' {
			u, _ := url.Parse(banner.Uri)
			uri = u.Scheme + "://" + u.Host + jsRedirectUri
		} else {
			uri = urlJoin(uri, jsRedirectUri)
		}

		gologger.Debug().Msgf("redirect URL:%s", uri)
		return banner, uri, nil
	} else {
		return banner, "", nil
	}

}

func readICON(client *http.Client, banner *Banner) (iconHash int32, err error) {
	var body []byte
	var req *http.Request
	var resp *http.Response
	iconURL := parseIconFile(banner.Body)
	if iconURL == "" {
		iconURL = "/favicon.ico"
	}
	if isAbsoluteURL(iconURL) {
		iconURL = joinURL(banner.Uri, iconURL)
	}
	if strings.HasPrefix(iconURL, "data:") {
		base64Seps := strings.Split(iconURL, ",")
		if len(base64Seps) == 2 {
			body, err = base64.StdEncoding.DecodeString(base64Seps[1])
			if err != nil {
				return iconHash, err
			}
		} else {
			return iconHash, errors.New("ICON 无法解析")
		}

	} else {
		req, err = http.NewRequest("GET", iconURL, nil)
		if err != nil {
			// 图片异常不影响
			return iconHash, err
		}
		req.Header.Set("Referer", banner.Uri)
		resp, err = client.Do(req)
		if err != nil {
			return iconHash, err
		}
		if resp.StatusCode != 200 {
			return iconHash, err
		}
		defer func(Body io.ReadCloser) {
			_ = Body.Close()
		}(resp.Body)
		if strings.Contains(resp.Header.Get("Content-Type"), "image") {
			return iconHash, errors.New("icon Not Found")
		}
		body, err = io.ReadAll(resp.Body)
		if err != nil {
			return iconHash, err
		}
		banner.IconURI = iconURL
	}
	iconHash = mmh3(body)
	banner.IconBytes = body
	banner.IconHash = iconHash
	return iconHash, nil
}

func Request(uri string, timeout time.Duration, proxyURL string, disableIcon bool, debugResp bool) ([]*Banner, error) {
	var err error
	client, err := NewClient(proxyURL, timeout)
	if err != nil {
		return nil, err
	}
	defer client.CloseIdleConnections()
	var banners []*Banner
	var banner *Banner
	var nextURI = uri

	for ret := 0; ret < 3; ret++ {
		banner, nextURI, err = RequestOnce(client, nextURI)
		if err != nil {
			break
		}
		if debugResp {
			if banner.Certificate != "" {
				fmt.Println("Dump Cert For " + banner.Uri + "\r\n" + banner.Certificate)
			}
			fmt.Println("Dump Response For " + banner.Uri + "\r\n" + banner.Response)
		}
		banners = append(banners, banner)
		if nextURI == "" {
			break
		}
	}
	if len(banners) == 0 {
		return nil, err
	}
	// 解析icon
	if len(banners) > 0 && !disableIcon {
		_, err = readICON(client, banners[len(banners)-1])
		if err != nil {
			gologger.Debug().Msg(err.Error())
		}
	}
	if len(banners) == 0 {
		return banners, errors.New("banner empty")
	}
	return banners, nil
}
