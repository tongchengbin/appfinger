package crawl

import (
	"bytes"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"github.com/PuerkitoBio/goquery"
	"github.com/pkg/errors"
	"github.com/projectdiscovery/gologger"
	"github.com/spaolacci/murmur3"
	"github.com/tongchengbin/appfinger/pkg/rule"
	"golang.org/x/net/html/charset"
	"golang.org/x/text/encoding/charmap"
	"golang.org/x/text/encoding/simplifiedchinese"
	"golang.org/x/text/transform"
	"io"
	"net/http"
	"net/http/httputil"
	"net/url"
	"regexp"
	"strings"
)

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

func readICON(client *http.Client, banner *rule.Banner) (iconHash int32, err error) {
	var body []byte
	var req *http.Request
	var resp *http.Response
	iconURL := parseIconFile(banner.Body)
	if iconURL == "" {
		iconURL = "/favicon.ico"
	}
	var contentType string
	if strings.HasPrefix(iconURL, "data:") {
		iconData := iconURL[5:]
		contentTypeSeps := strings.Split(iconData, ";")
		if len(contentTypeSeps) == 2 {
			contentType = contentTypeSeps[0]
			content := contentTypeSeps[1]
			base64Seps := strings.Split(content, ",")
			if len(base64Seps) == 2 {
				body, err = base64.StdEncoding.DecodeString(base64Seps[1])
				if err != nil {
					return iconHash, err
				}
			} else {
				return iconHash, errors.New("ICON 无法解析")
			}
		}
	} else {
		if isAbsoluteURL(iconURL) {
			iconURL = joinURL(banner.Uri, iconURL)
		}
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
		contentType = resp.Header.Get("Content-Type")
		if !strings.Contains(contentType, "image") {
			return iconHash, errors.New("icon Not Found")
		}
		if resp.ContentLength == 0 {
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
	banner.IconType = contentType
	return iconHash, nil
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
func ExtractContentTypeCharset(contentType string) (charset string) {
	//	 从content-type 中提取Charset
	re := regexp.MustCompile(`(?i)charset=([\w-]+)`)
	matches := re.FindStringSubmatch(contentType)
	if len(matches) >= 2 {
		charset = matches[1]
	}
	return
}
func getTitle(body []byte) []byte {
	re := regexp.MustCompile(`(?i)<title[^>]*>([^<]+)</title>`)
	matches := re.FindSubmatch(body)
	if len(matches) >= 2 {
		return matches[1]
	}
	return nil
}
func RequestOnce(client *http.Client, uri string) (banner *rule.Banner, redirectURL string, err error) {
	// 开始请求数据
	var resp *http.Response
	req, err := http.NewRequest("GET", uri, nil)
	if err != nil {
		return banner, redirectURL, err
	}
	req.Header.Set("accept-language", "zh-CN,zh;q=0.9")
	req.Header.Set("Accept", "*/*")
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36 Edg/114.0.1823.58")
	maxRedirect := 6
	for i := 0; i < maxRedirect; i++ {
		var r2 *http.Response
		r2, err = client.Do(req)
		if err != nil {
			break
		}
		resp = r2
		if resp.StatusCode == http.StatusMovedPermanently || resp.StatusCode == http.StatusFound {
			location := resp.Header.Get("Location")
			if location != "" {
				var newURL *url.URL
				newURL, err = url.Parse(location)
				if err != nil {
					break
				}
				// 如果 location 是相对路径，将其转换为绝对路径
				if !newURL.IsAbs() {
					newURL = resp.Request.URL.ResolveReference(newURL)
				}
				req.URL = newURL
			}
			continue
		} else {
			break
		}
	}
	if err != nil && err.Error() != http.ErrUseLastResponse.Error() && resp == nil {
		return banner, redirectURL, err
	}
	if resp == nil {
		return nil, redirectURL, errors.New("响应为空")
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

	banner = &rule.Banner{
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

func mmh3(data []byte) int32 {
	hash := murmur3.New32WithSeed(0)
	_, err := hash.Write([]byte(base64Py(data)))
	if err != nil {
		return 0
	}
	return int32(hash.Sum32())
}
func base64Py(data []byte) string {
	// python encodes to base64 with lines of 76 bytes terminated by new line "\n"
	stdBase64 := base64.StdEncoding.EncodeToString(data)
	return InsertInto(stdBase64, 76, '\n')
}

func InsertInto(s string, interval int, sep rune) string {
	var buffer bytes.Buffer
	before := interval - 1
	last := len(s) - 1
	for i, char := range s {
		buffer.WriteRune(char)
		if i%interval == before && i != last {
			buffer.WriteRune(sep)
		}
	}
	buffer.WriteRune(sep)
	return buffer.String()
}
