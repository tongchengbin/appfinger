package crawl

import (
	"context"
	"crypto/tls"
	"golang.org/x/net/proxy"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"time"
)

// 默认超时时间
const defaultTimeout = 12 * time.Second

type ClientOption func(*http.Client) error

// WithProxy 配置代理
func WithProxy(proxy string) ClientOption {
	return func(client *http.Client) error {
		transport, err := NewTransport(proxy) // 假设 NewTransport 函数正确实现
		if err != nil {
			return err
		}
		client.Transport = transport
		return nil
	}
}

// WithTimeout 配置超时时间
func WithTimeout(timeout time.Duration) ClientOption {
	return func(client *http.Client) error {
		client.Timeout = timeout
		return nil
	}
}

// NewTransport 创建一个带有 SOCKS5 代理的 http.Transport
func NewTransport(uri string) (*http.Transport, error) {
	// 这里需要判断是否是http 代理
	urlProxy, err := url.Parse(uri)
	if err != nil {
		return nil, err
	}
	// Set the base TLS configuration definition
	tlsConfig := &tls.Config{
		Renegotiation:      tls.RenegotiateOnceAsClient,
		InsecureSkipVerify: true,
		MinVersion:         tls.VersionTLS10,
	}
	transport := &http.Transport{
		TLSClientConfig: tlsConfig,
	}
	// 如果是 SOCKS5 代理，手动创建拨号器
	dialer, err := proxy.FromURL(urlProxy, proxy.Direct)
	if err != nil {
		return nil, err
	}
	if urlProxy.Scheme == "http" || urlProxy.Scheme == "https" {
		transport.Proxy = http.ProxyURL(urlProxy)
		return transport, nil
	}
	dc := dialer.(interface {
		DialContext(ctx context.Context, network, addr string) (net.Conn, error)
	})
	transport.DialContext = dc.DialContext
	transport.DialTLSContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
		// upgrade proxy connection to tls
		conn, err := dc.DialContext(ctx, network, addr)
		if err != nil {
			return nil, err
		}
		return tls.Client(conn, tlsConfig), nil
	}
	return transport, nil
}

// WithRedirectPolicy 自定义重定向策略
func WithRedirectPolicy(policy func(req *http.Request, via []*http.Request) error) ClientOption {
	return func(client *http.Client) error {
		client.CheckRedirect = policy
		return nil
	}
}

func NewClient(options ...ClientOption) (*http.Client, error) {
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{
			MinVersion:           tls.VersionTLS10,
			InsecureSkipVerify:   true,
			GetClientCertificate: nil}}

	// 创建一个共享的 CookieJar
	jar, err := cookiejar.New(nil)
	if err != nil {
		return nil, err
	}

	// 创建默认的 http.Client
	client := &http.Client{
		Transport: transport,
		Jar:       jar,
		Timeout:   defaultTimeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	// 应用所有可选配置
	for _, opt := range options {
		if err := opt(client); err != nil {
			return nil, err
		}
	}
	return client, nil
}
