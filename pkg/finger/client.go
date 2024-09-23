package finger

import (
	"crypto/tls"
	"net/http"
	"net/http/cookiejar"
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
func NewTransport(proxy string) (*http.Transport, error) {
	// 实现代理的 Transport
	return &http.Transport{}, nil
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
