package benchmarks

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
	"sort"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/hexbay/appfinger/pkg/fetch"
	"github.com/hexbay/appfinger/pkg/matchers"
	"github.com/hexbay/appfinger/pkg/rule"
	"github.com/hexbay/appfinger/pkg/scanner"
)

// Synthetic dataset v1. All signatures and payloads are deterministic and offline.
// Keep this directory identical in both checkouts when comparing engine changes.
func rules() *rule.RuleSet {
	s := rule.NewRuleSet()
	for i := 0; i < 256; i++ {
		s.AddRules([]*rule.Rule{{Name: fmt.Sprintf("absent-%03d", i), Service: "http", Matchers: []*matchers.Matcher{{
			Type: matchers.MatcherTypeHolder{MatcherType: matchers.WordsMatcher},
			Part: "body", Words: []string{fmt.Sprintf("absent-signature-%03d", i)},
		}}}})
	}
	s.AddRules([]*rule.Rule{
		{Name: "Demo", Service: "http", Matchers: []*matchers.Matcher{{Type: matchers.MatcherTypeHolder{MatcherType: matchers.WordsMatcher}, Part: "body", Words: []string{"AppFingerDemo"}}}},
		{Name: "Version", Service: "http", Matchers: []*matchers.Matcher{{Type: matchers.MatcherTypeHolder{MatcherType: matchers.RegexMatcher}, Part: "body", Regex: []string{`release-[0-9]+\.[0-9]+`}}}},
	})
	return s
}

func body(size int, hit bool) string {
	s := strings.Repeat("Mixed CASE 页面 ", size/len("Mixed CASE 页面 ")+1)[:size]
	if hit {
		return s + " AppFingerDemo release-1.2"
	}
	return s
}

func check(t testing.TB, got []string, hit bool) {
	t.Helper()
	sort.Strings(got)
	want := []string{}
	if hit {
		want = []string{"Demo", "Version"}
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("components = %v, want %v", got, want)
	}
}

func BenchmarkRuleSetMatch(b *testing.B) {
	for _, size := range []int{1024, 32768, 262144} {
		for _, hit := range []bool{false, true} {
			b.Run(fmt.Sprintf("bytes%d/hit%t", size, hit), func(b *testing.B) {
				s, corpus := rules(), body(size, hit)
				getter := func(part string, sensitive bool) string {
					if part == "body" {
						return corpus
					}
					return ""
				}
				names := []string{}
				for _, result := range s.Match("http", getter) {
					names = append(names, result.Rule.Name)
				}
				check(b, names, hit)
				b.ReportAllocs()
				b.SetBytes(int64(len(corpus)))
				b.ResetTimer()
				for i := 0; i < b.N; i++ {
					s.Match("http", getter)
				}
			})
		}
	}
}

type provider struct{ set *rule.RuleSet }

func (p provider) Snapshot() *rule.RuleSet { return p.set }

func BenchmarkScan(b *testing.B) {
	for _, mode := range []string{"plain", "redirect", "favicon", "tls", "large1MiB"} {
		b.Run(mode, func(b *testing.B) {
			payload := body(32768, true)
			if mode == "large1MiB" {
				payload = body(1024*1024, true)
			}
			var requests atomic.Int64
			handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				requests.Add(1)
				if mode == "redirect" && r.URL.Path == "/" {
					http.Redirect(w, r, "/landing", http.StatusFound)
					return
				}
				if r.URL.Path == "/favicon.ico" {
					w.Header().Set("Content-Type", "image/x-icon")
					_, _ = w.Write([]byte{0, 0, 1, 0})
					return
				}
				w.Header().Set("Content-Type", "text/html; charset=utf-8")
				_, _ = w.Write([]byte(payload))
			})
			var server *httptest.Server
			if mode == "tls" {
				server = httptest.NewTLSServer(handler)
			} else {
				server = httptest.NewServer(handler)
			}
			defer server.Close()
			client := server.Client()
			defer client.CloseIdleConnections()
			opts := fetch.DefaultOption()
			opts.HTTPClient = client
			opts.DisableIcon = mode != "favicon"
			opts.DisableJavaScript = true
			f, err := fetch.NewFetcher(opts)
			if err != nil {
				b.Fatal(err)
			}
			s, err := scanner.New(scanner.Config{Fetcher: f, RuleProvider: provider{rules()}})
			if err != nil {
				b.Fatal(err)
			}
			result, err := s.Scan(context.Background(), server.URL)
			if err != nil {
				b.Fatal(err)
			}
			names := []string{}
			for _, c := range result.Components {
				names = append(names, c.Name)
			}
			check(b, names, true)
			wantRequests := int64(1)
			if mode == "redirect" || mode == "favicon" {
				wantRequests = 2
			}
			if requests.Load() != wantRequests {
				b.Fatalf("warmup requests = %d, want %d", requests.Load(), wantRequests)
			}
			requests.Store(0)
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				if _, err := s.Scan(context.Background(), server.URL); err != nil {
					b.Fatal(err)
				}
			}
			b.StopTimer()
			if requests.Load() != int64(b.N)*wantRequests {
				b.Fatalf("unexpected request count: %d", requests.Load())
			}
			b.ReportMetric(float64(requests.Load())/float64(b.N), "requests/target")
			b.ReportMetric(float64(b.N)/b.Elapsed().Seconds(), "targets/s")
		})
	}
}
