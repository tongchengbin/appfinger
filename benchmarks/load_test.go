package benchmarks

import (
	"compress/gzip"
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sort"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/hexbay/appfinger/pkg/fetch"
	"github.com/hexbay/appfinger/pkg/matchers"
	"github.com/hexbay/appfinger/pkg/rule"
	"github.com/hexbay/appfinger/pkg/scanner"
)

// Fixed worker counts are independent of GOMAXPROCS. Every timed request validates
// its result. Latency includes execution, not waiting in a target queue.
func BenchmarkScanLoad(b *testing.B) {
	for _, mode := range []string{"plain", "delay20ms", "gzip", "redirect3", "plugin", "javascript", "real-rules"} {
		for _, workers := range []int{1, 8, 32} {
			b.Run(fmt.Sprintf("%s/workers%d", mode, workers), func(b *testing.B) {
				set := rules()
				wantComponents, wantRequests := 2, int64(1)
				if mode == "plugin" {
					set.AddRules([]*rule.Rule{{Name: "Probe", Plugins: []*rule.Plugin{{Path: "/probe"}}, Matchers: []*matchers.Matcher{{Type: matchers.MatcherTypeHolder{MatcherType: matchers.WordsMatcher}, Part: "body", Words: []string{"AppFingerDemo"}}}}})
					wantRequests = 2
				}
				if mode == "redirect3" {
					wantRequests = 4
				}
				if mode == "javascript" {
					wantRequests = 2
				}
				payload := body(32768, true)
				if mode == "real-rules" {
					set = loadRealRules(b)
					payload = body(32768, false) + `<meta name="generator" content="WordPress 6.4"><script src="/wp-content/core.js"></script>`
				}
				var requests atomic.Int64
				server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					requests.Add(1)
					if mode == "delay20ms" {
						time.Sleep(20 * time.Millisecond)
					}
					if mode == "redirect3" {
						next := map[string]string{"/": "/one", "/one": "/two", "/two": "/landing"}[r.URL.Path]
						if next != "" {
							http.Redirect(w, r, next, http.StatusFound)
							return
						}
					}
					w.Header().Set("Content-Type", "text/html; charset=utf-8")
					if mode == "real-rules" {
						w.Header().Set("Server", "nginx/1.24.0")
					}
					if mode == "javascript" && r.URL.Path == "/" {
						_, _ = w.Write([]byte(`<html><script>window.location.href='/landing';</script></html>`))
						return
					}
					if mode == "gzip" {
						w.Header().Set("Content-Encoding", "gzip")
						g := gzip.NewWriter(w)
						_, _ = g.Write([]byte(payload))
						_ = g.Close()
						return
					}
					_, _ = w.Write([]byte(payload))
				}))
				defer server.Close()
				client := server.Client()
				transport := client.Transport.(*http.Transport)
				transport.MaxIdleConnsPerHost = 64
				defer client.CloseIdleConnections()
				opts := fetch.DefaultOption()
				opts.HTTPClient, opts.DisableIcon, opts.DisableJavaScript = client, true, mode != "javascript"
				f, err := fetch.NewFetcher(opts)
				if err != nil {
					b.Fatal(err)
				}
				s, err := scanner.New(scanner.Config{Fetcher: f, RuleProvider: provider{set}})
				if err != nil {
					b.Fatal(err)
				}
				validate := func(result *scanner.Result, err error) error {
					if err != nil {
						return err
					}
					if len(result.Components) != wantComponents {
						return fmt.Errorf("components=%v", result.Components)
					}
					first, second := "Demo", "Version"
					if mode == "real-rules" {
						first, second = "Nginx", "Wordpress"
					}
					if result.Components[0].Name != first || result.Components[1].Name != second {
						return fmt.Errorf("unexpected components: %v", result.Components)
					}
					return nil
				}
				if err := validate(s.Scan(context.Background(), server.URL)); err != nil {
					b.Fatal(err)
				}
				if requests.Load() != wantRequests {
					b.Fatalf("warmup requests=%d, want %d", requests.Load(), wantRequests)
				}
				requests.Store(0)
				latencies := make([]time.Duration, b.N)
				var next atomic.Int64
				var failures atomic.Int64
				var wg sync.WaitGroup
				ready, start := make(chan struct{}, workers), make(chan struct{})
				for w := 0; w < workers; w++ {
					wg.Add(1)
					go func() {
						defer wg.Done()
						ready <- struct{}{}
						<-start
						for {
							i := int(next.Add(1) - 1)
							if i >= b.N {
								return
							}
							began := time.Now()
							err := validate(s.Scan(context.Background(), server.URL))
							latencies[i] = time.Since(began)
							if err != nil {
								failures.Add(1)
							}
						}
					}()
				}
				for w := 0; w < workers; w++ {
					<-ready
				}
				b.ReportAllocs()
				b.ResetTimer()
				close(start)
				wg.Wait()
				b.StopTimer()
				if failures.Load() != 0 || requests.Load() != int64(b.N)*wantRequests {
					b.Fatalf("failures=%d requests=%d expected=%d", failures.Load(), requests.Load(), int64(b.N)*wantRequests)
				}
				sort.Slice(latencies, func(i, j int) bool { return latencies[i] < latencies[j] })
				for _, p := range []int{50, 95, 99} {
					index := (len(latencies)*p+99)/100 - 1
					b.ReportMetric(float64(latencies[index].Nanoseconds()), fmt.Sprintf("p%d-ns", p))
				}
				b.ReportMetric(float64(b.N)/b.Elapsed().Seconds(), "targets/s")
				b.ReportMetric(float64(requests.Load())/float64(b.N), "requests/target")
				b.ReportMetric(float64(b.N), "latency-samples")
			})
		}
	}
}
