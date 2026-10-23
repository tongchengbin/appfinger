package benchmarks

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/hexbay/appfinger/pkg/rule"
)

const rulesCommit = "b245e9d7cf02b533b1948b19cc369e7fd734366d"

// Use the public loader for every file but reject malformed fixtures explicitly.
// Never silently benchmark a partially loaded rules directory.
func loadRealRules(b testing.TB) *rule.RuleSet {
	b.Helper()
	dir := os.Getenv("APPFINGER_RULES_DIR")
	if dir == "" {
		b.Skip("set APPFINGER_RULES_DIR to the pinned finger-rules checkout")
	}
	s := rule.NewRuleSet()
	count := 0
	err := filepath.WalkDir(dir, func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() {
			if strings.HasPrefix(entry.Name(), ".") && path != dir {
				return filepath.SkipDir
			}
			return nil
		}
		if filepath.Ext(path) != ".yaml" && filepath.Ext(path) != ".yml" {
			return nil
		}
		rs, err := rule.LoadRule(path)
		if err != nil {
			return err
		}
		for _, r := range rs {
			for _, m := range r.Matchers {
				if err := m.CompileMatchers(); err != nil {
					return err
				}
			}
		}
		s.AddRules(rs)
		count += len(rs)
		return nil
	})
	if err != nil {
		b.Fatal(err)
	}
	if count != 2603 {
		b.Fatalf("rules=%d, want 2603 from %s", count, rulesCommit)
	}
	return s
}

func BenchmarkRealRules(b *testing.B) {
	s := loadRealRules(b)
	for _, size := range []int{1024, 32768, 262144} {
		for _, hit := range []bool{false, true} {
			b.Run(strings.Join([]string{formatSize(size), map[bool]string{false: "neutral", true: "wordpress-nginx"}[hit]}, "/"), func(b *testing.B) {
				corpus, server := body(size, false), ""
				if hit {
					corpus += `<meta name="generator" content="WordPress 6.4"><script src="/wp-content/core.js"></script>`
					server = "nginx/1.24.0"
				}
				parts := map[string]string{"body": corpus, "response": corpus, "headers.server": server, "header": "Server: " + server, "title": "Example", "status_code": "200", "port": "80"}
				getter := func(part string, sensitive bool) string {
					if sensitive {
						return parts[part]
					}
					return strings.ToLower(parts[part])
				}
				verify := func(results []*rule.MatchResult) {
					found := map[string]map[string]string{}
					for _, r := range results {
						found[r.Rule.Name] = r.Extracted
					}
					_, wordpress := found["Wordpress"]
					if hit && (!wordpress || found["Nginx"]["version"] != "1.24.0") {
						b.Fatalf("expected Wordpress and Nginx 1.24.0, got %v", found)
					}
					if !hit {
						if _, ok := found["Wordpress"]; ok {
							b.Fatal("unexpected Wordpress")
						}
						if _, ok := found["Nginx"]; ok {
							b.Fatal("unexpected Nginx")
						}
					}
				}
				verify(s.Match("http", getter))
				b.ReportAllocs()
				b.SetBytes(int64(len(corpus)))
				b.ResetTimer()
				for i := 0; i < b.N; i++ {
					s.Match("http", getter)
				}
				b.StopTimer()
				verify(s.Match("http", getter))
			})
		}
	}
}

func formatSize(n int) string {
	switch n {
	case 1024:
		return "1KiB"
	case 32768:
		return "32KiB"
	default:
		return "256KiB"
	}
}

func BenchmarkLoadRealRules(b *testing.B) {
	loadRealRules(b)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		loadRealRules(b)
	}
}
