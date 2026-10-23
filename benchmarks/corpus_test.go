package benchmarks

import (
	"encoding/json"
	"os"
	"sort"
	"testing"
)

// The workflow compares these complete outputs before measuring performance,
// including all incidental matches and extracted fields, not only known products.
func TestCorpusResults(t *testing.T) {
	path := os.Getenv("APPFINGER_RESULTS_PATH")
	if path == "" {
		t.Skip("CI corpus comparison: set APPFINGER_RESULTS_PATH")
	}
	set := loadRealRules(t)
	type match struct {
		Name   string
		Values map[string]string
	}
	output := map[string][]match{}
	for _, fixture := range []struct{ name, body, server string }{
		{"neutral", body(32768, false), ""},
		{"wordpress-nginx", `<meta name="generator" content="WordPress 6.4"><script src="/wp-content/core.js"></script>`, "nginx/1.24.0"},
		{"grafana", `<html><title>Grafana</title><body>Grafana</body></html>`, ""},
	} {
		parts := map[string]string{"body": fixture.body, "response": fixture.body, "header": "Server: " + fixture.server, "headers.server": fixture.server, "title": "Grafana", "status_code": "200", "port": "80"}
		if fixture.name != "grafana" {
			parts["title"] = "Example"
		}
		results := set.Match("http", func(part string, _ bool) string { return parts[part] })
		matches := []match{}
		for _, r := range results {
			matches = append(matches, match{r.Rule.Name, r.Extracted})
		}
		sort.Slice(matches, func(i, j int) bool {
			a, _ := json.Marshal(matches[i])
			c, _ := json.Marshal(matches[j])
			return string(a) < string(c)
		})
		output[fixture.name] = matches
	}
	data, err := json.MarshalIndent(output, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0644); err != nil {
		t.Fatal(err)
	}
}
