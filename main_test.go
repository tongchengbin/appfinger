package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/gologger/levels"
	"github.com/stretchr/testify/assert"
	"github.com/tongchengbin/appfinger/internal"
	"github.com/tongchengbin/appfinger/pkg/crawl"
	"github.com/tongchengbin/appfinger/pkg/external/customrules"
	"github.com/tongchengbin/appfinger/pkg/rule"
)

func TestVersion(t *testing.T) {
	assert.NotEmpty(t, Version, "Version should not be empty")
	assert.Contains(t, Banner, Version, "Banner should contain the version")
}

func TestParseOptions(t *testing.T) {
	// Save original args and restore after test
	oldArgs := os.Args
	defer func() { os.Args = oldArgs }()

	// Test default options
	os.Args = []string{"appfinger"}
	options := internal.ParseOptions()
	assert.Equal(t, 10, options.Threads, "Default threads should be 10")
	assert.Equal(t, 10, options.Timeout, "Default timeout should be 10")
	assert.False(t, options.Debug, "Debug should be false by default")
	assert.False(t, options.Stdin, "Stdin should be false by default")

	// Test with custom options
	os.Args = []string{
		"appfinger",
		"-u", "http://example.com",
		"-t", "20",
		"--timeout", "30",
		"--debug",
		"-o", "output.json",
	}
	options = internal.ParseOptions()
	assert.Equal(t, []string{"http://example.com"}, options.URL, "URL should be set correctly")
	assert.Equal(t, 20, options.Threads, "Threads should be set to 20")
	assert.Equal(t, 30, options.Timeout, "Timeout should be set to 30")
	assert.True(t, options.Debug, "Debug should be true")
	assert.Equal(t, "output.json", options.OutputFile, "Output file should be set correctly")
}

func TestNewRunner(t *testing.T) {
	options := &internal.Options{
		Threads:    5,
		Timeout:    5,
		FingerHome: t.TempDir(), // Use a temp directory for testing
	}

	// Create a test rule file in the temp directory
	err := os.MkdirAll(options.FingerHome, 0755)
	assert.NoError(t, err, "Failed to create temp directory")

	// Create a minimal test rule file
	testRuleContent := `rules:
  http:
    - name: Test
      matchers:
        - type: word
          words:
            - "test"
`
	err = os.WriteFile(options.FingerHome+"/test.yaml", []byte(testRuleContent), 0644)
	assert.NoError(t, err, "Failed to write test rule file")

	runner, err := internal.NewRunner(options)
	assert.NoError(t, err, "Failed to create runner")
	assert.NotNil(t, runner, "Runner should not be nil")
}

func TestRunnerEnumerate(t *testing.T) {
	// Create a test server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "TestServer")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("<html><head><title>Test Page</title></head><body>Test content</body></html>"))
	}))
	defer server.Close()

	// Setup temp directory for rules
	tempDir := t.TempDir()
	
	// Create a test rule that will match our test server
	testRuleContent := `rules:
  http:
    - name: TestServer
      matchers:
        - type: word
          part: body
          words:
            - "Test content"
`
	err := os.WriteFile(tempDir+"/test.yaml", []byte(testRuleContent), 0644)
	assert.NoError(t, err, "Failed to write test rule file")

	// Create options with the test server URL
	options := &internal.Options{
		URL:        []string{server.URL},
		Threads:    1,
		Timeout:    5,
		FingerHome: tempDir,
	}

	runner, err := internal.NewRunner(options)
	assert.NoError(t, err, "Failed to create runner")

	// Run the enumeration
	err = runner.Enumerate()
	assert.NoError(t, err, "Enumeration should not fail")
}

func TestCrawlMatch(t *testing.T) {
	// Create a test server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/favicon.ico" {
			w.Header().Set("Content-Type", "image/x-icon")
			w.Write([]byte{0x00, 0x00, 0x01, 0x00}) // Minimal icon data
			return
		}
		
		w.Header().Set("Server", "TestServer")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("<html><head><title>Test Page</title></head><body>Test content</body></html>"))
	}))
	defer server.Close()

	// Create a test finger with rules
	finger := rule.NewFinger()
	finger.AddRules([]*rule.Rule{
		{
			Name:    "TestApp",
			Service: "http",
			Matchers: []*matchers.Matcher{
				{
					Type:  "word",
					Part:  "body",
					Words: []string{"Test content"},
				},
			},
		},
	})

	// Create a crawler with the test finger
	crawler := crawl.NewCrawl(&crawl.Options{
		Timeout: 5 * time.Second,
	}, finger)

	// Test the Match function
	banner, fingerprints, err := crawler.Match(server.URL)
	assert.NoError(t, err, "Match should not fail")
	assert.NotNil(t, banner, "Banner should not be nil")
	assert.Contains(t, banner.Body, "Test content", "Banner body should contain test content")
	assert.Equal(t, "Test Page", banner.Title, "Banner title should be correct")
	assert.NotNil(t, fingerprints, "Fingerprints should not be nil")
	assert.Contains(t, fingerprints, "TestApp", "Should identify TestApp")
}

func TestRuleMatching(t *testing.T) {
	// Create a test banner
	banner := &rule.Banner{
		Uri:        "http://example.com",
		Body:       "<html><body>Test content with WordPress</body></html>",
		Title:      "Test Page",
		StatusCode: 200,
		Headers: map[string]string{
			"server": "Apache/2.4.41",
		},
	}

	// Create rules for testing
	testRules := []*rule.Rule{
		{
			Name:    "WordPress",
			Service: "http",
			Matchers: []*matchers.Matcher{
				{
					Type:  "word",
					Part:  "body",
					Words: []string{"WordPress"},
				},
			},
		},
		{
			Name:    "Apache",
			Service: "http",
			Matchers: []*matchers.Matcher{
				{
					Type:  "word",
					Part:  "headers.server",
					Words: []string{"Apache"},
				},
			},
		},
		{
			Name:    "NotPresent",
			Service: "http",
			Matchers: []*matchers.Matcher{
				{
					Type:  "word",
					Part:  "body",
					Words: []string{"This text is not in the body"},
				},
			},
		},
	}

	// Create finger and add rules
	finger := rule.NewFinger()
	finger.AddRules(testRules)

	// Test matching
	results := finger.Match("http", banner)
	assert.NotNil(t, results, "Results should not be nil")
	assert.Contains(t, results, "WordPress", "Should identify WordPress")
	assert.Contains(t, results, "Apache", "Should identify Apache")
	assert.NotContains(t, results, "NotPresent", "Should not identify NotPresent")
}

func TestCustomRulesUpdate(t *testing.T) {
	// Skip this test if we're not in an environment where we can download rules
	if testing.Short() {
		t.Skip("Skipping test in short mode")
	}

	tempDir := t.TempDir()
	err := customrules.DefaultProvider.Update(context.Background(), tempDir)
	assert.NoError(t, err, "Rule update should not fail")

	// Verify that rules were downloaded
	files, err := os.ReadDir(tempDir)
	assert.NoError(t, err, "Reading directory should not fail")
	assert.Greater(t, len(files), 0, "Should have downloaded at least one rule file")
}

func TestMainFunction(t *testing.T) {
	// Save original args and restore after test
	oldArgs := os.Args
	defer func() { os.Args = oldArgs }()

	// Test version flag
	os.Args = []string{"appfinger", "-v"}
	
	// Capture log output
	oldLogger := gologger.DefaultLogger
	defer func() { gologger.DefaultLogger = oldLogger }()
	
	gologger.DefaultLogger.SetMaxLevel(levels.LevelInfo)
	
	// Run main function - this should just print version and return
	main()
	
	// No assertions needed here, we're just making sure it doesn't crash
}
