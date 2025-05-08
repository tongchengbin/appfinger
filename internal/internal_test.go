package internal

import (
	"bytes"
	"context"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/tongchengbin/appfinger/pkg/rule"
)

func TestOutputWriter(t *testing.T) {
	// Test creating a new output writer
	writer := NewOutputWriter(true)
	assert.NotNil(t, writer, "Output writer should not be nil")
	assert.True(t, writer.append, "Append should be set to true")

	// Test creating a file
	tempDir := t.TempDir()
	testFile := filepath.Join(tempDir, "test_output.txt")
	
	file, err := writer.createFile(testFile, true)
	assert.NoError(t, err, "Creating file should not return an error")
	assert.NotNil(t, file, "File should not be nil")
	
	// Write some data and close the file
	_, err = file.Write([]byte("test data\n"))
	assert.NoError(t, err, "Writing to file should not return an error")
	err = file.Close()
	assert.NoError(t, err, "Closing file should not return an error")
	
	// Verify the file was created with the correct content
	content, err := os.ReadFile(testFile)
	assert.NoError(t, err, "Reading file should not return an error")
	assert.Equal(t, "test data\n", string(content), "File should contain the written data")
	
	// Test appending to the file
	file, err = writer.createFile(testFile, true)
	assert.NoError(t, err, "Creating file for append should not return an error")
	_, err = file.Write([]byte("more data\n"))
	assert.NoError(t, err, "Writing to file should not return an error")
	err = file.Close()
	assert.NoError(t, err, "Closing file should not return an error")
	
	// Verify the content was appended
	content, err = os.ReadFile(testFile)
	assert.NoError(t, err, "Reading file should not return an error")
	assert.Equal(t, "test data\nmore data\n", string(content), "File should contain the appended data")
}

func TestOutputFields(t *testing.T) {
	// Test output fields JSON marshaling
	output := &OutputFields{
		URL: "http://example.com",
		Extract: map[string]map[string]string{
			"WordPress": {
				"version": "5.8",
			},
			"PHP": {
				"version": "7.4",
			},
		},
	}
	
	// Marshal to JSON
	jsonBytes, err := output.MarshalJSON()
	assert.NoError(t, err, "MarshalJSON should not return an error")
	
	// Verify the JSON content
	jsonStr := string(jsonBytes)
	assert.Contains(t, jsonStr, `"url":"http://example.com"`, "JSON should contain the URL")
	assert.Contains(t, jsonStr, `"WordPress":{"version":"5.8"}`, "JSON should contain WordPress data")
	assert.Contains(t, jsonStr, `"PHP":{"version":"7.4"}`, "JSON should contain PHP data")
}

func TestRunnerCallbackFunction(t *testing.T) {
	// Create a buffer to capture output
	var buf bytes.Buffer
	
	// Create options and runner
	options := &Options{
		Threads:  1,
		Timeout:  5,
		DebugResp: false,
	}
	
	runner := &Runner{
		options: options,
		outputs: []io.Writer{&buf},
	}
	
	// Create test banner and extract data
	banner := &rule.Banner{
		Uri:   "http://example.com",
		Title: "Example Website",
		Body:  "Test content",
	}
	
	extract := map[string]map[string]string{
		"WordPress": {
			"version": "5.8",
		},
	}
	
	// Call the callback function
	runner.callback(runner, "http://example.com", banner, extract)
	
	// Verify the output
	output := buf.String()
	assert.Contains(t, output, `"url":"http://example.com"`, "Output should contain the URL")
	assert.Contains(t, output, `"WordPress":{"version":"5.8"}`, "Output should contain WordPress data")
}

func TestSanitize(t *testing.T) {
	// Test sanitizing valid input
	result, err := sanitize("  http://example.com  ")
	assert.NoError(t, err, "Sanitize should not return an error for valid input")
	assert.Equal(t, "http://example.com", result, "Sanitize should trim whitespace")
	
	// Test sanitizing with quotes
	result, err = sanitize(`"http://example.com"`)
	assert.NoError(t, err, "Sanitize should not return an error for quoted input")
	assert.Equal(t, "http://example.com", result, "Sanitize should remove quotes")
	
	// Test sanitizing empty input
	_, err = sanitize("   ")
	assert.Equal(t, ErrEmptyInput, err, "Sanitize should return ErrEmptyInput for empty input")
	
	_, err = sanitize("")
	assert.Equal(t, ErrEmptyInput, err, "Sanitize should return ErrEmptyInput for empty string")
}

func TestEnumerateMultipleDomainsWithCtx(t *testing.T) {
	// Create a runner with test options
	options := &Options{
		Threads:  2,
		Timeout:  1,
		DebugResp: false,
	}
	
	// Create a buffer to capture output
	var buf bytes.Buffer
	
	// Create a mock crawl function that always succeeds
	mockCrawl := &mockCrawl{
		matchFunc: func(url string) (*rule.Banner, map[string]map[string]string, error) {
			return &rule.Banner{
				Uri:   url,
				Title: "Test Title",
				Body:  "Test Body",
			}, map[string]map[string]string{
				"TestApp": {"version": "1.0"},
			}, nil
		},
	}
	
	runner := &Runner{
		options: options,
		outputs: []io.Writer{&buf},
		crawl:   mockCrawl,
		callback: func(r *Runner, url string, banner *rule.Banner, extract map[string]map[string]string) {
			for _, output := range r.outputs {
				out := &OutputFields{URL: url, Extract: extract}
				s, _ := out.MarshalJSON()
				_, _ = output.Write(append(s, "\n"...))
			}
		},
	}
	
	// Create a reader with test URLs
	reader := strings.NewReader("http://example1.com\nhttp://example2.com\n")
	
	// Test enumerating multiple domains
	err := runner.EnumerateMultipleDomainsWithCtx(context.Background(), reader)
	assert.NoError(t, err, "EnumerateMultipleDomainsWithCtx should not return an error")
	
	// Verify the output
	output := buf.String()
	assert.Contains(t, output, `"url":"http://example1.com"`, "Output should contain example1.com")
	assert.Contains(t, output, `"url":"http://example2.com"`, "Output should contain example2.com")
	assert.Contains(t, output, `"TestApp":{"version":"1.0"}`, "Output should contain TestApp data")
}

func TestStringTerms(t *testing.T) {
	// Test string terms function
	input := "  Test \n String \t With \n Whitespace  "
	result := StringTerms(input)
	assert.Equal(t, "Test String With Whitespace", result, "StringTerms should remove whitespace and newlines")
	
	// Test with empty string
	result = StringTerms("")
	assert.Equal(t, "", result, "StringTerms should handle empty string")
}

func TestFormatExtract(t *testing.T) {
	// Test format extract function
	extract := map[string]map[string]string{
		"WordPress": {
			"version": "5.8",
			"theme":   "twentytwentyone",
		},
		"PHP": {
			"version": "7.4",
		},
	}
	
	result := formatExtract(extract)
	assert.Contains(t, result, "WordPress", "Result should contain WordPress")
	assert.Contains(t, result, "version=5.8", "Result should contain WordPress version")
	assert.Contains(t, result, "theme=twentytwentyone", "Result should contain WordPress theme")
	assert.Contains(t, result, "PHP", "Result should contain PHP")
	assert.Contains(t, result, "version=7.4", "Result should contain PHP version")
}

// Mock crawl implementation for testing
type mockCrawl struct {
	matchFunc func(string) (*rule.Banner, map[string]map[string]string, error)
}

func (m *mockCrawl) Match(uri string) (*rule.Banner, map[string]map[string]string, error) {
	return m.matchFunc(uri)
}
