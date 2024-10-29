package internal

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/logrusorgru/aurora"
	"github.com/projectdiscovery/gologger"
	"github.com/tongchengbin/appfinger/pkg/crawl"
	"github.com/tongchengbin/appfinger/pkg/rule"
	"io"
	"os"
	"strings"
	"sync"
	"time"
)

var finger *rule.Finger
var once = &sync.Once{}

func Init() {
	once.Do(func() {

	})
}

type Runner struct {
	options  *Options
	callback func(runner *Runner, url string, banner *rule.Banner, extract map[string]map[string]string)
	outputs  []io.Writer
	crawl    *crawl.Crawl
}

func formatExtract(extract map[string]map[string]string) string {
	var s []string
	for key, value := range extract {
		var s2 []string
		for v, vv := range value {
			s2 = append(s2, aurora.Blue(fmt.Sprintf("%s=%s", v, vv)).String())
		}
		s = append(s, fmt.Sprintf("%s:{%s}", aurora.Cyan(key).String(), strings.Join(s2, ",")))
	}
	return strings.Join(s, ",")
}
func StringTerms(s string) string {
	return strings.Trim(strings.ReplaceAll(strings.ReplaceAll(s, "\n", ""), "\t", ""), " ")
}
func NewRunner(options *Options) (*Runner, error) {
	var err error
	finger, err = rule.ScanRuleDirectory(options.FingerHome)
	if err != nil {
		return nil, err
	}
	runner := &Runner{
		options: options,
		crawl: crawl.NewCrawl(&crawl.Options{
			Timeout: time.Duration(options.Timeout) * time.Second,
			Proxy:   options.Proxy,
		}, finger),
		callback: func(r *Runner, url string, banner *rule.Banner, extract map[string]map[string]string) {
			for _, output := range r.outputs {
				out := &OutputFields{URL: url, Extract: extract}
				s, _ := json.Marshal(out)
				_, _ = output.Write(append(s, "\n"...))
			}
			l := fmt.Sprintf("[%s] %v [%v]", aurora.Green(url).String(), formatExtract(extract), aurora.Yellow(StringTerms(strings.ReplaceAll(banner.Title, "\r\n", ""))).String())
			if banner.Cert != nil && len(banner.Cert.PeerCertificates) > 0 && banner.Cert.PeerCertificates[0].Subject.CommonName != "" {
				org := strings.Join(banner.Cert.PeerCertificates[0].Subject.Organization, "|")
				l += fmt.Sprintf(" [%s]", aurora.Magenta(org))

			}
			gologger.Info().Msgf(l)
		},
	}
	var outputs []io.Writer
	if options.OutputFile != "" {
		outputWriter := NewOutputWriter(true)
		file, err := outputWriter.createFile(options.OutputFile, true)
		if err != nil {
			gologger.Error().Msgf("Could not create file for %s: %s\n", options.OutputFile, err)
			return nil, err
		}
		outputs = append(outputs, file)

	}
	runner.outputs = outputs
	return runner, nil

}

var (
	ErrEmptyInput = errors.New("empty data")
)

func sanitize(data string) (string, error) {
	data = strings.Trim(data, "\n\t\"' ")
	if data == "" {
		return "", ErrEmptyInput
	}
	return data, nil
}

func (r *Runner) EnumerateMultipleDomainsWithCtx(ctx context.Context, reader io.Reader) error {
	scanner := bufio.NewScanner(reader)
	urlCh := make(chan string, 10)
	var wg sync.WaitGroup
	for i := 0; i < r.options.Threads; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for url := range urlCh {
				banner, extract, err := r.crawl.Match(url)
				if err != nil {
					gologger.Debug().Msg(err.Error())
					continue
				}
				r.callback(r, url, banner, extract)
			}
		}()
	}
	for scanner.Scan() {
		uri, err := sanitize(scanner.Text())
		if err != nil {
			continue
		}
		urlCh <- uri
	}
	close(urlCh)
	wg.Wait()
	return nil
}

func (r *Runner) Enumerate() error {
	ctx := context.Background()
	if r.options.OutputFile != "" {
		outputWriter := NewOutputWriter(true)
		file, err := outputWriter.createFile(r.options.OutputFile, true)
		if err != nil {
			gologger.Error().Msgf("Could not create file for %s: %s\n", r.options.OutputFile, err)
			return err
		}
		err = file.Close()
		if err != nil {
			return err
		}
	}

	// If we have multiple domains as input,
	if len(r.options.URL) > 0 {
		reader := strings.NewReader(strings.Join(r.options.URL, "\n"))
		return r.EnumerateMultipleDomainsWithCtx(ctx, reader)
	}
	if r.options.UrlFile != "" {
		f, err := os.Open(r.options.UrlFile)
		if err != nil {
			return err
		}
		err = r.EnumerateMultipleDomainsWithCtx(ctx, f)
		_ = f.Close()
		return err
	}
	if r.options.Stdin {
		return r.EnumerateMultipleDomainsWithCtx(ctx, os.Stdin)
	}
	return nil
}
