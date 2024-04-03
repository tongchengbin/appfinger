package runner

import (
	"bufio"
	"context"
	"github.com/projectdiscovery/gologger"
	"io"
	"os"
	"strings"
	"sync"
)

func (r *Runner) EnumerateMultipleDomainsWithCtx(ctx context.Context, reader io.Reader) error {
	scanner := bufio.NewScanner(reader)
	urlCh := make(chan string, 10)
	var wg sync.WaitGroup
	for i := 0; i < r.options.Threads; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for url := range urlCh {
				banner, extract, err := r.finger.MatchURI(url)
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
