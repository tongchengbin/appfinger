package runner

import (
	"bufio"
	"context"
	"io"
	"os"
	"strings"
	"sync"
)

func (r *Runner) EnumerateMultipleDomainsWithCtx(ctx context.Context, reader io.Reader, writers []io.Writer) error {
	scanner := bufio.NewScanner(reader)
	urlCh := make(chan string)
	var wg sync.WaitGroup
	for i := 0; i < r.options.Threads; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for url := range urlCh {
				banner, extract := r.finger.MatchURI(url)
				if banner == nil {
					continue
				}
				r.callback(url, banner, extract)
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
	outputs := []io.Writer{r.options.Output}
	// If we have multiple domains as input,
	if len(r.options.URL) > 0 {
		reader := strings.NewReader(strings.Join(r.options.URL, "\n"))
		return r.EnumerateMultipleDomainsWithCtx(ctx, reader, outputs)
	}
	if r.options.UrlFile != "" {
		f, err := os.Open(r.options.UrlFile)
		if err != nil {
			return err
		}
		err = r.EnumerateMultipleDomainsWithCtx(ctx, f, outputs)
		_ = f.Close()
		return err
	}
	if r.options.Stdin {
		return r.EnumerateMultipleDomainsWithCtx(ctx, os.Stdin, outputs)
	}
	return nil
}
