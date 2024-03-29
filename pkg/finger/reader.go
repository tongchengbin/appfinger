package finger

import "io"

// NewLimitResponseBody wraps response body with a limit reader.
// thus only allowing MaxBodyRead bytes to be read. i.e 4MB
func NewLimitResponseBody(body io.ReadCloser) io.ReadCloser {
	return NewLimitResponseBodyWithSize(body, MaxBodyRead)
}
