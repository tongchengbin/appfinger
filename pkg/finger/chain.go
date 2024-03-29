package finger

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
)

var (
	MaxBodyRead  = int64(1 << 22) // 4MB using shift operator
	maxBodyLimit = int64(1 << 22)
)

// use buffer pool for storing response body
// and reuse it for each request
var bufPool = sync.Pool{
	New: func() any {
		// The Pool's New function should generally only return pointer
		// types, since a pointer can be put into the return interface
		// value without an allocation:
		return new(bytes.Buffer)
	},
}

// getBuffer returns a buffer from the pool
func getBuffer() *bytes.Buffer {
	return bufPool.Get().(*bytes.Buffer)
}

// putBuffer returns a buffer to the pool
func putBuffer(buf *bytes.Buffer) {
	buf.Reset()
	bufPool.Put(buf)
}

// Performance Notes:
// do not use http.Response once we create ResponseChain from it
// as this reuses buffers and saves allocations and also drains response
// body automatically.
// In required cases it can be used but should never be used for anything
// related to response body.
// Bytes.Buffer returned by getters should not be used and are only meant for convinience
// purposes like .String() or .Bytes() calls.
// Remember to call Close() on ResponseChain once you are done with it.

// ResponseChain is a response chain for a http request
// on every call to previous it returns the previous response
// if it was redirected.
type ResponseChain struct {
	headers      *bytes.Buffer
	body         *bytes.Buffer
	fullResponse *bytes.Buffer
	resp         *http.Response
	reloaded     bool // if response was reloaded to its previous redirect
}

type LimitResponseBody struct {
	io.Reader
	io.Closer
}

// NewLimitResponseBody wraps response body with a limit reader.
// thus only allowing MaxBodyRead bytes to be read. i.e 4MB
func NewLimitResponseBodyWithSize(body io.ReadCloser, size int64) io.ReadCloser {
	if body == nil {
		return nil
	}
	if size == -1 {
		// stick to default 4MB
		size = MaxBodyRead
	}
	return &LimitResponseBody{
		Reader: io.LimitReader(body, size),
		Closer: body,
	}
}

// NewResponseChain creates a new response chain for a http request
// with a maximum body size. (if -1 stick to default 4MB)
func NewResponseChain(resp *http.Response, maxBody int64) *ResponseChain {
	if _, ok := resp.Body.(LimitResponseBody); !ok {
		resp.Body = NewLimitResponseBodyWithSize(resp.Body, maxBody)
	}
	return &ResponseChain{
		headers:      getBuffer(),
		body:         getBuffer(),
		fullResponse: getBuffer(),
		resp:         resp,
	}
}

// Response returns the current response in the chain
func (r *ResponseChain) Headers() *bytes.Buffer {
	return r.headers
}

// Body returns the current response body in the chain
func (r *ResponseChain) Body() *bytes.Buffer {
	return r.body
}

// FullResponse returns the current response in the chain
func (r *ResponseChain) FullResponse() *bytes.Buffer {
	return r.fullResponse
}

// previous updates response pointer to previous response
// if it was redirected and returns true else false
func (r *ResponseChain) Previous() bool {
	if r.resp != nil && r.resp.Request != nil && r.resp.Request.Response != nil {
		r.resp = r.resp.Request.Response
		r.reloaded = true
		return true
	}
	return false
}

// errNoBody is a sentinel error value used by failureToReadBody so we
// can detect that the lack of body was intentional.
var errNoBody = errors.New("sentinel error value")

// failureToReadBody is an io.ReadCloser that just returns errNoBody on
// Read. It's swapped in when we don't actually want to consume
// the body, but need a non-nil one, and want to distinguish the
// error from reading the dummy body.
type failureToReadBody struct{}

func (failureToReadBody) Read([]byte) (int, error) { return 0, errNoBody }
func (failureToReadBody) Close() error             { return nil }

// emptyBody is an instance of empty reader.
var emptyBody = io.NopCloser(strings.NewReader(""))

// drainBody reads all of b to memory and then returns two equivalent
// ReadClosers yielding the same bytes.
//
// It returns an error if the initial slurp of all bytes fails. It does not attempt
// to make the returned ReadClosers have identical error-matching behavior.
func drainBody(b io.ReadCloser) (r1, r2 io.ReadCloser, err error) {
	if b == nil || b == http.NoBody {
		// No copying needed. Preserve the magic sentinel meaning of NoBody.
		return http.NoBody, http.NoBody, nil
	}
	var buf bytes.Buffer
	if _, err = buf.ReadFrom(b); err != nil {
		return nil, b, err
	}
	if err = b.Close(); err != nil {
		return nil, b, err
	}
	return io.NopCloser(&buf), io.NopCloser(bytes.NewReader(buf.Bytes())), nil
}

// DumpResponseIntoBuffer dumps a http response without allocating a new buffer
// for the response body.
func DumpResponseIntoBuffer(resp *http.Response, body bool, buff *bytes.Buffer) (err error) {
	if resp == nil {
		return fmt.Errorf("response is nil")
	}
	save := resp.Body
	savecl := resp.ContentLength

	if !body {
		// For content length of zero. Make sure the body is an empty
		// reader, instead of returning error through failureToReadBody{}.
		if resp.ContentLength == 0 {
			resp.Body = emptyBody
		} else {
			resp.Body = failureToReadBody{}
		}
	} else if resp.Body == nil {
		resp.Body = emptyBody
	} else {
		save, resp.Body, err = drainBody(resp.Body)
		if err != nil {
			return err
		}
	}
	err = resp.Write(buff)
	if err == errNoBody {
		err = nil
	}
	resp.Body = save
	resp.ContentLength = savecl
	return
}

// DrainResponseBody drains the response body and closes it.
func DrainResponseBody(resp *http.Response) {
	defer resp.Body.Close()
	// don't reuse connection and just close if body length is more than 2 * MaxBodyRead
	// to avoid DOS
	_, _ = io.CopyN(io.Discard, resp.Body, 2*MaxBodyRead)
}

// Fill buffers
func (r *ResponseChain) Fill() error {
	r.reset()
	if r.resp == nil {
		return fmt.Errorf("response is nil")
	}

	// load headers
	err := DumpResponseIntoBuffer(r.resp, false, r.headers)
	if err != nil {
		return fmt.Errorf("error dumping response headers: %s", err)
	}

	if r.resp.StatusCode != http.StatusSwitchingProtocols && !r.reloaded {
		// Note about reloaded:
		// this is a known behaviour existing from earlier version
		// when redirect is followed and operators are executed on all redirect chain
		// body of those requests is not available since its already been redirected
		// This is not a issue since redirect happens with empty body according to RFC
		// but this may be required sometimes
		// Solution: Manual redirect using dynamic matchers or hijack redirected responses
		// at transport level at replace with bytes buffer and then use it

		// load body
		err = readNNormalizeRespBody(r, r.body)
		if err != nil {
			return fmt.Errorf("error reading response body: %s", err)
		}

		// response body should not be used anymore
		// drain and close
		DrainResponseBody(r.resp)
	}

	// join headers and body
	r.fullResponse.Write(r.headers.Bytes())
	r.fullResponse.Write(r.body.Bytes())
	return nil
}

// Close the response chain and releases the buffers.
func (r *ResponseChain) Close() {
	putBuffer(r.headers)
	putBuffer(r.body)
	putBuffer(r.fullResponse)
	r.headers = nil
	r.body = nil
	r.fullResponse = nil
}

// Has returns true if the response chain has a response
func (r *ResponseChain) Has() bool {
	return r.resp != nil
}

// Request is request of current response
func (r *ResponseChain) Request() *http.Request {
	if r.resp == nil {
		return nil
	}
	return r.resp.Request
}

// Response is response of current response
func (r *ResponseChain) Response() *http.Response {
	return r.resp
}

// reset without releasing the buffers
// useful for redirect chain
func (r *ResponseChain) reset() {
	r.headers.Reset()
	r.body.Reset()
	r.fullResponse.Reset()
}
