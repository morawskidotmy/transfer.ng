package server

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	. "gopkg.in/check.v1"
)

// Hook up gocheck into the "go test" runner.
func Test(t *testing.T) { TestingT(t) }

var (
	_ = Suite(&suiteRedirectWithForceHTTPS{})
	_ = Suite(&suiteRedirectWithoutForceHTTPS{})
)

type suiteRedirectWithForceHTTPS struct {
	handler http.HandlerFunc
}

func (s *suiteRedirectWithForceHTTPS) SetUpTest(c *C) {
	srvr, err := New(ForceHTTPS())
	c.Assert(err, IsNil)

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = fmt.Fprintln(w, "Hello, client")
	})

	s.handler = srvr.RedirectHandler(handler)
}

func (s *suiteRedirectWithForceHTTPS) TestHTTPs(c *C) {
	req := httptest.NewRequest("GET", "https://test/test", nil)

	w := httptest.NewRecorder()
	s.handler(w, req)

	resp := w.Result()
	c.Assert(resp.StatusCode, Equals, http.StatusOK)
}

func (s *suiteRedirectWithForceHTTPS) TestOnion(c *C) {
	req := httptest.NewRequest("GET", "http://test.onion/test", nil)

	w := httptest.NewRecorder()
	s.handler(w, req)

	resp := w.Result()
	c.Assert(resp.StatusCode, Equals, http.StatusOK)
}

func (s *suiteRedirectWithForceHTTPS) TestXForwardedFor(c *C) {
	req := httptest.NewRequest("GET", "http://127.0.0.1/test", nil)
	req.Header.Set("X-Forwarded-Proto", "https")

	w := httptest.NewRecorder()
	s.handler(w, req)

	resp := w.Result()
	c.Assert(resp.StatusCode, Equals, http.StatusOK)
}

func (s *suiteRedirectWithForceHTTPS) TestHTTP(c *C) {
	req := httptest.NewRequest("GET", "http://127.0.0.1/test", nil)

	w := httptest.NewRecorder()
	s.handler(w, req)

	resp := w.Result()
	c.Assert(resp.StatusCode, Equals, http.StatusPermanentRedirect)
	c.Assert(resp.Header.Get("Location"), Equals, "https://127.0.0.1/test")
}

type suiteRedirectWithoutForceHTTPS struct {
	handler http.HandlerFunc
}

func (s *suiteRedirectWithoutForceHTTPS) SetUpTest(c *C) {
	srvr, err := New()
	c.Assert(err, IsNil)

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = fmt.Fprintln(w, "Hello, client")
	})

	s.handler = srvr.RedirectHandler(handler)
}

func (s *suiteRedirectWithoutForceHTTPS) TestHTTP(c *C) {
	req := httptest.NewRequest("GET", "http://127.0.0.1/test", nil)

	w := httptest.NewRecorder()
	s.handler(w, req)

	resp := w.Result()
	c.Assert(resp.StatusCode, Equals, http.StatusOK)
}

func (s *suiteRedirectWithoutForceHTTPS) TestHTTPs(c *C) {
	req := httptest.NewRequest("GET", "https://127.0.0.1/test", nil)

	w := httptest.NewRecorder()
	s.handler(w, req)

	resp := w.Result()
	c.Assert(resp.StatusCode, Equals, http.StatusOK)
}

var (
	_ = Suite(&suiteSanitize{})
	_ = Suite(&suiteValidation{})
	_ = Suite(&suiteCanContainsXSS{})
)

type suiteSanitize struct{}

func (s *suiteSanitize) TestSanitizeBasic(c *C) {
	tests := []struct {
		input    string
		expected string
	}{
		{"normal.txt", "normal.txt"},
		{"file name.txt", "file name.txt"},
		{"../../../etc/passwd", "passwd"},
		{"..\\..\\windows\\system32", "system32"},
		{".hidden", "hidden"},
		{"...test", "test"},
		{"", "_"},
		{"file:name.txt", "filename.txt"},
	}

	for _, test := range tests {
		result := sanitize(test.input)
		c.Assert(result, Equals, test.expected, Commentf("input=%q", test.input))
	}
}

func (s *suiteSanitize) TestSanitizeLongFilename(c *C) {
	longName := make([]byte, 300)
	for i := range longName {
		longName[i] = 'a'
	}
	result := sanitize(string(longName))
	c.Assert(len(result) <= 255, Equals, true)
}

func (s *suiteSanitize) TestSanitizePathTraversal(c *C) {
	tests := []string{
		"../file.txt",
		"..\\file.txt",
		"foo/../bar.txt",
		"foo\\..\\bar.txt",
	}

	for _, input := range tests {
		result := sanitize(input)
		c.Assert(result, Not(Equals), "", Commentf("input=%q should produce non-empty result", input))
		c.Assert(result, Not(Matches), ".*\\.\\.", Commentf("input=%q result=%q should not contain '..'", input, result))
	}
}

type suiteValidation struct{}

func (s *suiteValidation) TestValidateTokenAndFilename(c *C) {
	tests := []struct {
		token    string
		filename string
		wantErr  bool
	}{
		{"abc123", "file.txt", false},
		{"token", "name", false},
		{string(make([]byte, 200)), "file.txt", false},
		{string(make([]byte, 201)), "file.txt", true},
		{"token", string(make([]byte, 255)), false},
		{"token", string(make([]byte, 256)), true},
		{string(make([]byte, 201)), string(make([]byte, 256)), true},
	}

	for _, test := range tests {
		err := validateTokenAndFilename(test.token, test.filename)
		if test.wantErr {
			c.Assert(err, NotNil, Commentf("token len=%d, filename len=%d", len(test.token), len(test.filename)))
		} else {
			c.Assert(err, IsNil, Commentf("token len=%d, filename len=%d", len(test.token), len(test.filename)))
		}
	}
}

type suiteCanContainsXSS struct{}

func (s *suiteCanContainsXSS) TestCanContainsXSS(c *C) {
	tests := []struct {
		contentType string
		expected    bool
	}{
		{"text/html", true},
		{"text/html; charset=utf-8", true},
		{"application/xhtml+xml", true},
		{"text/xml", true},
		{"application/xml", true},
		{"text/plain", false},
		{"application/json", false},
		{"image/png", false},
		{"application/octet-stream", false},
		{"text/cache-manifest", true},
		{"application/rdf+xml", true},
		{"text/vtt", true},
		{"application/xsl+xml", true},
		{"multipart/x-mixed-replace", true},
	}

	for _, test := range tests {
		result := canContainsXSS(test.contentType)
		c.Assert(result, Equals, test.expected, Commentf("contentType=%q", test.contentType))
	}
}
