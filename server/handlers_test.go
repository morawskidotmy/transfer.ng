package server

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

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
	_ = Suite(&suiteContentTypeMayContainXSS{})
)

type suiteSanitize struct{}

func (s *suiteSanitize) TestSanitizePathBasic(c *C) {
	tests := []struct {
		input    string
		expected string
	}{
		{"normal.txt", "normal.txt"},
		{"file name.txt", "file name.txt"},
		{"../../../etc/passwd", "etc/passwd"},
		{"..\\..\\windows\\system32", "windows/system32"},
		{".hidden", "hidden"},
		{"...test", "test"},
		{"", "_"},
		{"file:name.txt", "filename.txt"},
	}

	for _, test := range tests {
		result := sanitizePath(test.input)
		c.Assert(result, Equals, test.expected, Commentf("input=%q", test.input))
	}
}

func (s *suiteSanitize) TestSanitizePathLongFilename(c *C) {
	longName := make([]byte, 300)
	for i := range longName {
		longName[i] = 'a'
	}
	result := sanitizePath(string(longName))
	c.Assert(len(result) <= 255, Equals, true)
}

func (s *suiteSanitize) TestSanitizePathNested(c *C) {
	tests := []struct {
		input    string
		expected string
	}{
		{"dir/sub/file.txt", "dir/sub/file.txt"},
		{"../file.txt", "file.txt"},
		{"..\\file.txt", "file.txt"},
		{"foo/../bar.txt", "foo/bar.txt"},
		{"foo\\..\\bar.txt", "foo/bar.txt"},
		{"a/b/c/d/e/f/g/h/i/j/k/l", "a/b/c/d/e/f/g/h/i/j"},
	}

	for _, test := range tests {
		result := sanitizePath(test.input)
		c.Assert(result, Equals, test.expected, Commentf("input=%q", test.input))
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
		{"token", string(make([]byte, 1024)), false},
		{"token", string(make([]byte, 1025)), true},
		{string(make([]byte, 201)), string(make([]byte, 1025)), true},
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

type suiteContentTypeMayContainXSS struct{}

func (s *suiteContentTypeMayContainXSS) TestContentTypeMayContainXSS(c *C) {
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
		result := contentTypeMayContainXSS(test.contentType)
		c.Assert(result, Equals, test.expected, Commentf("contentType=%q", test.contentType))
	}
}

var (
	_ = Suite(&suiteHandlers{})
)

type suiteHandlers struct{}

func (s *suiteHandlers) TestIsBotUserAgent(c *C) {
	tests := []struct {
		ua       string
		expected bool
	}{
		{"WhatsApp/2.0", true},
		{"Discordbot/1.0", true},
		{"TelegramBot/1.0", true},
		{"Twitterbot/1.0", true},
		{"facebookexternalhit/1.0", true},
		{"LinkedInBot/1.0", true},
		{"Slackbot/1.0", true},
		{"Embedly/1.0", true},
		{"Mozilla/5.0", false},
		{"curl/7.68.0", false},
		{"", false},
	}

	for _, test := range tests {
		result := isBotUserAgent(test.ua)
		c.Assert(result, Equals, test.expected, Commentf("ua=%q", test.ua))
	}
}

func (s *suiteHandlers) TestResolveKey(c *C) {
	tests := []struct {
		key       string
		proxyPath string
		expected  string
	}{
		{"/abc/def.txt", "", "abc/def.txt"},
		{"abc\\def.txt", "", "abc/def.txt"},
		{"abc/def.txt", "", "abc/def.txt"},
	}

	for _, test := range tests {
		result := resolveKey(test.key, test.proxyPath)
		c.Assert(result, Equals, test.expected, Commentf("key=%q proxyPath=%q", test.key, test.proxyPath))
	}
}

func (s *suiteHandlers) TestResolveURL(c *C) {
	req := httptest.NewRequest("GET", "http://example.com/some/path", nil)
	u, _ := url.Parse("token/file.txt")
	result := resolveURL(req, u, "")
	c.Assert(result, Equals, "http://example.com/token/file.txt")
}

func (s *suiteHandlers) TestResolveWebAddress(c *C) {
	req := httptest.NewRequest("GET", "http://example.com/", nil)

	result := resolveWebAddress(req, "", "")
	c.Assert(result, Equals, "http://example.com/")

	result = resolveWebAddress(req, "/prefix", "")
	c.Assert(result, Equals, "http://example.com/prefix")
}

func (s *suiteHandlers) TestGetURL(c *C) {
	req := httptest.NewRequest("GET", "http://example.com:8080/path", nil)
	u := getURL(req, "")
	c.Assert(u.Scheme, Equals, "http")
	c.Assert(u.Host, Equals, "example.com:8080")

	req2 := httptest.NewRequest("GET", "https://example.com/path", nil)
	u2 := getURL(req2, "")
	c.Assert(u2.Scheme, Equals, "https")
	c.Assert(u2.Host, Equals, "example.com")

	req3 := httptest.NewRequest("GET", "http://example.com/path", nil)
	u3 := getURL(req3, "9090")
	c.Assert(u3.Host, Equals, "example.com:9090")
}

func (s *suiteHandlers) TestCloneURL(c *C) {
	orig, _ := url.Parse("http://user:pass@example.com/path")
	cloned := cloneURL(orig)

	c.Assert(cloned.String(), Equals, orig.String())
	c.Assert(cloned, Not(Equals), orig)
	c.Assert(cloned.User, Not(Equals), orig.User)
}

func (s *suiteHandlers) TestGetDisposition(c *C) {
	srvr, err := New()
	c.Assert(err, IsNil)

	c.Assert(srvr.getDisposition("inline"), Equals, "inline")
	c.Assert(srvr.getDisposition("attachment"), Equals, "attachment")
	c.Assert(srvr.getDisposition(""), Equals, "attachment")
}

func (s *suiteHandlers) TestRemainingLimitHeaderValues(c *C) {
	m := metadata{MaxDownloads: -1}
	downloads, days := m.remainingLimitHeaderValues()
	c.Assert(downloads, Equals, "n/a")
	c.Assert(days, Equals, "n/a")

	m2 := metadata{MaxDownloads: 10, Downloads: 3, MaxDate: time.Now().Add(48 * time.Hour)}
	downloads2, days2 := m2.remainingLimitHeaderValues()
	c.Assert(downloads2, Equals, "7")
	c.Assert(days2, Equals, "2")
}

func (s *suiteHandlers) TestGetPreviewTemplate(c *C) {
	srvr, err := New()
	c.Assert(err, IsNil)

	c.Assert(srvr.getPreviewTemplate("image/png", false), Equals, "download.image.html")
	c.Assert(srvr.getPreviewTemplate("video/mp4", false), Equals, "download.video.html")
	c.Assert(srvr.getPreviewTemplate("audio/mp3", false), Equals, "download.audio.html")
	c.Assert(srvr.getPreviewTemplate("text/plain", false), Equals, "download.markdown.html")
	c.Assert(srvr.getPreviewTemplate("application/octet-stream", false), Equals, "download.html")
	c.Assert(srvr.getPreviewTemplate("image/png", true), Equals, "download.html")
}

func (s *suiteHandlers) TestStripPrefix(c *C) {
	c.Assert(stripPrefix("abc/def"), Equals, "abc/def")
}

func (s *suiteHandlers) TestHealthHandler(c *C) {
	req := httptest.NewRequest("GET", "/health.html", nil)
	w := httptest.NewRecorder()
	healthHandler(w, req)
	c.Assert(w.Code, Equals, http.StatusOK)
	c.Assert(w.Body.String(), Equals, "Approaching Neutral Zone, all systems normal and functioning.")
}

func (s *suiteHandlers) TestNotFoundHandler(c *C) {
	srvr, err := New()
	c.Assert(err, IsNil)

	req := httptest.NewRequest("GET", "/nonexistent", nil)
	w := httptest.NewRecorder()
	srvr.notFoundHandler(w, req)
	c.Assert(w.Code, Equals, http.StatusNotFound)
}

func (s *suiteHandlers) TestCommonHeader(c *C) {
	w := httptest.NewRecorder()
	commonHeader(w, "test.zip")
	c.Assert(w.Header().Get("Content-Disposition"), Equals, `attachment; filename="test.zip"`)
	c.Assert(w.Header().Get("Connection"), Equals, "close")
	c.Assert(w.Header().Get("Cache-Control"), Equals, "no-store")
}

func (s *suiteHandlers) TestSetCommonHeaders(c *C) {
	srvr, err := New()
	c.Assert(err, IsNil)

	w := httptest.NewRecorder()
	srvr.setCommonHeaders(w, "file.txt", "attachment", "5", "10")
	c.Assert(w.Header().Get("Content-Disposition"), Equals, "attachment; filename=file.txt")
	c.Assert(w.Header().Get("Connection"), Equals, "keep-alive")
	c.Assert(w.Header().Get("Cache-Control"), Equals, "no-store")
	c.Assert(w.Header().Get("X-Remaining-Downloads"), Equals, "5")
	c.Assert(w.Header().Get("X-Remaining-Days"), Equals, "10")
}

func (s *suiteHandlers) TestLoveHandler(c *C) {
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	handler := LoveHandler(inner)

	req := httptest.NewRequest("GET", "/", nil)
	w := httptest.NewRecorder()
	handler(w, req)

	c.Assert(w.Code, Equals, http.StatusOK)
	c.Assert(w.Header().Get("x-made-with"), Equals, "<3 by DutchCoders & morawskidotmy")
	c.Assert(w.Header().Get("x-served-by"), Equals, "Proudly served by DutchCoders & morawskidotmy")
	c.Assert(w.Header().Get("server"), Equals, "Transfer.sh HTTP Server")
}

func (s *suiteHandlers) TestSecurityHeadersHandler(c *C) {
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	handler := securityHeadersHandler(inner)

	req := httptest.NewRequest("GET", "/", nil)
	w := httptest.NewRecorder()
	handler(w, req)

	c.Assert(w.Header().Get("X-Content-Type-Options"), Equals, "nosniff")
	c.Assert(w.Header().Get("X-Frame-Options"), Equals, "DENY")
	c.Assert(w.Header().Get("Referrer-Policy"), Equals, "no-referrer")
	c.Assert(w.Header().Get("X-XSS-Protection"), Equals, "1; mode=block")
}

func (s *suiteHandlers) TestIPFilterHandlerNil(c *C) {
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	handler := ipFilterHandler(inner, nil)

	req := httptest.NewRequest("GET", "/", nil)
	w := httptest.NewRecorder()
	handler(w, req)
	c.Assert(w.Code, Equals, http.StatusOK)
}

func (s *suiteHandlers) TestParseArchiveFiles(c *C) {
	srvr, err := New()
	c.Assert(err, IsNil)

	specs, err := srvr.parseArchiveFiles("token1/file1.txt,token2/file2.txt")
	c.Assert(err, IsNil)
	c.Assert(len(specs), Equals, 2)
	c.Assert(specs[0].token, Equals, "token1")
	c.Assert(specs[0].filename, Equals, "file1.txt")
	c.Assert(specs[1].token, Equals, "token2")
	c.Assert(specs[1].filename, Equals, "file2.txt")
}

func (s *suiteHandlers) TestParseArchiveFilesTooMany(c *C) {
	srvr, err := New(MaxArchiveFiles(2))
	c.Assert(err, IsNil)

	_, err = srvr.parseArchiveFiles("a/1,b/2,c/3")
	c.Assert(err, NotNil)
}

func (s *suiteHandlers) TestRespondError(c *C) {
	srvr, err := New()
	c.Assert(err, IsNil)

	w := httptest.NewRecorder()
	srvr.respondError(w, http.StatusBadRequest, "bad request", "")
	c.Assert(w.Code, Equals, http.StatusBadRequest)
	c.Assert(w.Body.String(), Equals, "bad request\n")
}
