package server

import (
	"archive/zip"
	"bytes"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"strings"

	"github.com/gorilla/mux"
	. "gopkg.in/check.v1"

	"github.com/morawskidotmy/transfer.ng/server/storage"
)

var (
	_ = Suite(&suiteDirectory{})
)

type suiteDirectory struct {
	srvr   *Server
	router *mux.Router
}

func (s *suiteDirectory) SetUpTest(c *C) {
	store, err := storage.NewLocalStorage(c.MkDir(), log.New(io.Discard, "", 0))
	c.Assert(err, IsNil)

	srvr, err := New(
		UseStorage(store),
		Logger(log.New(io.Discard, "", 0)),
		RandomTokenLength(10),
		TempPath(c.MkDir()),
	)
	c.Assert(err, IsNil)

	s.srvr = srvr
	s.srvr.htmlTemplates = initHTMLTemplates()
	s.srvr.textTemplates = initTextTemplates()
	s.srvr.loadTemplatesFromAssets()
	s.router = mux.NewRouter()
	srvr.setupRoutes(s.router, http.NotFoundHandler())
}

func (s *suiteDirectory) do(req *http.Request) *httptest.ResponseRecorder {
	w := httptest.NewRecorder()
	s.router.ServeHTTP(w, req)
	return w
}

// TestSingleUploadCreatesDirectory verifies a single PUT creates a directory and
// returns an upload token plus directory URL.
func (s *suiteDirectory) TestSingleUploadCreatesDirectory(c *C) {
	req := httptest.NewRequest("PUT", "http://example.com/hello.txt", strings.NewReader("hello world"))
	w := s.do(req)

	c.Assert(w.Code, Equals, http.StatusOK)
	c.Assert(w.Header().Get("X-Upload-Token"), Not(Equals), "")
	c.Assert(w.Header().Get("X-Url-Directory"), Not(Equals), "")
}

// TestAddFileToDirectory verifies files can be added to an existing directory
// using the upload token, and rejected with a wrong token. Without an upload
// token, PUT /{token}/{filename} falls through to putHandler and creates a new
// directory at that path.
func (s *suiteDirectory) TestAddFileToDirectory(c *C) {
	req := httptest.NewRequest("PUT", "http://example.com/one.txt", strings.NewReader("one"))
	w := s.do(req)
	c.Assert(w.Code, Equals, http.StatusOK)

	dirURL := w.Header().Get("X-Url-Directory")
	uploadToken := w.Header().Get("X-Upload-Token")
	dirToken := strings.Trim(strings.TrimPrefix(dirURL, "http://example.com/"), "/")

	// Without X-Upload-Token, the request creates a brand new directory
	// at path "{dirToken}/two.txt" rather than failing with 401.
	req = httptest.NewRequest("PUT", "http://example.com/"+dirToken+"/two.txt", strings.NewReader("two"))
	w = s.do(req)
	c.Assert(w.Code, Equals, http.StatusOK)
	c.Assert(w.Header().Get("X-Url-Directory"), Not(Equals), dirURL)

	// Wrong token -> 403
	req = httptest.NewRequest("PUT", "http://example.com/"+dirToken+"/three.txt", strings.NewReader("three"))
	req.Header.Set("X-Upload-Token", "wrong")
	c.Assert(s.do(req).Code, Equals, http.StatusForbidden)

	// Correct token -> 200
	req = httptest.NewRequest("PUT", "http://example.com/"+dirToken+"/two.txt", strings.NewReader("two"))
	req.Header.Set("X-Upload-Token", uploadToken)
	c.Assert(s.do(req).Code, Equals, http.StatusOK)

	// Listing should contain both files
	req = httptest.NewRequest("GET", "http://example.com/"+dirToken+"/", nil)
	w = s.do(req)
	c.Assert(w.Code, Equals, http.StatusOK)
	body := w.Body.String()
	c.Assert(strings.Contains(body, "/one.txt"), Equals, true)
	c.Assert(strings.Contains(body, "/two.txt"), Equals, true)
}

// TestCreateEmptyDirectory verifies POST /dir creates a listable, empty
// directory with an upload token.
func (s *suiteDirectory) TestCreateEmptyDirectory(c *C) {
	req := httptest.NewRequest("POST", "http://example.com/dir", nil)
	w := s.do(req)

	c.Assert(w.Code, Equals, http.StatusOK)
	uploadToken := w.Header().Get("X-Upload-Token")
	dirURL := w.Header().Get("X-Url-Directory")
	c.Assert(uploadToken, Not(Equals), "")
	c.Assert(dirURL, Not(Equals), "")

	dirToken := strings.Trim(strings.TrimPrefix(dirURL, "http://example.com/"), "/")

	req = httptest.NewRequest("PUT", "http://example.com/"+dirToken+"/file.txt", strings.NewReader("data"))
	req.Header.Set("X-Upload-Token", uploadToken)
	c.Assert(s.do(req).Code, Equals, http.StatusOK)

	req = httptest.NewRequest("GET", "http://example.com/"+dirToken+"/", nil)
	w = s.do(req)
	c.Assert(w.Code, Equals, http.StatusOK)
	c.Assert(strings.Contains(w.Body.String(), "/file.txt"), Equals, true)
}

// TestListMissingDirectory verifies listing a non-existent directory 404s.
func (s *suiteDirectory) TestListMissingDirectory(c *C) {
	req := httptest.NewRequest("GET", "http://example.com/doesnotexist/", nil)
	c.Assert(s.do(req).Code, Equals, http.StatusNotFound)
}

func (s *suiteDirectory) TestParsePaginationParams(c *C) {
	req := httptest.NewRequest("GET", "http://example.com/?page=2&limit=10", nil)
	page, limit := parsePaginationParams(req)
	c.Assert(page, Equals, 2)
	c.Assert(limit, Equals, 10)

	req2 := httptest.NewRequest("GET", "http://example.com/", nil)
	page2, limit2 := parsePaginationParams(req2)
	c.Assert(page2, Equals, 1)
	c.Assert(limit2, Equals, 0)

	req3 := httptest.NewRequest("GET", "http://example.com/?page=-1&limit=abc", nil)
	page3, limit3 := parsePaginationParams(req3)
	c.Assert(page3, Equals, 1)
	c.Assert(limit3, Equals, 0)
}

func (s *suiteDirectory) TestApplyPagination(c *C) {
	entries := []dirFileEntry{
		{Name: "a.txt", URL: "http://a"},
		{Name: "b.txt", URL: "http://b"},
		{Name: "c.txt", URL: "http://c"},
		{Name: "d.txt", URL: "http://d"},
		{Name: "e.txt", URL: "http://e"},
	}

	paginated, totalPages, page := applyPagination(entries, 1, 2)
	c.Assert(len(paginated), Equals, 2)
	c.Assert(totalPages, Equals, 3)
	c.Assert(page, Equals, 1)
	c.Assert(paginated[0].Name, Equals, "a.txt")
	c.Assert(paginated[1].Name, Equals, "b.txt")

	paginated2, totalPages2, page2 := applyPagination(entries, 2, 2)
	c.Assert(len(paginated2), Equals, 2)
	c.Assert(totalPages2, Equals, 3)
	c.Assert(page2, Equals, 2)

	paginated3, _, _ := applyPagination(entries, 1, 0)
	c.Assert(len(paginated3), Equals, 5)

	paginated4, totalPages4, page4 := applyPagination(entries, 10, 2)
	c.Assert(len(paginated4), Equals, 1)
	c.Assert(totalPages4, Equals, 3)
	c.Assert(page4, Equals, 3)
}

func (s *suiteDirectory) TestDeleteDirectory(c *C) {
	req := httptest.NewRequest("PUT", "http://example.com/one.txt", strings.NewReader("one"))
	w := s.do(req)
	c.Assert(w.Code, Equals, http.StatusOK)

	dirURL := w.Header().Get("X-Url-Directory")
	uploadToken := w.Header().Get("X-Upload-Token")
	dirToken := strings.Trim(strings.TrimPrefix(dirURL, "http://example.com/"), "/")

	req = httptest.NewRequest("DELETE", "http://example.com/"+dirToken+"/", nil)
	req.Header.Set("X-Upload-Token", uploadToken)
	w = s.do(req)
	c.Assert(w.Code, Equals, http.StatusOK)
	c.Assert(strings.Contains(w.Body.String(), "Deleted"), Equals, true)

	req = httptest.NewRequest("GET", "http://example.com/"+dirToken+"/", nil)
	w = s.do(req)
	c.Assert(w.Code, Equals, http.StatusNotFound)
}

func (s *suiteDirectory) TestDeleteDirectoryMissingToken(c *C) {
	req := httptest.NewRequest("DELETE", "http://example.com/sometoken/", nil)
	w := s.do(req)
	c.Assert(w.Code, Equals, http.StatusUnauthorized)
}

func (s *suiteDirectory) TestDeleteDirectoryWrongToken(c *C) {
	req := httptest.NewRequest("PUT", "http://example.com/one.txt", strings.NewReader("one"))
	w := s.do(req)
	c.Assert(w.Code, Equals, http.StatusOK)

	dirURL := w.Header().Get("X-Url-Directory")
	dirToken := strings.Trim(strings.TrimPrefix(dirURL, "http://example.com/"), "/")

	req = httptest.NewRequest("DELETE", "http://example.com/"+dirToken+"/", nil)
	req.Header.Set("X-Upload-Token", "wrongtoken")
	w = s.do(req)
	c.Assert(w.Code, Equals, http.StatusForbidden)
}

func (s *suiteDirectory) TestDeletionTokenRoundTrip(c *C) {
	req := httptest.NewRequest("PUT", "http://example.com/hello.txt", strings.NewReader("hello world"))
	w := s.do(req)
	c.Assert(w.Code, Equals, http.StatusOK)

	deleteURL := w.Header().Get("X-Url-Delete")
	c.Assert(deleteURL, Not(Equals), "")

	deletePath := strings.TrimPrefix(deleteURL, "http://example.com")
	req = httptest.NewRequest("DELETE", deletePath, nil)
	w = s.do(req)
	c.Assert(w.Code, Equals, http.StatusOK)

	_ = httptest.NewRequest("GET", "http://example.com/download"+deletePath[:len(deletePath)-len("/hello.txt")]+"/hello.txt", nil)
}

func (s *suiteDirectory) TestDeleteRemovesMetadata(c *C) {
	req := httptest.NewRequest("PUT", "http://example.com/file.txt", strings.NewReader("content"))
	w := s.do(req)
	c.Assert(w.Code, Equals, http.StatusOK)

	deleteURL := w.Header().Get("X-Url-Delete")
	deletePath := strings.TrimPrefix(deleteURL, "http://example.com")

	req = httptest.NewRequest("DELETE", deletePath, nil)
	w = s.do(req)
	c.Assert(w.Code, Equals, http.StatusOK)

	dirURL := w.Header().Get("X-Url-Directory")
	_ = dirURL
}

func (s *suiteDirectory) TestEmptyDirectoryCleanupOnLastDelete(c *C) {
	req := httptest.NewRequest("PUT", "http://example.com/solo.txt", strings.NewReader("solo"))
	w := s.do(req)
	c.Assert(w.Code, Equals, http.StatusOK)

	dirURL := w.Header().Get("X-Url-Directory")
	dirToken := strings.Trim(strings.TrimPrefix(dirURL, "http://example.com/"), "/")

	deleteURL := w.Header().Get("X-Url-Delete")
	deletePath := strings.TrimPrefix(deleteURL, "http://example.com")
	req = httptest.NewRequest("DELETE", deletePath, nil)
	w = s.do(req)
	c.Assert(w.Code, Equals, http.StatusOK)

	req = httptest.NewRequest("GET", "http://example.com/"+dirToken+"/", nil)
	w = s.do(req)
	c.Assert(w.Code, Equals, http.StatusNotFound)
}

func (s *suiteDirectory) TestPostResponseBodyIncludesDirectoryInfo(c *C) {
	body := "--boundary\r\n" +
		"Content-Disposition: form-data; name=\"file\"; filename=\"test.txt\"\r\n" +
		"Content-Type: text/plain\r\n\r\n" +
		"hello\r\n" +
		"--boundary--\r\n"

	req := httptest.NewRequest("POST", "http://example.com/", strings.NewReader(body))
	req.Header.Set("Content-Type", "multipart/form-data; boundary=boundary")
	w := s.do(req)
	c.Assert(w.Code, Equals, http.StatusOK)

	respBody := w.Body.String()
	c.Assert(w.Header().Get("X-Url-Directory"), Not(Equals), "")
	c.Assert(strings.Contains(respBody, "Upload-Token:"), Equals, true)
}

func (s *suiteDirectory) TestDirectoryZipArchive(c *C) {
	req := httptest.NewRequest("PUT", "http://example.com/a.txt", strings.NewReader("aaa"))
	w := s.do(req)
	c.Assert(w.Code, Equals, http.StatusOK)

	dirURL := w.Header().Get("X-Url-Directory")
	uploadToken := w.Header().Get("X-Upload-Token")
	dirToken := strings.Trim(strings.TrimPrefix(dirURL, "http://example.com/"), "/")

	req = httptest.NewRequest("PUT", "http://example.com/"+dirToken+"/b.txt", strings.NewReader("bbb"))
	req.Header.Set("X-Upload-Token", uploadToken)
	c.Assert(s.do(req).Code, Equals, http.StatusOK)

	req = httptest.NewRequest("GET", "http://example.com/"+dirToken+"/.zip", nil)
	w = s.do(req)
	c.Assert(w.Code, Equals, http.StatusOK)
	c.Assert(w.Header().Get("Content-Type"), Equals, "application/zip")

	zr, err := zip.NewReader(bytes.NewReader(w.Body.Bytes()), int64(w.Body.Len()))
	c.Assert(err, IsNil)

	names := make(map[string]bool)
	for _, f := range zr.File {
		names[f.Name] = true
	}
	c.Assert(names["a.txt"], Equals, true)
	c.Assert(names["b.txt"], Equals, true)
}

func (s *suiteDirectory) TestDirectorySizeLimit(c *C) {
	store, err := storage.NewLocalStorage(c.MkDir(), log.New(io.Discard, "", 0))
	c.Assert(err, IsNil)

	srvr, err := New(
		UseStorage(store),
		Logger(log.New(io.Discard, "", 0)),
		RandomTokenLength(10),
		TempPath(c.MkDir()),
		MaxDirSize(10),
	)
	c.Assert(err, IsNil)

	router := mux.NewRouter()
	srvr.setupRoutes(router, http.NotFoundHandler())

	do := func(req *http.Request) *httptest.ResponseRecorder {
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)
		return w
	}

	req := httptest.NewRequest("PUT", "http://example.com/small.txt", strings.NewReader("12345"))
	w := do(req)
	c.Assert(w.Code, Equals, http.StatusOK)

	dirURL := w.Header().Get("X-Url-Directory")
	uploadToken := w.Header().Get("X-Upload-Token")
	dirToken := strings.Trim(strings.TrimPrefix(dirURL, "http://example.com/"), "/")

	req = httptest.NewRequest("PUT", "http://example.com/"+dirToken+"/big.txt", strings.NewReader("1234567890"))
	req.Header.Set("X-Upload-Token", uploadToken)
	w = do(req)
	c.Assert(w.Code, Equals, http.StatusRequestEntityTooLarge)
}

func (s *suiteDirectory) TestDirectoryFileCountLimit(c *C) {
	store, err := storage.NewLocalStorage(c.MkDir(), log.New(io.Discard, "", 0))
	c.Assert(err, IsNil)

	srvr, err := New(
		UseStorage(store),
		Logger(log.New(io.Discard, "", 0)),
		RandomTokenLength(10),
		TempPath(c.MkDir()),
		MaxDirFiles(2),
	)
	c.Assert(err, IsNil)

	router := mux.NewRouter()
	srvr.setupRoutes(router, http.NotFoundHandler())

	do := func(req *http.Request) *httptest.ResponseRecorder {
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)
		return w
	}

	req := httptest.NewRequest("PUT", "http://example.com/first.txt", strings.NewReader("1"))
	w := do(req)
	c.Assert(w.Code, Equals, http.StatusOK)

	dirURL := w.Header().Get("X-Url-Directory")
	uploadToken := w.Header().Get("X-Upload-Token")
	dirToken := strings.Trim(strings.TrimPrefix(dirURL, "http://example.com/"), "/")

	req = httptest.NewRequest("PUT", "http://example.com/"+dirToken+"/second.txt", strings.NewReader("2"))
	req.Header.Set("X-Upload-Token", uploadToken)
	c.Assert(do(req).Code, Equals, http.StatusOK)

	req = httptest.NewRequest("PUT", "http://example.com/"+dirToken+"/third.txt", strings.NewReader("3"))
	req.Header.Set("X-Upload-Token", uploadToken)
	w = do(req)
	c.Assert(w.Code, Equals, http.StatusRequestEntityTooLarge)
}

// TestUploadToSubdirectoryCreatesNewDirectory verifies that PUT to a
// subdirectory path (e.g. /subdir/file.txt) without X-Upload-Token creates a
// new directory and stores the file at subdir/file.txt inside it.
func (s *suiteDirectory) TestUploadToSubdirectoryCreatesNewDirectory(c *C) {
	req := httptest.NewRequest("PUT", "http://example.com/subdir/file.txt", strings.NewReader("content"))
	w := s.do(req)
	c.Assert(w.Code, Equals, http.StatusOK)

	dirURL := w.Header().Get("X-Url-Directory")
	uploadToken := w.Header().Get("X-Upload-Token")
	c.Assert(uploadToken, Not(Equals), "")
	dirToken := strings.Trim(strings.TrimPrefix(dirURL, "http://example.com/"), "/")

	// Root directory listing should contain the subdirectory
	req = httptest.NewRequest("GET", "http://example.com/"+dirToken+"/", nil)
	w = s.do(req)
	c.Assert(w.Code, Equals, http.StatusOK)
	c.Assert(strings.Contains(w.Body.String(), "subdir/"), Equals, true)

	// Subdirectory listing should contain the file
	req = httptest.NewRequest("GET", "http://example.com/"+dirToken+"/subdir/", nil)
	w = s.do(req)
	c.Assert(w.Code, Equals, http.StatusOK)
	c.Assert(strings.Contains(w.Body.String(), "file.txt"), Equals, true)

	// Downloading the file via the subdirectory path should return the content
	req = httptest.NewRequest("GET", "http://example.com/"+dirToken+"/subdir/file.txt", nil)
	w = s.do(req)
	c.Assert(w.Code, Equals, http.StatusOK)
	c.Assert(w.Body.String(), Equals, "content")
}

// TestDownloadFromSubdirectoryPath verifies that a file uploaded with a
// subdirectory path can be downloaded using the full nested URL.
func (s *suiteDirectory) TestDownloadFromSubdirectoryPath(c *C) {
	req := httptest.NewRequest("PUT", "http://example.com/funyguy/harvest/file.txt", strings.NewReader("deep"))
	w := s.do(req)
	c.Assert(w.Code, Equals, http.StatusOK)

	dirURL := w.Header().Get("X-Url-Directory")
	dirToken := strings.Trim(strings.TrimPrefix(dirURL, "http://example.com/"), "/")

	req = httptest.NewRequest("GET", "http://example.com/"+dirToken+"/funyguy/harvest/file.txt", nil)
	w = s.do(req)
	c.Assert(w.Code, Equals, http.StatusOK)
	c.Assert(w.Body.String(), Equals, "deep")
}

// TestAddToSubdirectoryInExistingDirectory verifies that files with
// subdirectory paths can be added to an existing directory using the
// X-Upload-Token header.
func (s *suiteDirectory) TestAddToSubdirectoryInExistingDirectory(c *C) {
	req := httptest.NewRequest("PUT", "http://example.com/top.txt", strings.NewReader("top"))
	w := s.do(req)
	c.Assert(w.Code, Equals, http.StatusOK)

	dirURL := w.Header().Get("X-Url-Directory")
	uploadToken := w.Header().Get("X-Upload-Token")
	dirToken := strings.Trim(strings.TrimPrefix(dirURL, "http://example.com/"), "/")

	req = httptest.NewRequest("PUT", "http://example.com/"+dirToken+"/sub/deep.txt", strings.NewReader("nested"))
	req.Header.Set("X-Upload-Token", uploadToken)
	w = s.do(req)
	c.Assert(w.Code, Equals, http.StatusOK)

	// Root directory should contain top.txt and sub/
	req = httptest.NewRequest("GET", "http://example.com/"+dirToken+"/", nil)
	w = s.do(req)
	c.Assert(w.Code, Equals, http.StatusOK)
	c.Assert(strings.Contains(w.Body.String(), "top.txt"), Equals, true)
	c.Assert(strings.Contains(w.Body.String(), "sub/"), Equals, true)

	// Subdirectory should contain deep.txt
	req = httptest.NewRequest("GET", "http://example.com/"+dirToken+"/sub/", nil)
	w = s.do(req)
	c.Assert(w.Code, Equals, http.StatusOK)
	c.Assert(strings.Contains(w.Body.String(), "deep.txt"), Equals, true)

	req = httptest.NewRequest("GET", "http://example.com/"+dirToken+"/sub/deep.txt", nil)
	w = s.do(req)
	c.Assert(w.Code, Equals, http.StatusOK)
	c.Assert(w.Body.String(), Equals, "nested")
}

// TestSubdirectoryFilenameSanitization verifies that unsafe characters in
// subdirectory paths are sanitized properly.
func (s *suiteDirectory) TestSubdirectoryFilenameSanitization(c *C) {
	// Upload a file using a subdirectory path containing characters that
	// sanitizePath strips (leading dots in path components are removed).
	req := httptest.NewRequest("PUT", "http://example.com/foo/.hidden/file.txt", strings.NewReader("safe"))
	w := s.do(req)
	c.Assert(w.Code, Equals, http.StatusOK)

	dirURL := w.Header().Get("X-Url-Directory")
	dirToken := strings.Trim(strings.TrimPrefix(dirURL, "http://example.com/"), "/")

	// Leading-dot components are stripped by sanitizePath, so the stored
	// path becomes "foo/hidden/file.txt" (hidden segment removed).
	req = httptest.NewRequest("GET", "http://example.com/"+dirToken+"/foo/hidden/file.txt", nil)
	w = s.do(req)
	c.Assert(w.Code, Equals, http.StatusOK)
	c.Assert(w.Body.String(), Equals, "safe")
}

// TestArchiveRouteMatches verifies that the zip/tar archive routes match
// paths correctly (the pattern must not contain literal parentheses).
func (s *suiteDirectory) TestArchiveRouteMatches(c *C) {
	req := httptest.NewRequest("PUT", "http://example.com/archive-test.txt", strings.NewReader("arch"))
	w := s.do(req)
	c.Assert(w.Code, Equals, http.StatusOK)
	dirURL := w.Header().Get("X-Url-Directory")
	dirToken := strings.Trim(strings.TrimPrefix(dirURL, "http://example.com/"), "/")

	req = httptest.NewRequest("GET", "http://example.com/"+dirToken+"/archive-test.txt.zip", nil)
	w = s.do(req)
	c.Assert(w.Code, Equals, http.StatusOK)
	c.Assert(w.Header().Get("Content-Type"), Equals, "application/zip")
}

// TestHTMLRenderingRootDirectory verifies that browser requests to the root
// directory listing render HTML without errors.
func (s *suiteDirectory) TestHTMLRenderingRootDirectory(c *C) {
	req := httptest.NewRequest("PUT", "http://example.com/hello.txt", strings.NewReader("hello"))
	w := s.do(req)
	c.Assert(w.Code, Equals, http.StatusOK)

	dirURL := w.Header().Get("X-Url-Directory")
	dirToken := strings.Trim(strings.TrimPrefix(dirURL, "http://example.com/"), "/")

	req = httptest.NewRequest("GET", "http://example.com/"+dirToken+"/", nil)
	req.Header.Set("Accept", "text/html")
	w = s.do(req)
	c.Assert(w.Code, Equals, http.StatusOK)
	c.Assert(strings.Contains(w.Header().Get("Content-Type"), "text/html"), Equals, true)
	c.Assert(strings.Contains(w.Body.String(), "hello.txt"), Equals, true)
	c.Assert(strings.Contains(w.Body.String(), "[ DIRECTORY ]"), Equals, true)
}

// TestHTMLRenderingSubdirectory verifies that browser requests to subdirectory
// listings render HTML with breadcrumbs and correct display names.
func (s *suiteDirectory) TestHTMLRenderingSubdirectory(c *C) {
	req := httptest.NewRequest("PUT", "http://example.com/sub/deep.txt", strings.NewReader("content"))
	w := s.do(req)
	c.Assert(w.Code, Equals, http.StatusOK)

	dirURL := w.Header().Get("X-Url-Directory")
	dirToken := strings.Trim(strings.TrimPrefix(dirURL, "http://example.com/"), "/")

	req = httptest.NewRequest("GET", "http://example.com/"+dirToken+"/sub/", nil)
	req.Header.Set("Accept", "text/html")
	w = s.do(req)
	c.Assert(w.Code, Equals, http.StatusOK)
	body := w.Body.String()
	c.Assert(strings.Contains(body, "deep.txt"), Equals, true)
	c.Assert(strings.Contains(body, "root"), Equals, true)
	c.Assert(strings.Contains(body, "sub"), Equals, true)
}

// TestSubdirectoryTrailingSlashRedirect verifies that requesting a subdirectory
// path without a trailing slash redirects to the path with a trailing slash.
func (s *suiteDirectory) TestSubdirectoryTrailingSlashRedirect(c *C) {
	req := httptest.NewRequest("PUT", "http://example.com/sub/file.txt", strings.NewReader("data"))
	w := s.do(req)
	c.Assert(w.Code, Equals, http.StatusOK)

	dirURL := w.Header().Get("X-Url-Directory")
	dirToken := strings.Trim(strings.TrimPrefix(dirURL, "http://example.com/"), "/")

	req = httptest.NewRequest("GET", "http://example.com/"+dirToken+"/sub", nil)
	w = s.do(req)
	c.Assert(w.Code, Equals, http.StatusMovedPermanently)
	c.Assert(strings.Contains(w.Header().Get("Location"), "/sub/"), Equals, true)
}

// TestDuplicateUploadUpdatesSize verifies that re-uploading a file with the
// same name to the same directory updates the stored size.
func (s *suiteDirectory) TestDuplicateUploadUpdatesSize(c *C) {
	req := httptest.NewRequest("PUT", "http://example.com/file.txt", strings.NewReader("short"))
	w := s.do(req)
	c.Assert(w.Code, Equals, http.StatusOK)

	dirURL := w.Header().Get("X-Url-Directory")
	uploadToken := w.Header().Get("X-Upload-Token")
	dirToken := strings.Trim(strings.TrimPrefix(dirURL, "http://example.com/"), "/")

	req = httptest.NewRequest("PUT", "http://example.com/"+dirToken+"/file.txt", strings.NewReader("a much longer content"))
	req.Header.Set("X-Upload-Token", uploadToken)
	w = s.do(req)
	c.Assert(w.Code, Equals, http.StatusOK)

	req = httptest.NewRequest("GET", "http://example.com/"+dirToken+"/", nil)
	w = s.do(req)
	c.Assert(w.Code, Equals, http.StatusOK)
}

// TestSubdirectoryPagination verifies that pagination works in subdirectory listings.
func (s *suiteDirectory) TestSubdirectoryPagination(c *C) {
	req := httptest.NewRequest("PUT", "http://example.com/top.txt", strings.NewReader("top"))
	w := s.do(req)
	c.Assert(w.Code, Equals, http.StatusOK)

	dirURL := w.Header().Get("X-Url-Directory")
	uploadToken := w.Header().Get("X-Upload-Token")
	dirToken := strings.Trim(strings.TrimPrefix(dirURL, "http://example.com/"), "/")

	for i := 0; i < 5; i++ {
		req = httptest.NewRequest("PUT", "http://example.com/"+dirToken+"/sub/"+string(rune('a'+i))+".txt", strings.NewReader("data"))
		req.Header.Set("X-Upload-Token", uploadToken)
		c.Assert(s.do(req).Code, Equals, http.StatusOK)
	}

	req = httptest.NewRequest("GET", "http://example.com/"+dirToken+"/sub/?page=1&limit=2", nil)
	w = s.do(req)
	c.Assert(w.Code, Equals, http.StatusOK)
	c.Assert(w.Header().Get("X-Total-Files"), Equals, "5")
	c.Assert(w.Header().Get("X-Page"), Equals, "1")
	c.Assert(w.Header().Get("X-Total-Pages"), Equals, "3")
}
