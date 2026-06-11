package server

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"html"
	htmlTemplate "html/template"
	"io"
	"mime"
	"mime/multipart"
	"net"
	"net/http"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	textTemplate "text/template"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/ProtonMail/go-crypto/openpgp/armor"
	"github.com/ProtonMail/go-crypto/openpgp/packet"
	"github.com/ProtonMail/gopenpgp/v2/constants"
	"github.com/morawskidotmy/transfer.ng/server/storage"
	"github.com/tg123/go-htpasswd"

	"github.com/gorilla/mux"
	"github.com/microcosm-cc/bluemonday"
	web "github.com/morawskidotmy/transfer.ng/web"
	blackfriday "github.com/russross/blackfriday/v2"
	qrcode "github.com/skip2/go-qrcode"
	"golang.org/x/net/idna"
	"golang.org/x/text/runes"
	"golang.org/x/text/transform"
	"golang.org/x/text/unicode/norm"
)

const getPathPart = "get"
const defaultMaxArchiveFiles = 100
const maxFilenameLength = 255
const maxPathDepth = 10
const maxPathLength = 1024
const maxTokenLength = 200

// defaultMaxUploadSize is the default maximum upload size (10GB) when maxUploadSize is not configured.
// This prevents unbounded uploads that could exhaust disk space.
const defaultMaxUploadSize = 10 * 1024 * 1024 * 1024

var idnaConverter = idna.New(idna.ValidateForRegistration())

func stripPrefix(p string) string {
	return strings.TrimPrefix(p, web.Prefix+"/")
}

func initTextTemplates() *textTemplate.Template {
	templateMap := textTemplate.FuncMap{"format": formatNumber}
	var templates = textTemplate.New("").Funcs(templateMap)
	return templates
}

func initHTMLTemplates() *htmlTemplate.Template {
	templateMap := htmlTemplate.FuncMap{
		"format": formatNumber,
		"add":    func(a, b int) int { return a + b },
	}
	var templates = htmlTemplate.New("").Funcs(templateMap)
	return templates
}

func attachEncryptionReader(reader io.ReadCloser, password string) (io.ReadCloser, error) {
	if len(password) == 0 {
		return reader, nil
	}

	return encrypt(reader, []byte(password))
}

func attachDecryptionReader(reader io.ReadCloser, password string) (io.ReadCloser, error) {
	if len(password) == 0 {
		return reader, nil
	}

	return decrypt(reader, []byte(password))
}

type readerWithCloser struct {
	io.Reader
	closeFn func() error
}

func (r *readerWithCloser) Close() error {
	return r.closeFn()
}

func decrypt(ciphertext io.ReadCloser, password []byte) (io.ReadCloser, error) {
	unarmored, err := armor.Decode(ciphertext)
	if err != nil {
		_ = ciphertext.Close()
		return nil, err
	}

	firstTimeCalled := true
	var prompt = func(keys []openpgp.Key, symmetric bool) ([]byte, error) {
		if firstTimeCalled {
			firstTimeCalled = false
			return password, nil
		}
		return nil, errors.New("gopenpgp: wrong password in symmetric decryption")
	}

	config := &packet.Config{
		DefaultCipher: packet.CipherAES256,
	}

	var emptyKeyRing openpgp.EntityList
	md, err := openpgp.ReadMessage(unarmored.Body, emptyKeyRing, prompt, config)
	if err != nil {
		_ = ciphertext.Close()
		return nil, err
	}

	return &readerWithCloser{
		Reader: md.UnverifiedBody,
		closeFn: func() error {
			return ciphertext.Close()
		},
	}, nil
}

func encrypt(plaintext io.ReadCloser, password []byte) (io.ReadCloser, error) {
	pr, pw := io.Pipe()

	go func() {
		defer func() { _ = plaintext.Close() }()
		defer func() { _ = pw.Close() }()

		config := &packet.Config{
			DefaultCipher: packet.CipherAES256,
			Time:          time.Now,
		}
		hints := &openpgp.FileHints{
			IsBinary: true,
			FileName: "",
			ModTime:  time.Now().UTC(),
		}

		armored, err := armor.Encode(pw, constants.PGPMessageHeader, nil)
		if err != nil {
			_ = pw.CloseWithError(err)
			return
		}

		encryptWriter, err := openpgp.SymmetricallyEncrypt(armored, password, hints, config)
		if err != nil {
			_ = pw.CloseWithError(err)
			return
		}

		if _, err := io.Copy(encryptWriter, plaintext); err != nil {
			_ = pw.CloseWithError(err)
			return
		}
		if err := encryptWriter.Close(); err != nil {
			_ = pw.CloseWithError(err)
			return
		}
		if err := armored.Close(); err != nil {
			_ = pw.CloseWithError(err)
			return
		}
	}()

	return pr, nil
}

func healthHandler(w http.ResponseWriter, _ *http.Request) {
	_, _ = w.Write([]byte("Approaching Neutral Zone, all systems normal and functioning."))
}

func (s *Server) respondError(w http.ResponseWriter, status int, publicMsg string, logFmt string, args ...interface{}) {
	if logFmt != "" {
		s.logger.Printf(logFmt, args...)
	}
	if publicMsg == "" {
		publicMsg = http.StatusText(status)
	}
	http.Error(w, publicMsg, status)
}

func contentTypeMayContainXSS(contentType string) bool {
	switch {
	case strings.Contains(contentType, "cache-manifest"),
		strings.Contains(contentType, "html"),
		strings.Contains(contentType, "rdf"),
		strings.Contains(contentType, "vtt"),
		strings.Contains(contentType, "xml"),
		strings.Contains(contentType, "xsl"),
		strings.Contains(contentType, "x-mixed-replace"):
		return true
	}

	return false
}

func (s *Server) getPreviewTemplate(contentType string, compressed bool) string {
	if compressed {
		return "download.html"
	}
	switch {
	case strings.HasPrefix(contentType, "image/"):
		return "download.image.html"
	case strings.HasPrefix(contentType, "video/"):
		return "download.video.html"
	case strings.HasPrefix(contentType, "audio/"):
		return "download.audio.html"
	case strings.HasPrefix(contentType, "text/"):
		return "download.markdown.html"
	default:
		return "download.html"
	}
}

func (s *Server) getTextContent(ctx context.Context, token, filename, contentType string) (htmlTemplate.HTML, string, error) {
	reader, _, err := s.storage.Get(ctx, token, filename, nil)
	if err != nil {
		return "", "", err
	}
	defer storage.CloseCheck(reader)

	buf := &bytes.Buffer{}
	if _, err = io.CopyN(buf, reader, _5M); err != nil && !errors.Is(err, io.EOF) {
		return "", "", err
	}
	data := buf.Bytes()

	if strings.HasPrefix(contentType, "text/x-markdown") || strings.HasPrefix(contentType, "text/markdown") {
		unsafe := blackfriday.Run(data)
		output := bluemonday.UGCPolicy().SanitizeBytes(unsafe)
		// #nosec G203 -- bluemonday.UGCPolicy() sanitizes all HTML, preventing XSS
		return htmlTemplate.HTML(output), "download.markdown.html", nil
	}
	if strings.HasPrefix(contentType, "text/plain") {
		// #nosec G203 -- html.EscapeString() escapes all HTML special characters
		return htmlTemplate.HTML(fmt.Sprintf("<pre>%s</pre>", html.EscapeString(string(data)))), "download.markdown.html", nil
	}
	return "", "download.sandbox.html", nil
}

var botSignatures = []string{
	"whatsapp",
	"discordbot",
	"telegrambot",
	"twitterbot",
	"facebookexternalhit",
	"linkedinbot",
	"slackbot",
	"embedly",
}

func isBotUserAgent(userAgent string) bool {
	ua := strings.ToLower(userAgent)
	for _, sig := range botSignatures {
		if strings.Contains(ua, sig) {
			return true
		}
	}
	return false
}

func (s *Server) previewHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Vary", "Accept, Range, Referer, X-Decrypt-Password, User-Agent")
	w.Header().Set("Cache-Control", "no-store")

	vars := mux.Vars(r)
	token := vars["token"]
	filename := sanitizePath(vars["filename"])

	if isBotUserAgent(r.Header.Get("User-Agent")) {
		vars["action"] = "inline"
		s.getHandler(w, r)
		return
	}

	if err := validateTokenAndFilename(token, filename); err != nil {
		s.respondError(w, http.StatusBadRequest, err.Error(), "")
		return
	}

	metadata, err := s.checkMetadata(r.Context(), token, filename, false)
	if err != nil {
		s.respondError(w, http.StatusNotFound, "", "Error metadata: %s", err.Error())
		return
	}

	contentType := metadata.ContentType
	contentLength, err := s.storage.Head(r.Context(), token, filename)
	if err != nil {
		s.respondError(w, http.StatusNotFound, "", "")
		return
	}

	templatePath := s.getPreviewTemplate(contentType, metadata.Compressed)
	var content htmlTemplate.HTML
	if metadata.Encrypted {
		templatePath = "download.html"
	}

	if !metadata.Encrypted && !metadata.Compressed && strings.HasPrefix(contentType, "text/") {
		content, templatePath, err = s.getTextContent(r.Context(), token, filename, contentType)
		if err != nil {
			s.respondError(w, http.StatusInternalServerError, "Could not retrieve file.", "preview: %v", err)
			return
		}
	}

	escapedPath := escapePathForURL(filename)
	relativeURL, _ := url.Parse(path.Join(s.proxyPath, token, escapedPath))
	resolvedURL := s.resolveURL(r, relativeURL)
	relativeURLGet, _ := url.Parse(path.Join(s.proxyPath, getPathPart, token, escapedPath))
	resolvedURLGet := s.resolveURL(r, relativeURLGet)
	directoryRelativeURL, _ := url.Parse(path.Join(s.proxyPath, token) + "/")
	directoryURL := s.resolveURL(r, directoryRelativeURL)

	png, err := qrcode.Encode(resolvedURL, qrcode.High, 150)
	if err != nil {
		s.respondError(w, http.StatusInternalServerError, "", "preview: failed to generate QR code: %v", err)
		return
	}

	data := struct {
		ContentType    string
		Content        htmlTemplate.HTML
		Filename       string
		URL            string
		URLGet         string
		DirectoryURL   string
		URLRandomToken string
		Hostname       string
		WebAddress     string
		ContentLength  uint64
		GAKey          string
		UserVoiceKey   string
		QRCode         string
	}{
		contentType,
		content,
		filename,
		resolvedURL,
		resolvedURLGet,
		directoryURL,
		token,
		s.getURL(r).Host,
		s.resolveWebAddress(r),
		contentLength,
		s.gaKey,
		s.userVoiceKey,
		base64.StdEncoding.EncodeToString(png),
	}

	s.htmlTemplatesMutex.RLock()
	err = s.htmlTemplates.ExecuteTemplate(w, templatePath, data)
	s.htmlTemplatesMutex.RUnlock()
	if err != nil {
		s.respondError(w, http.StatusInternalServerError, "", "preview: failed to execute template: %v", err)
		return
	}

}

// this handler will output html or text, depending on the
// support of the client (Accept header).

func (s *Server) viewHandler(w http.ResponseWriter, r *http.Request) {
	// vars := mux.Vars(r)

	hostname := s.getURL(r).Host
	webAddress := s.resolveWebAddress(r)

	maxUploadSize := ""
	if s.maxUploadSize > 0 {
		maxUploadSize = formatSize(s.maxUploadSize)
	}
	dirSizeCap := "unlimited"
	if s.maxDirSize > 0 {
		dirSizeCap = formatSize(s.maxDirSize)
	}
	dirFileCap := "unlimited"
	if s.maxDirFiles > 0 {
		dirFileCap = strconv.Itoa(s.maxDirFiles)
	}
	archiveFileCap := strconv.Itoa(defaultMaxArchiveFiles)
	if s.maxArchiveFiles > 0 {
		archiveFileCap = strconv.Itoa(s.maxArchiveFiles)
	}
	compressionThreshold := "disabled"
	if s.compressionThreshold > 0 {
		compressionThreshold = "files larger than " + formatSize(s.compressionThreshold)
	}

	purgeTime := ""
	if s.purgeDays > 0 {
		purgeTime = formatDurationDays(s.purgeDays)
	}

	data := struct {
		Hostname      string
		WebAddress    string
		EmailContact  string
		GAKey         string
		UserVoiceKey  string
		PurgeTime     string
		MaxUploadSize string
		DirSizeCap    string
		DirFileCap    string
		ArchiveMax    string
		CompressLarge string
		SampleToken   string
		SampleToken2  string
	}{
		hostname,
		webAddress,
		s.emailContact,
		s.gaKey,
		s.userVoiceKey,
		purgeTime,
		maxUploadSize,
		dirSizeCap,
		dirFileCap,
		archiveFileCap,
		compressionThreshold,
		s.sampleTokenA,
		s.sampleTokenB,
	}

	w.Header().Set("Vary", "Accept")
	w.Header().Set("Cache-Control", "no-store")
	if acceptsHTML(r.Header) {
		s.htmlTemplatesMutex.RLock()
		err := s.htmlTemplates.ExecuteTemplate(w, "index.html", data)
		s.htmlTemplatesMutex.RUnlock()
		if err != nil {
			s.logger.Printf("view: failed to execute template: %v", err)
			http.Error(w, "Internal server error.", http.StatusInternalServerError)
			return
		}
	} else {
		s.textTemplatesMutex.RLock()
		err := s.textTemplates.ExecuteTemplate(w, "index.txt", data)
		s.textTemplatesMutex.RUnlock()
		if err != nil {
			s.logger.Printf("view: failed to execute template: %v", err)
			http.Error(w, "Internal server error.", http.StatusInternalServerError)
			return
		}
	}
}

func (s *Server) notFoundHandler(w http.ResponseWriter, _ *http.Request) {
	http.Error(w, http.StatusText(http.StatusNotFound), http.StatusNotFound)
}

func sanitizePath(fileName string) string {
	fileName = strings.ReplaceAll(fileName, "\\", "/")

	t := transform.Chain(
		norm.NFD,
		runes.Remove(runes.In(unicode.Cc)),
		runes.Remove(runes.In(unicode.Cf)),
		runes.Remove(runes.In(unicode.Co)),
		runes.Remove(runes.In(unicode.Cs)),
		runes.Remove(runes.In(unicode.Other)),
		runes.Remove(runes.In(unicode.Zl)),
		runes.Remove(runes.In(unicode.Zp)),
		norm.NFC)
	sanitized, _, err := transform.String(t, fileName)
	if err != nil {
		sanitized = path.Base(fileName)
	}

	parts := strings.Split(sanitized, "/")
	var clean []string
	for _, part := range parts {
		if part == "" || part == ".." || part == "." {
			continue
		}
		part = strings.TrimLeft(part, ".")
		part = strings.ReplaceAll(part, ":", "")
		if part == "" {
			part = "_"
		}
		if utf8.RuneCountInString(part) > maxFilenameLength {
			part = string([]rune(part)[:maxFilenameLength])
		}
		if reservedFilenames[part] {
			part = "_"
		}
		if strings.HasSuffix(strings.ToLower(part), ".metadata") {
			part = part[:len(part)-len(".metadata")] + "_metadata"
		}
		clean = append(clean, part)
	}

	if len(clean) == 0 {
		return "_"
	}
	if len(clean) > maxPathDepth {
		clean = clean[:maxPathDepth]
	}

	result := strings.Join(clean, "/")
	if len(result) > maxPathLength {
		for len(result) > maxPathLength && len(clean) > 1 {
			clean = clean[1:]
			result = strings.Join(clean, "/")
		}
	}
	return result
}

func escapePathForURL(filename string) string {
	parts := strings.Split(filename, "/")
	escaped := make([]string, len(parts))
	for i, p := range parts {
		escaped[i] = url.PathEscape(p)
	}
	return strings.Join(escaped, "/")
}

func validateToken(token string) error {
	if len(token) == 0 {
		return fmt.Errorf("token is empty")
	}
	if len(token) > maxTokenLength {
		return fmt.Errorf("token too long")
	}
	for _, c := range token {
		if (c < '0' || c > '9') && (c < 'a' || c > 'z') && (c < 'A' || c > 'Z') {
			return fmt.Errorf("token contains invalid characters")
		}
	}
	return nil
}

func validateTokenAndFilename(token, filename string) error {
	if err := validateToken(token); err != nil {
		return err
	}
	if len(filename) > maxPathLength {
		return fmt.Errorf("filename too long")
	}
	for _, part := range strings.Split(filename, "/") {
		if reservedFilenames[part] {
			return fmt.Errorf("filename component is reserved")
		}
	}
	return nil
}

func (s *Server) postHandler(w http.ResponseWriter, r *http.Request) {
	s.limitRequestBody(w, r)
	// #nosec G120 -- multipartMemLimit (192 bytes) is intentionally small to limit memory usage
	if err := r.ParseMultipartForm(multipartMemLimit); nil != err {
		if s.handleUploadError(w, err) {
			return
		}
		s.logger.Printf("%s", err.Error())
		http.Error(w, "Error occurred copying to output stream", http.StatusInternalServerError)
		return
	}
	// Remove any temp files multipart parsing spilled to disk.
	defer func() { _ = r.MultipartForm.RemoveAll() }()

	// All files in a single POST are grouped into one directory so they can be
	// shared together and more files can be added later with the upload token.
	dirToken, uploadToken, dirErr := s.createDirectory(r.Context())
	if dirErr != nil {
		s.logger.Printf("%s", dirErr.Error())
		http.Error(w, "Error occurred creating directory", http.StatusInternalServerError)
		return
	}

	s.writeDirHeaders(w, r, dirToken, uploadToken)
	w.Header().Set("Content-Type", "text/plain")

	var responseBody strings.Builder
	responseBody.WriteString("Upload-Token: " + uploadToken + "\n")
	responseBody.WriteString("\n")

	for _, fHeaders := range r.MultipartForm.File {
		for _, fHeader := range fHeaders {
			if !s.processUploadFile(w, r, dirToken, fHeader, &responseBody) {
				return
			}
		}
	}
	_, err := w.Write([]byte(responseBody.String()))
	if err != nil {
		s.logger.Printf("post: failed to write response: %v", err)
		http.Error(w, "Internal server error.", http.StatusInternalServerError)
	}
}

func (s *Server) processUploadFile(w http.ResponseWriter, r *http.Request, token string, fHeader *multipart.FileHeader, responseBody *strings.Builder) bool {
	filename := sanitizePath(fHeader.Filename)

	if reservedFilenames[filename] {
		s.logger.Printf("upload: rejected reserved filename: %s", filename)
		http.Error(w, "Filename is reserved", http.StatusBadRequest)
		return false
	}

	contentType := mime.TypeByExtension(filepath.Ext(fHeader.Filename))

	f, err := fHeader.Open()
	if err != nil {
		s.logger.Printf("upload: failed to open file: %v", err)
		http.Error(w, "Could not process upload.", http.StatusInternalServerError)
		return false
	}
	defer storage.CloseCheck(f)

	file, err := os.CreateTemp(s.tempPath, "transfer-")
	if err != nil {
		s.logger.Printf("upload: failed to create temp file: %v", err)
		http.Error(w, "Could not process upload.", http.StatusInternalServerError)
		return false
	}
	defer s.cleanTmpFile(file)

	contentLength, err := s.copyAndValidateFile(w, file, f)
	if err != nil {
		return false
	}
	if !s.validateDirFileSize(w, contentLength) {
		return false
	}

	if s.performClamavPrescan {
		if !s.runVirusScan(w, file.Name()) {
			return false
		}
	}

	if !s.processPutUpload(w, r, token, filename, contentType, contentLength, file) {
		return false
	}

	if err := s.registerFileInDir(r.Context(), token, filename, contentLength); err != nil {
		s.cleanupOrphanedUpload(r.Context(), token, filename)
		if strings.Contains(err.Error(), "size limit") || strings.Contains(err.Error(), "file count limit") {
			s.respondError(w, http.StatusRequestEntityTooLarge, err.Error(), "upload: %v", err)
		} else {
			s.respondError(w, http.StatusInternalServerError, "Could not register file", "upload: %v", err)
		}
		return false
	}

	return s.addResponseURL(w, r, token, filename, responseBody)
}

func (s *Server) copyAndValidateFile(w http.ResponseWriter, file *os.File, f io.Reader) (int64, error) {
	n, err := io.Copy(file, f)
	if err != nil {
		if s.handleUploadError(w, err) {
			return 0, err
		}
		s.logger.Printf("upload: failed to copy file: %v", err)
		http.Error(w, "Could not process upload.", http.StatusInternalServerError)
		return 0, err
	}

	_, err = file.Seek(0, io.SeekStart)
	if err != nil {
		s.logger.Printf("upload: failed to seek file: %v", err)
		return 0, err
	}

	maxSize := s.maxUploadSize
	if maxSize <= 0 {
		maxSize = defaultMaxUploadSize
	}
	if n > maxSize {
		s.logger.Printf("Entity too large: %d > %d", n, maxSize)
		http.Error(w, http.StatusText(http.StatusRequestEntityTooLarge), http.StatusRequestEntityTooLarge)
		return 0, errors.New("entity too large")
	}

	return n, nil
}

func (s *Server) runVirusScan(w http.ResponseWriter, filePath string) bool {
	status, err := s.performScan(filePath)
	if err != nil {
		s.logger.Printf("%s", err.Error())
		http.Error(w, "Could not perform prescan", http.StatusInternalServerError)
		return false
	}

	if status != clamavScanStatusOK {
		s.logger.Printf("prescan positive: %s", status)
		http.Error(w, "Clamav prescan found a virus", http.StatusPreconditionFailed)
		return false
	}
	return true
}

func (s *Server) addResponseURL(w http.ResponseWriter, r *http.Request, uploadToken, filename string, responseBody *strings.Builder) bool {
	escapedPath := escapePathForURL(filename)
	storedMeta, err := s.checkMetadata(r.Context(), uploadToken, filename, false)
	if err != nil {
		s.logger.Printf("addResponseURL: %v", err)
		http.Error(w, "Could not generate response", http.StatusInternalServerError)
		return false
	}

	relativeURL, _ := url.Parse(path.Join(s.proxyPath, uploadToken, escapedPath))
	deleteURL, _ := url.Parse(path.Join(s.proxyPath, uploadToken, escapedPath))
	q := deleteURL.Query()
	q.Set("delete", storedMeta.DeletionToken)
	deleteURL.RawQuery = q.Encode()
	w.Header().Add("X-Url-Delete", s.resolveURL(r, deleteURL))
	responseBody.WriteString(s.getURL(r).ResolveReference(relativeURL).String())
	responseBody.WriteString("\n")
	return true
}

func (s *Server) cleanTmpFile(f *os.File) {
	if f != nil {
		err := f.Close()
		if err != nil {
			s.logger.Printf("Error closing tmpfile: %s (%s)", err, f.Name())
		}

		err = os.Remove(f.Name())
		if err != nil {
			s.logger.Printf("Error removing tmpfile: %s (%s)", err, f.Name())
		}
	}
}

type metadata struct {
	ContentType          string
	ContentLength        int64
	Downloads            int
	MaxDownloads         int
	MaxDate              time.Time
	DeletionToken        string
	Encrypted            bool
	DecryptedContentType string
	Compressed           bool
}

func metadataForRequest(contentType string, contentLength int64, randomTokenLength int, r *http.Request) (metadata, error) {
	delToken1, err := token(randomTokenLength)
	if err != nil {
		return metadata{}, err
	}
	delToken2, err := token(randomTokenLength)
	if err != nil {
		return metadata{}, err
	}
	metadata := metadata{
		ContentType:   strings.ToLower(contentType),
		ContentLength: contentLength,
		MaxDate:       time.Time{},
		Downloads:     0,
		MaxDownloads:  -1,
		DeletionToken: delToken1 + delToken2,
	}

	if v := r.Header.Get("Max-Downloads"); v != "" {
		if parsed, err := strconv.Atoi(v); err == nil && parsed >= 0 {
			metadata.MaxDownloads = parsed
		}
	}

	if v := r.Header.Get("Max-Days"); v != "" {
		if parsed, err := strconv.Atoi(v); err == nil && parsed > 0 && parsed <= 3650 {
			metadata.MaxDate = time.Now().Add(time.Hour * 24 * time.Duration(parsed))
		}
	}

	if password := r.Header.Get("X-Encrypt-Password"); password != "" {
		metadata.Encrypted = true
		metadata.ContentType = "text/plain; charset=utf-8"
		metadata.DecryptedContentType = contentType
	} else {
		metadata.Encrypted = false
	}

	return metadata, nil
}

func (s *Server) putHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	filename := sanitizePath(vars["filename"])

	if reservedFilenames[filename] {
		s.logger.Printf("put: rejected reserved filename: %s", filename)
		http.Error(w, "Filename is reserved", http.StatusBadRequest)
		return
	}

	putToken, err := token(s.randomTokenLength)
	if err != nil {
		s.logger.Printf("%s", err.Error())
		http.Error(w, "Error occurred generating token", http.StatusInternalServerError)
		return
	}

	uploadToken, err := s.makeUploadToken()
	if err != nil {
		s.logger.Printf("%s", err.Error())
		http.Error(w, "Error occurred generating token", http.StatusInternalServerError)
		return
	}

	ok, contentLength := s.doPutUpload(w, r, putToken, filename)
	if !ok {
		return
	}

	// Every upload lives in its own directory, even a single file. The upload
	// token returned to the client allows adding more files to this directory
	// later via PUT /{token}/{filename} with the X-Upload-Token header.
	idx := dirIndex{
		UploadToken: uploadToken,
		Created:     time.Now(),
		Files:       []fileEntry{{Name: filename, Size: contentLength, Modified: time.Now()}},
		TotalSize:   contentLength,
		SizeKnown:   true,
	}
	if err := s.saveDirIndex(r.Context(), putToken, idx); err != nil {
		s.logger.Printf("put: failed to save directory index: %v", err)
	}

	s.writePutResponse(w, r, putToken, filename, uploadToken)
}

// doPutUpload buffers (if needed), validates and stores the request body as
// filename under putToken. It is shared by single-file uploads and uploads that
// add a file to an existing directory.
func (s *Server) doPutUpload(w http.ResponseWriter, r *http.Request, putToken, filename string) (bool, int64) {
	s.limitRequestBody(w, r)
	defer storage.CloseCheck(r.Body)

	reader := r.Body
	contentLength := r.ContentLength

	if contentLength < 1 || s.performClamavPrescan {
		file, err := os.CreateTemp(s.tempPath, "transfer-")
		if err != nil {
			s.logger.Printf("put: failed to create temp file: %v", err)
			http.Error(w, "Could not process upload.", http.StatusInternalServerError)
			return false, 0
		}
		defer s.cleanTmpFile(file)

		var bufferErr error
		contentLength, bufferErr = s.bufferFileToTemp(w, file, r.Body)
		if bufferErr != nil {
			return false, 0
		}

		if s.performClamavPrescan && !s.runVirusScan(w, file.Name()) {
			return false, 0
		}

		reader = file
	}

	if !s.validateUploadSize(w, contentLength) {
		return false, 0
	}
	if !s.validateDirFileSize(w, contentLength) {
		return false, 0
	}

	contentType := mime.TypeByExtension(filepath.Ext(filename))
	if !s.processPutUpload(w, r, putToken, filename, contentType, contentLength, reader) {
		return false, 0
	}
	return true, contentLength
}

func (s *Server) bufferFileToTemp(w http.ResponseWriter, file *os.File, requestBody io.Reader) (int64, error) {
	n, err := io.Copy(file, requestBody)
	if err != nil {
		if s.handleUploadError(w, err) {
			return 0, err
		}
		s.logger.Printf("put: failed to buffer file: %v", err)
		http.Error(w, "Could not process upload.", http.StatusInternalServerError)
		return 0, err
	}

	_, err = file.Seek(0, io.SeekStart)
	if err != nil {
		s.logger.Printf("put: failed to seek file: %v", err)
		http.Error(w, "Could not process upload.", http.StatusInternalServerError)
		return 0, err
	}

	return n, nil
}

func (s *Server) validateUploadSize(w http.ResponseWriter, contentLength int64) bool {
	maxSize := s.maxUploadSize
	if maxSize <= 0 {
		maxSize = defaultMaxUploadSize
	}
	if contentLength > maxSize {
		s.logger.Printf("Entity too large: %d > %d", contentLength, maxSize)
		http.Error(w, http.StatusText(http.StatusRequestEntityTooLarge), http.StatusRequestEntityTooLarge)
		return false
	}

	return true
}

// handleUploadError checks if the error is a MaxBytesError and returns 413,
// otherwise returns 500. Returns true if an error was handled.
func (s *Server) handleUploadError(w http.ResponseWriter, err error) bool {
	if err == nil {
		return false
	}
	var maxBytesErr *http.MaxBytesError
	if errors.As(err, &maxBytesErr) {
		s.logger.Printf("upload: request body too large: %v", err)
		http.Error(w, http.StatusText(http.StatusRequestEntityTooLarge), http.StatusRequestEntityTooLarge)
		return true
	}
	return false
}

// limitRequestBody wraps r.Body with http.MaxBytesReader to prevent unbounded reads.
// Uses maxUploadSize if configured, otherwise falls back to defaultMaxUploadSize.
func (s *Server) limitRequestBody(w http.ResponseWriter, r *http.Request) {
	maxSize := s.maxUploadSize
	if maxSize <= 0 {
		maxSize = defaultMaxUploadSize
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxSize+1)
}

func (s *Server) validateDirFileSize(w http.ResponseWriter, contentLength int64) bool {
	if s.maxDirSize > 0 && contentLength > s.maxDirSize {
		s.logger.Print("File exceeds directory size limit")
		http.Error(w, fmt.Sprintf("file size exceeds directory size limit (max %d bytes)", s.maxDirSize), http.StatusRequestEntityTooLarge)
		return false
	}

	return true
}

func (s *Server) processPutUpload(w http.ResponseWriter, r *http.Request, putToken, filename, contentType string, contentLength int64, reader io.ReadCloser) bool {
	metadata, err := metadataForRequest(contentType, contentLength, s.randomTokenLength, r)
	if err != nil {
		s.logger.Printf("processPutUpload: %v", err)
		http.Error(w, "Could not generate metadata", http.StatusInternalServerError)
		return false
	}

	shouldCompress := s.compressionThreshold > 0 && contentLength > s.compressionThreshold
	if shouldCompress {
		metadata.Compressed = true
		s.logger.Printf("File %s will be compressed (size: %d bytes)", filename, contentLength)
	}

	if !s.saveMetadata(w, r, putToken, filename, metadata) {
		return false
	}

	s.logger.Printf("Uploading %s %s %d %s", putToken, filename, contentLength, contentType)

	// Order matters: compress the plaintext first, then encrypt. Downloads
	// decrypt before decompressing, so the stored layout must be
	// encrypt(compress(plaintext)). Compressing after encryption would make
	// encrypted files impossible to decrypt on download.
	finalReader := reader
	finalLength := contentLength

	if shouldCompress {
		compressTmp, ok := s.compressAndUpdate(w, &finalReader, &finalLength)
		if !ok {
			s.cleanupOrphanedUpload(r.Context(), putToken, filename)
			return false
		}
		defer s.cleanTmpFile(compressTmp)
	}

	password := r.Header.Get("X-Encrypt-Password")
	if password != "" {
		encryptedReader, err := attachEncryptionReader(finalReader, password)
		if err != nil {
			s.cleanupOrphanedUpload(r.Context(), putToken, filename)
			http.Error(w, "Could not crypt file", http.StatusInternalServerError)
			return false
		}
		defer storage.CloseCheck(encryptedReader)

		encTmp, err := os.CreateTemp(s.tempPath, "transfer-encrypt-")
		if err != nil {
			s.logger.Printf("encrypt: failed to create temp file: %v", err)
			s.cleanupOrphanedUpload(r.Context(), putToken, filename)
			http.Error(w, "Could not encrypt file", http.StatusInternalServerError)
			return false
		}
		defer s.cleanTmpFile(encTmp)

		if _, err := io.Copy(encTmp, encryptedReader); err != nil {
			s.logger.Printf("encrypt: failed to write encrypted temp: %v", err)
			s.cleanupOrphanedUpload(r.Context(), putToken, filename)
			http.Error(w, "Could not encrypt file", http.StatusInternalServerError)
			return false
		}

		if _, err := encTmp.Seek(0, io.SeekStart); err != nil {
			s.logger.Printf("encrypt: failed to seek encrypted temp: %v", err)
			s.cleanupOrphanedUpload(r.Context(), putToken, filename)
			http.Error(w, "Could not encrypt file", http.StatusInternalServerError)
			return false
		}

		fi, err := encTmp.Stat()
		if err != nil {
			s.logger.Printf("encrypt: failed to stat encrypted temp: %v", err)
			s.cleanupOrphanedUpload(r.Context(), putToken, filename)
			http.Error(w, "Could not encrypt file", http.StatusInternalServerError)
			return false
		}

		finalReader = encTmp
		finalLength = fi.Size()
	}

	if err = s.storage.Put(r.Context(), putToken, filename, finalReader, contentType, storage.SafeInt64ToUint64(finalLength)); err != nil {
		s.logger.Printf("Error putting new file: %s", err.Error())
		s.cleanupOrphanedUpload(r.Context(), putToken, filename)
		http.Error(w, "Could not save file", http.StatusInternalServerError)
		return false
	}

	return true
}

func (s *Server) saveMetadata(w http.ResponseWriter, r *http.Request, putToken, filename string, metadata metadata) bool {
	buffer := &bytes.Buffer{}
	if err := json.NewEncoder(buffer).Encode(metadata); err != nil {
		s.logger.Printf("%s", err.Error())
		http.Error(w, "Could not encode metadata", http.StatusInternalServerError)
		return false
	}

	if !metadata.MaxDate.IsZero() && time.Now().After(metadata.MaxDate) {
		s.logger.Print("Invalid MaxDate")
		http.Error(w, "Invalid MaxDate, make sure Max-Days is smaller than 290 years", http.StatusBadRequest)
		return false
	}

	if err := s.storage.Put(r.Context(), putToken, fmt.Sprintf("%s.metadata", filename), buffer, "text/json", storage.SafeIntToUint64(buffer.Len())); err != nil {
		s.logger.Printf("%s", err.Error())
		http.Error(w, "Could not save metadata", http.StatusInternalServerError)
		return false
	}

	return true
}

func (s *Server) compressAndUpdate(w http.ResponseWriter, reader *io.ReadCloser, contentLength *int64) (*os.File, bool) {
	tmpFile, err := os.CreateTemp(s.tempPath, "transfer-compress-")
	if err != nil {
		s.logger.Printf("compress: failed to create temp file: %v", err)
		http.Error(w, "Could not compress file", http.StatusInternalServerError)
		return nil, false
	}

	if _, err := CompressStream(tmpFile, *reader); err != nil {
		_ = tmpFile.Close()
		_ = os.Remove(tmpFile.Name())
		s.logger.Printf("Error compressing file: %s", err.Error())
		http.Error(w, "Could not compress file", http.StatusInternalServerError)
		return nil, false
	}

	if _, err := tmpFile.Seek(0, io.SeekStart); err != nil {
		_ = tmpFile.Close()
		_ = os.Remove(tmpFile.Name())
		s.logger.Printf("compress: failed to seek temp file: %v", err)
		http.Error(w, "Could not compress file", http.StatusInternalServerError)
		return nil, false
	}

	fi, err := tmpFile.Stat()
	if err != nil {
		_ = tmpFile.Close()
		_ = os.Remove(tmpFile.Name())
		s.logger.Printf("compress: failed to stat temp file: %v", err)
		http.Error(w, "Could not compress file", http.StatusInternalServerError)
		return nil, false
	}

	*reader = tmpFile
	*contentLength = fi.Size()
	return tmpFile, true
}

func (s *Server) writePutResponse(w http.ResponseWriter, r *http.Request, putToken, filename, uploadToken string) bool {
	storedMeta, err := s.checkMetadata(r.Context(), putToken, filename, false)
	if err != nil {
		s.logger.Printf("writePutResponse: %v", err)
		http.Error(w, "Could not generate response", http.StatusInternalServerError)
		return false
	}

	w.Header().Set("Content-Type", "text/plain")
	escapedPath := escapePathForURL(filename)
	relativeURL, _ := url.Parse(path.Join(s.proxyPath, putToken, escapedPath))
	deleteURL, _ := url.Parse(path.Join(s.proxyPath, putToken, escapedPath))
	q := deleteURL.Query()
	q.Set("delete", storedMeta.DeletionToken)
	deleteURL.RawQuery = q.Encode()

	w.Header().Set("X-Url-Delete", s.resolveURL(r, deleteURL))
	s.writeDirHeaders(w, r, putToken, uploadToken)
	// URL is constructed from server-generated token and sanitized filename
	// #nosec G705 -- all URL components are server-controlled or sanitized
	_, _ = w.Write([]byte(s.resolveURL(r, relativeURL)))
	return true
}

func (s *Server) resolveURL(r *http.Request, u *url.URL) string {
	cloned := cloneURL(r.URL)
	cloned.Path = ""

	return s.getURL(&http.Request{URL: cloned, Host: r.Host, Header: r.Header, TLS: r.TLS, RemoteAddr: r.RemoteAddr}).ResolveReference(u).String()
}

func resolveKey(key, proxyPath string) string {
	key = strings.TrimPrefix(key, "/")

	key = strings.TrimPrefix(key, proxyPath)

	key = strings.ReplaceAll(key, "\\", "/")

	return key
}

func (s *Server) resolveWebAddress(r *http.Request) string {
	rURL := s.getURL(r)
	resolved := rURL.ResolveReference(rURL)

	if len(s.proxyPath) == 0 {
		return fmt.Sprintf("%s://%s/", resolved.Scheme, resolved.Host)
	}
	return fmt.Sprintf("%s://%s/%s", resolved.Scheme, resolved.Host, strings.TrimPrefix(s.proxyPath, "/"))
}

// Similar to the logic found here:
// https://github.com/golang/go/blob/release-branch.go1.14/src/net/http/clone.go#L22-L33
func cloneURL(u *url.URL) *url.URL {
	c := &url.URL{}
	*c = *u

	if u.User != nil {
		c.User = &url.Userinfo{}
		*c.User = *u.User
	}

	return c
}

func (s *Server) getURL(r *http.Request) *url.URL {
	u := cloneURL(r.URL)

	if r.TLS != nil {
		u.Scheme = "https"
	} else if s.trustForwardedHeaders(r) {
		if proto := r.Header.Get("X-Forwarded-Proto"); proto != "" {
			u.Scheme = proto
		} else {
			u.Scheme = "http"
		}
	} else {
		u.Scheme = "http"
	}

	validHost := s.validateHost(r)
	if validHost == "" {
		u.Host = "localhost"
	} else {
		host, port, err := net.SplitHostPort(validHost)
		if err != nil {
			host = validHost
			port = ""
		}

		hostFromPunycode, err := idnaConverter.ToUnicode(host)
		if err == nil {
			host = hostFromPunycode
		}

		if len(s.proxyPort) != 0 {
			port = s.proxyPort
		}

		if len(port) == 0 || (port == "80" && u.Scheme == "http") || (port == "443" && u.Scheme == "https") {
			u.Host = host
		} else {
			u.Host = net.JoinHostPort(host, port)
		}
	}

	return u
}

func (metadata metadata) remainingLimitHeaderValues() (remainingDownloads, remainingDays string) {
	if metadata.MaxDate.IsZero() {
		remainingDays = "n/a"
	} else {
		timeDifference := time.Until(metadata.MaxDate)
		remainingDays = strconv.Itoa(int(timeDifference.Hours()/24) + 1)
	}

	if metadata.MaxDownloads == -1 {
		remainingDownloads = "n/a"
	} else {
		remainingDownloads = strconv.Itoa(metadata.MaxDownloads - metadata.Downloads)
	}

	return remainingDownloads, remainingDays
}

func (s *Server) lock(token, filename string) {
	key := path.Join(token, filename)

	lock, _ := s.locks.LoadOrStore(key, &sync.Mutex{})

	lock.(*sync.Mutex).Lock()
}

func (s *Server) unlock(token, filename string) {
	key := path.Join(token, filename)

	if lock, ok := s.locks.Load(key); ok {
		lock.(*sync.Mutex).Unlock()
	}
}

func (s *Server) checkMetadata(ctx context.Context, token, filename string, _ bool) (metadata, error) {
	var metadata metadata

	r, _, err := s.storage.Get(ctx, token, fmt.Sprintf("%s.metadata", filename), nil)
	if err != nil {
		return metadata, err
	}
	defer storage.CloseCheck(r)

	if err := json.NewDecoder(r).Decode(&metadata); err != nil {
		return metadata, err
	}
	if metadata.MaxDownloads != -1 && metadata.Downloads >= metadata.MaxDownloads {
		return metadata, errors.New("maxDownloads expired")
	}
	if !metadata.MaxDate.IsZero() && time.Now().After(metadata.MaxDate) {
		return metadata, errors.New("maxDate expired")
	}

	return metadata, nil
}

func (s *Server) incrementDownloadCount(ctx context.Context, token, filename string) error {
	s.lock(token, filename)
	defer s.unlock(token, filename)

	var metadata metadata

	r, _, err := s.storage.Get(ctx, token, fmt.Sprintf("%s.metadata", filename), nil)
	if err != nil {
		return err
	}
	defer storage.CloseCheck(r)

	if err := json.NewDecoder(r).Decode(&metadata); err != nil {
		return err
	}

	if metadata.MaxDownloads != -1 && metadata.Downloads >= metadata.MaxDownloads {
		return errors.New("maxDownloads expired")
	}
	if !metadata.MaxDate.IsZero() && time.Now().After(metadata.MaxDate) {
		return errors.New("maxDate expired")
	}

	if metadata.MaxDownloads != -1 {
		metadata.Downloads++

		buffer := &bytes.Buffer{}
		if err := json.NewEncoder(buffer).Encode(metadata); err != nil {
			return errors.New("could not encode metadata")
		}
		if err := s.storage.Put(ctx, token, fmt.Sprintf("%s.metadata", filename), buffer, "text/json", storage.SafeIntToUint64(buffer.Len())); err != nil {
			return errors.New("could not save metadata")
		}
	}

	return nil
}

func (s *Server) checkDeletionToken(ctx context.Context, deletionToken, token, filename string) error {
	s.lock(token, filename)
	defer s.unlock(token, filename)

	var metadata metadata

	r, _, err := s.storage.Get(ctx, token, fmt.Sprintf("%s.metadata", filename), nil)
	if s.storage.IsNotExist(err) {
		return errors.New("metadata doesn't exist")
	}
	if err != nil {
		return err
	}
	defer storage.CloseCheck(r)

	if err := json.NewDecoder(r).Decode(&metadata); err != nil {
		return err
	}
	if subtle.ConstantTimeCompare([]byte(metadata.DeletionToken), []byte(deletionToken)) != 1 {
		return errors.New("deletion token doesn't match")
	}

	return nil
}

func (s *Server) purgeHandler() {
	ticker := time.NewTicker(s.purgeInterval)
	defer ticker.Stop()
	for {
		select {
		case <-s.purgeCtx.Done():
			return
		case <-ticker.C:
			err := s.storage.Purge(s.purgeCtx, s.purgeDays)
			if err != nil {
				s.logger.Printf("error cleaning up expired files: %v", err)
			}
		}
	}
}

func (s *Server) deleteHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)

	token := vars["token"]
	if err := validateToken(token); err != nil {
		s.respondError(w, http.StatusBadRequest, err.Error(), "")
		return
	}
	filename := sanitizePath(vars["filename"])
	deletionToken := vars["deletionToken"]

	if deletionToken == "" {
		deletionToken = r.URL.Query().Get("delete")
	}
	if deletionToken == "" {
		deletionToken = r.Header.Get("X-Deletion-Token")
	}

	if deletionToken == "" {
		s.respondError(w, http.StatusBadRequest, "Missing deletion token", "delete: missing deletion token")
		return
	}

	if err := s.checkDeletionToken(r.Context(), deletionToken, token, filename); err != nil {
		s.respondError(w, http.StatusNotFound, "", "Error metadata: %s", err.Error())
		return
	}

	err := s.storage.Delete(r.Context(), token, filename)
	if s.storage.IsNotExist(err) {
		s.respondError(w, http.StatusNotFound, "", "")
		return
	} else if err != nil {
		s.respondError(w, http.StatusInternalServerError, "Could not delete file.", "%v", err)
		return
	}

	s.unregisterFileFromDir(r.Context(), token, filename)
}

type archiveFileSpec struct {
	token    string
	filename string
}

func (s *Server) parseArchiveFiles(filesSpec string) ([]archiveFileSpec, error) {
	keys := strings.Split(filesSpec, ",")
	maxFiles := s.maxArchiveFiles
	if maxFiles <= 0 {
		maxFiles = defaultMaxArchiveFiles
	}
	if len(keys) > maxFiles {
		return nil, fmt.Errorf("too many files requested (max %d)", maxFiles)
	}

	var specs []archiveFileSpec
	for _, key := range keys {
		key = resolveKey(key, s.proxyPath)
		parts := strings.SplitN(key, "/", 2)
		if len(parts) != 2 {
			continue
		}
		if err := validateTokenAndFilename(parts[0], parts[1]); err != nil {
			continue
		}
		specs = append(specs, archiveFileSpec{
			token:    parts[0],
			filename: sanitizePath(parts[1]),
		})
	}
	return specs, nil
}

func (s *Server) fetchFileForArchive(ctx context.Context, token, filename, password string, increaseDownload bool) (io.ReadCloser, uint64, error) {
	meta, err := s.checkMetadata(ctx, token, filename, false)
	if err != nil {
		return nil, 0, err
	}

	reader, contentLength, err := s.storage.Get(ctx, token, filename, nil)
	if err != nil {
		return nil, 0, err
	}

	if meta.Encrypted {
		if password == "" {
			storage.CloseCheck(reader)
			return nil, 0, errors.New("encrypted file requires X-Decrypt-Password")
		}
		reader, err = attachDecryptionReader(reader, password)
		if err != nil {
			storage.CloseCheck(reader)
			return nil, 0, err
		}
		contentLength = storage.SafeInt64ToUint64(meta.ContentLength)
	}

	if meta.Compressed {
		cr, crErr := NewCompressionReader(reader, true)
		if crErr != nil {
			storage.CloseCheck(reader)
			return nil, 0, crErr
		}
		reader = cr
		if meta.ContentLength > 0 {
			contentLength = uint64(meta.ContentLength)
		}
	}

	if increaseDownload {
		if err := s.incrementDownloadCount(ctx, token, filename); err != nil {
			storage.CloseCheck(reader)
			return nil, 0, err
		}
	}

	return reader, contentLength, nil
}

// preflightArchiveFile validates if a file can be fetched for archive creation
// using metadata-only checks. For encrypted files, it only checks that a password
// is provided; actual password validation happens during fetch.
// Returns true if the file is likely fetchable, false otherwise.
func (s *Server) preflightArchiveFile(ctx context.Context, token, filename, password string) bool {
	meta, err := s.checkMetadata(ctx, token, filename, false)
	if err != nil {
		return false
	}

	if meta.Encrypted && password == "" {
		return false
	}

	return true
}

// preflightArchiveSpecs checks if files in a spec list can be fetched
// for archive creation without incrementing download counts.
// Uses metadata-only validation to minimize storage reads.
// For encrypted files, it only checks that a password is provided.
// Returns the number of files that can be fetched and their total size.
func (s *Server) preflightArchiveSpecs(ctx context.Context, specs []archiveFileSpec, password string) (int, int64) {
	var fetchableCount int
	var totalSize int64
	for _, spec := range specs {
		meta, err := s.checkMetadata(ctx, spec.token, spec.filename, false)
		if err != nil {
			continue
		}
		if meta.Encrypted && password == "" {
			continue
		}
		fetchableCount++
		if meta.ContentLength > 0 {
			totalSize += meta.ContentLength
		}
	}
	return fetchableCount, totalSize
}

// manifestForSpecs generates manifest content for multi-file archives.
func manifestForSpecs(specs []archiveFileSpec, addedFiles int, totalSize int64, skippedFiles []string) string {
	var sb strings.Builder
	_, _ = sb.WriteString("# transfer.ng Archive Manifest\n")
	_, _ = fmt.Fprintf(&sb, "Created: %s\n", time.Now().UTC().Format(time.RFC3339))
	_, _ = fmt.Fprintf(&sb, "Files: %d\n", addedFiles)
	_, _ = fmt.Fprintf(&sb, "Total Size: %d bytes\n", totalSize)
	if len(specs) > 0 {
		_, _ = sb.WriteString("\n# Requested Files:\n")
		for _, spec := range specs {
			_, _ = fmt.Fprintf(&sb, "# - %s/%s\n", spec.token, spec.filename)
		}
	}
	if len(skippedFiles) > 0 {
		_, _ = sb.WriteString("\n# Skipped Files:\n")
		for _, f := range skippedFiles {
			_, _ = fmt.Fprintf(&sb, "# - %s\n", f)
		}
	}
	return sb.String()
}

func (s *Server) zipHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)

	specs, err := s.parseArchiveFiles(vars["files"])
	if err != nil {
		s.respondError(w, http.StatusBadRequest, err.Error(), "")
		return
	}

	if len(specs) == 0 {
		s.respondError(w, http.StatusBadRequest, "No files specified for archive", "")
		return
	}

	password := r.Header.Get("X-Decrypt-Password")
	fetchableCount, totalSize := s.preflightArchiveSpecs(r.Context(), specs, password)
	if fetchableCount == 0 {
		s.respondError(w, http.StatusBadRequest, "No downloadable files for archive", "")
		return
	}

	if s.maxArchiveSize > 0 && totalSize > s.maxArchiveSize {
		s.respondError(w, http.StatusBadRequest, fmt.Sprintf("Archive too large (max %d bytes)", s.maxArchiveSize), "")
		return
	}

	zipfilename := fmt.Sprintf("transfersh-%d.zip", time.Now().UnixNano())

	w.Header().Set("Content-Type", "application/zip")
	commonHeader(w, zipfilename)

	zw := zip.NewWriter(w)

	var addedFiles int
	var actualTotalSize int64
	var skippedFiles []string

	for _, spec := range specs {
		reader, contentLength, err := s.fetchFileForArchive(r.Context(), spec.token, spec.filename, password, true)
		if err != nil {
			s.logger.Printf("zip: skipping %s/%s: %v", spec.token, spec.filename, err)
			skippedFiles = append(skippedFiles, fmt.Sprintf("%s/%s", spec.token, spec.filename))
			continue
		}

		header := &zip.FileHeader{
			Name:     spec.filename,
			Method:   zip.Store,
			Modified: time.Now().UTC(),
		}

		fw, err := zw.CreateHeader(header)
		if err != nil {
			storage.CloseCheck(reader)
			s.logger.Printf("zip: failed to create entry for %s: %v", spec.filename, err)
			skippedFiles = append(skippedFiles, fmt.Sprintf("%s/%s", spec.token, spec.filename))
			continue
		}

		_, err = io.Copy(fw, reader)
		storage.CloseCheck(reader)
		if err != nil {
			s.logger.Printf("zip: failed to copy %s: %v", spec.filename, err)
			skippedFiles = append(skippedFiles, fmt.Sprintf("%s/%s", spec.token, spec.filename))
			continue
		}
		addedFiles++
		actualTotalSize += storage.SafeUint64ToInt64(contentLength)
	}

	// Add manifest file
	manifestContent := manifestForSpecs(specs, addedFiles, actualTotalSize, skippedFiles)
	manifestHeader := &zip.FileHeader{
		Name:     "_transfer-ng-manifest.txt",
		Method:   zip.Store,
		Modified: time.Now().UTC(),
	}
	mw, err := zw.CreateHeader(manifestHeader)
	if err == nil {
		_, _ = mw.Write([]byte(manifestContent))
	}

	if err := zw.Close(); err != nil {
		s.respondError(w, http.StatusInternalServerError, "", "%v", err)
		return
	}
}

func (s *Server) tarGzHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)

	specs, err := s.parseArchiveFiles(vars["files"])
	if err != nil {
		s.respondError(w, http.StatusBadRequest, err.Error(), "")
		return
	}

	if len(specs) == 0 {
		s.respondError(w, http.StatusBadRequest, "No files specified for archive", "")
		return
	}

	password := r.Header.Get("X-Decrypt-Password")
	fetchableCount, totalSize := s.preflightArchiveSpecs(r.Context(), specs, password)
	if fetchableCount == 0 {
		s.respondError(w, http.StatusBadRequest, "No downloadable files for archive", "")
		return
	}

	if s.maxArchiveSize > 0 && totalSize > s.maxArchiveSize {
		s.respondError(w, http.StatusBadRequest, fmt.Sprintf("Archive too large (max %d bytes)", s.maxArchiveSize), "")
		return
	}

	tarfilename := fmt.Sprintf("transfersh-%d.tar.gz", time.Now().UnixNano())

	w.Header().Set("Content-Type", "application/x-gzip")
	commonHeader(w, tarfilename)

	gw := gzip.NewWriter(w)
	defer storage.CloseCheck(gw)

	zw := tar.NewWriter(gw)
	defer storage.CloseCheck(zw)

	var addedFiles int
	var actualTotalSize int64
	var skippedFiles []string

	for _, spec := range specs {
		reader, contentLength, err := s.fetchFileForArchive(r.Context(), spec.token, spec.filename, password, true)
		if err != nil {
			s.logger.Printf("tarGz: skipping %s/%s: %v", spec.token, spec.filename, err)
			skippedFiles = append(skippedFiles, fmt.Sprintf("%s/%s", spec.token, spec.filename))
			continue
		}

		header := &tar.Header{
			Name: spec.filename,
			Size: storage.SafeUint64ToInt64(contentLength),
		}

		if err := zw.WriteHeader(header); err != nil {
			storage.CloseCheck(reader)
			s.logger.Printf("tarGz: failed to write header for %s: %v", spec.filename, err)
			skippedFiles = append(skippedFiles, fmt.Sprintf("%s/%s", spec.token, spec.filename))
			continue
		}

		_, err = io.Copy(zw, reader)
		storage.CloseCheck(reader)
		if err != nil {
			s.logger.Printf("tarGz: failed to copy %s: %v", spec.filename, err)
			skippedFiles = append(skippedFiles, fmt.Sprintf("%s/%s", spec.token, spec.filename))
			continue
		}
		addedFiles++
		actualTotalSize += storage.SafeUint64ToInt64(contentLength)
	}

	// Add manifest file
	manifestContent := manifestForSpecs(specs, addedFiles, actualTotalSize, skippedFiles)
	manifestHeader := &tar.Header{
		Name: "_transfer-ng-manifest.txt",
		Size: int64(len(manifestContent)),
	}
	if err := zw.WriteHeader(manifestHeader); err == nil {
		_, _ = zw.Write([]byte(manifestContent))
	}
}

func (s *Server) tarHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)

	specs, err := s.parseArchiveFiles(vars["files"])
	if err != nil {
		s.respondError(w, http.StatusBadRequest, err.Error(), "")
		return
	}

	if len(specs) == 0 {
		s.respondError(w, http.StatusBadRequest, "No files specified for archive", "")
		return
	}

	password := r.Header.Get("X-Decrypt-Password")
	fetchableCount, totalSize := s.preflightArchiveSpecs(r.Context(), specs, password)
	if fetchableCount == 0 {
		s.respondError(w, http.StatusBadRequest, "No downloadable files for archive", "")
		return
	}

	if s.maxArchiveSize > 0 && totalSize > s.maxArchiveSize {
		s.respondError(w, http.StatusBadRequest, fmt.Sprintf("Archive too large (max %d bytes)", s.maxArchiveSize), "")
		return
	}

	tarfilename := fmt.Sprintf("transfersh-%d.tar", time.Now().UnixNano())

	w.Header().Set("Content-Type", "application/x-tar")
	commonHeader(w, tarfilename)

	zw := tar.NewWriter(w)
	defer storage.CloseCheck(zw)

	var addedFiles int
	var actualTotalSize int64
	var skippedFiles []string

	for _, spec := range specs {
		reader, contentLength, err := s.fetchFileForArchive(r.Context(), spec.token, spec.filename, password, true)
		if err != nil {
			s.logger.Printf("tar: skipping %s/%s: %v", spec.token, spec.filename, err)
			skippedFiles = append(skippedFiles, fmt.Sprintf("%s/%s", spec.token, spec.filename))
			continue
		}

		header := &tar.Header{
			Name: spec.filename,
			Size: storage.SafeUint64ToInt64(contentLength),
		}

		if err := zw.WriteHeader(header); err != nil {
			storage.CloseCheck(reader)
			s.logger.Printf("tar: failed to write header for %s: %v", spec.filename, err)
			skippedFiles = append(skippedFiles, fmt.Sprintf("%s/%s", spec.token, spec.filename))
			continue
		}

		_, err = io.Copy(zw, reader)
		storage.CloseCheck(reader)
		if err != nil {
			s.logger.Printf("tar: failed to copy %s: %v", spec.filename, err)
			skippedFiles = append(skippedFiles, fmt.Sprintf("%s/%s", spec.token, spec.filename))
			continue
		}
		addedFiles++
		actualTotalSize += storage.SafeUint64ToInt64(contentLength)
	}

	// Add manifest file
	manifestContent := manifestForSpecs(specs, addedFiles, actualTotalSize, skippedFiles)
	manifestHeader := &tar.Header{
		Name: "_transfer-ng-manifest.txt",
		Size: int64(len(manifestContent)),
	}
	if err := zw.WriteHeader(manifestHeader); err == nil {
		_, _ = zw.Write([]byte(manifestContent))
	}
}

func (s *Server) headHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)

	token := vars["token"]
	filename := sanitizePath(vars["filename"])

	if err := validateTokenAndFilename(token, filename); err != nil {
		s.respondError(w, http.StatusBadRequest, err.Error(), "")
		return
	}

	metadata, err := s.checkMetadata(r.Context(), token, filename, false)

	if err != nil {
		s.respondError(w, http.StatusNotFound, "", "Error metadata: %s", err.Error())
		return
	}

	contentType := metadata.ContentType
	contentLength, err := s.storage.Head(r.Context(), token, filename)
	if s.storage.IsNotExist(err) {
		s.respondError(w, http.StatusNotFound, "", "")
		return
	}
	if err != nil {
		s.respondError(w, http.StatusInternalServerError, "Could not retrieve file.", "%v", err)
		return
	}

	remainingDownloads, remainingDays := metadata.remainingLimitHeaderValues()

	w.Header().Set("Content-Type", contentType)
	w.Header().Set("Content-Length", strconv.FormatUint(contentLength, 10))
	w.Header().Set("Connection", "close")
	w.Header().Set("X-Remaining-Downloads", remainingDownloads)
	w.Header().Set("X-Remaining-Days", remainingDays)
	w.Header().Set("Vary", "Accept, Range, Referer, X-Decrypt-Password")

	if s.storage.IsRangeSupported() {
		w.Header().Set("Accept-Ranges", "bytes")
	}
}

func (s *Server) redirectToSubdirectory(w http.ResponseWriter, r *http.Request, token, filename string) bool {
	idx, err := s.loadDirIndex(r.Context(), token)
	if err != nil {
		return false
	}
	prefix := filename + "/"
	for _, f := range idx.Files {
		if strings.HasPrefix(f.Name, prefix) {
			// #nosec G710 -- token is server-generated, filename is sanitized
			http.Redirect(w, r, r.URL.Path+"/", http.StatusMovedPermanently)
			return true
		}
	}
	return false
}

func (s *Server) getHandler(w http.ResponseWriter, r *http.Request) {
	action, token, filename, ok := s.getRequestParts(w, r)
	if !ok {
		return
	}

	metadata, ok := s.getMetadataForDownload(w, r, action, token, filename)
	if !ok {
		return
	}

	password := r.Header.Get("X-Decrypt-Password")
	contentType := metadata.contentTypeForPassword(password)
	rng := metadata.rangeForRequest(s.parseRange(r), password)
	reader, contentLength, ok := s.getReaderForDownload(w, r, token, filename, rng)
	if !ok {
		return
	}
	defer storage.CloseCheck(reader)

	reader = s.handleRangeHeaders(w, reader, rng)
	disposition := s.getDisposition(action)

	var err error
	reader, err = attachDecryptionReader(reader, password)
	if err != nil {
		http.Error(w, "Could not decrypt file (wrong or missing password?)", http.StatusUnauthorized)
		return
	}

	if err := s.incrementDownloadCount(r.Context(), token, filename); err != nil {
		storage.CloseCheck(reader)
		if err.Error() == "maxDownloads expired" || err.Error() == "maxDate expired" {
			s.respondError(w, http.StatusNotFound, "", "Error metadata: %s", err.Error())
			return
		}
		s.logger.Printf("get: failed to increment download count for %s/%s: %v", token, filename, err)
		s.respondError(w, http.StatusInternalServerError, "Could not process download", "%v", err)
		return
	}

	reader, contentLength, err = s.handleDecryptionAndCompression(reader, contentLength, &metadata, password)
	if err != nil {
		s.respondError(w, http.StatusInternalServerError, "Could not decode file", "%v", err)
		return
	}
	s.setDownloadResponseHeaders(w, filename, action, disposition, contentType, contentLength, &metadata, rng)
	reader = sanitizeInlineReader(reader, disposition, contentType)

	if _, err = io.Copy(w, reader); err != nil {
		s.logger.Printf("%s", err.Error())
		http.Error(w, "Error occurred copying to output stream", http.StatusInternalServerError)
		return
	}
}

func (s *Server) getRequestParts(w http.ResponseWriter, r *http.Request) (action, token, filename string, ok bool) {
	vars := mux.Vars(r)
	action = vars["action"]
	token = vars["token"]
	filename = sanitizePath(vars["filename"])

	if err := validateTokenAndFilename(token, filename); err != nil {
		s.respondError(w, http.StatusBadRequest, err.Error(), "")
		return "", "", "", false
	}

	return action, token, filename, true
}

func (s *Server) getMetadataForDownload(w http.ResponseWriter, r *http.Request, action, token, filename string) (metadata, bool) {
	metadata, err := s.checkMetadata(r.Context(), token, filename, false)
	if err == nil {
		return metadata, true
	}
	if action == "" && s.redirectToSubdirectory(w, r, token, filename) {
		return metadata, false
	}
	s.respondError(w, http.StatusNotFound, "", "Error metadata: %s", err.Error())
	return metadata, false
}

func (metadata metadata) contentTypeForPassword(password string) string {
	// When serving a decrypted file, restore the original content type that was
	// recorded at upload time (metadata.ContentType is forced to text/plain for
	// encrypted blobs).
	if metadata.Encrypted && password != "" && metadata.DecryptedContentType != "" {
		return metadata.DecryptedContentType
	}
	return metadata.ContentType
}

func (metadata metadata) rangeForRequest(rng *storage.Range, password string) *storage.Range {
	// Range requests cannot be served over transformed content: the stored bytes
	// differ from what the client receives, so byte offsets would be meaningless.
	if metadata.Compressed || (metadata.Encrypted && password != "") {
		return nil
	}
	return rng
}

func (s *Server) getReaderForDownload(w http.ResponseWriter, r *http.Request, token, filename string, rng *storage.Range) (io.ReadCloser, uint64, bool) {
	reader, contentLength, err := s.storage.Get(r.Context(), token, filename, rng)
	if s.storage.IsNotExist(err) {
		s.respondError(w, http.StatusNotFound, "", "")
		return nil, 0, false
	}
	if err != nil {
		s.respondError(w, http.StatusInternalServerError, "Could not retrieve file.", "%v", err)
		return nil, 0, false
	}
	if rng != nil && s.storage.IsRangeSupported() && rng.ContentRange() == "" {
		storage.CloseCheck(reader)
		w.Header().Set("Content-Range", fmt.Sprintf("bytes */%d", contentLength))
		s.respondError(w, http.StatusRequestedRangeNotSatisfiable, "", "")
		return nil, 0, false
	}
	return reader, contentLength, true
}

func (s *Server) setDownloadResponseHeaders(w http.ResponseWriter, filename, action, disposition, contentType string, contentLength uint64, metadata *metadata, rng *storage.Range) {
	if action == "inline" && strings.TrimSpace(contentType) == "" {
		contentType = "text/plain; charset=utf-8"
	}

	remainingDownloads, remainingDays := metadata.remainingLimitHeaderValues()
	s.setCommonHeaders(w, filename, disposition, remainingDownloads, remainingDays)
	w.Header().Set("Vary", "Accept, Range, Referer, X-Decrypt-Password")
	w.Header().Set("Content-Type", contentType)

	if !shouldSanitizeInline(disposition, contentType) {
		w.Header().Set("Content-Length", strconv.FormatUint(contentLength, 10))
	}
	if rng != nil && rng.ContentRange() != "" {
		w.WriteHeader(http.StatusPartialContent)
	}
}

func shouldSanitizeInline(disposition, contentType string) bool {
	// Sanitizing inline HTML rewrites the body, so the stored content length no
	// longer matches what we send; let the server use chunked encoding instead.
	return disposition == "inline" && contentTypeMayContainXSS(contentType)
}

func sanitizeInlineReader(reader io.ReadCloser, disposition, contentType string) io.ReadCloser {
	if shouldSanitizeInline(disposition, contentType) {
		return io.NopCloser(bluemonday.UGCPolicy().SanitizeReader(reader))
	}
	return reader
}

func (s *Server) parseRange(r *http.Request) *storage.Range {
	if r.Header.Get("Range") != "" {
		return storage.ParseRange(r.Header.Get("Range"))
	}
	return nil
}

func (s *Server) handleRangeHeaders(w http.ResponseWriter, reader io.ReadCloser, rng *storage.Range) io.ReadCloser {
	if rng != nil {
		cr := rng.ContentRange()
		if cr != "" {
			w.Header().Set("Accept-Ranges", "bytes")
			w.Header().Set("Content-Range", cr)
			if rng.Limit > 0 {
				reader = io.NopCloser(io.LimitReader(reader, storage.SafeUint64ToInt64(rng.Limit)))
			}
		}
	}
	return reader
}

func (s *Server) getDisposition(action string) string {
	if action == "inline" {
		return "inline"
	}
	return "attachment"
}

func (s *Server) setCommonHeaders(w http.ResponseWriter, filename, disposition, remainingDownloads, remainingDays string) {
	w.Header().Set("Content-Disposition", mime.FormatMediaType(disposition, map[string]string{"filename": filename}))
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Remaining-Downloads", remainingDownloads)
	w.Header().Set("X-Remaining-Days", remainingDays)
}

func (s *Server) handleDecryptionAndCompression(reader io.ReadCloser, contentLength uint64, metadata *metadata, password string) (io.ReadCloser, uint64, error) {
	if metadata.Encrypted && len(password) > 0 {
		contentLength = storage.SafeInt64ToUint64(metadata.ContentLength)
	}

	if metadata.Compressed {
		compressionReader, err := NewCompressionReader(reader, true)
		if err != nil {
			return reader, contentLength, err
		}
		reader = compressionReader
		contentLength = storage.SafeInt64ToUint64(metadata.ContentLength)
	}

	return reader, contentLength, nil
}

func commonHeader(w http.ResponseWriter, filename string) {
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=\"%s\"", filename))
	w.Header().Set("Connection", "close")
	w.Header().Set("Cache-Control", "no-store")
}

// RedirectHandler handles redirect
func (s *Server) RedirectHandler(h http.Handler) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		forwardedHTTPS := s.trustForwardedHeaders(r) && r.Header.Get("X-Forwarded-Proto") == "https"
		shouldRedirect := s.forceHTTPS &&
			r.URL.Path != "/health.html" &&
			!strings.HasSuffix(ipAddrFromRemoteAddr(r.Host), ".onion") &&
			!forwardedHTTPS &&
			r.TLS == nil

		if shouldRedirect {
			u := s.getURL(r)
			u.Scheme = "https"
			if len(s.proxyPort) == 0 && len(s.TLSListenerString) > 0 {
				_, port, err := net.SplitHostPort(s.TLSListenerString)
				if err != nil || port == "443" {
					port = ""
				}

				if len(port) > 0 {
					u.Host = net.JoinHostPort(u.Hostname(), port)
				} else {
					u.Host = u.Hostname()
				}
			}

			// #nosec G710 -- r.Host is client-controlled; deployment must validate Host at the proxy/ingress level
			http.Redirect(w, r, u.String(), http.StatusPermanentRedirect)
			return
		}

		h.ServeHTTP(w, r)
	}
}

// LoveHandler Create a log handler for every request it receives.
func LoveHandler(h http.Handler) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("x-made-with", "<3 by DutchCoders & morawskidotmy")
		w.Header().Set("x-served-by", "Proudly served by DutchCoders & morawskidotmy")
		w.Header().Set("server", "Transfer.sh HTTP Server")
		h.ServeHTTP(w, r)
	}
}

func ipFilterHandler(h http.Handler, ipFilterOptions *IPFilterOptions, remoteIPFn func(*http.Request) string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if ipFilterOptions == nil {
			h.ServeHTTP(w, r)
		} else {
			f := newIPFilter(ipFilterOptions)
			if remoteIPFn != nil {
				f.WrapWithIPFunc(h, remoteIPFn).ServeHTTP(w, r)
			} else {
				f.Wrap(h).ServeHTTP(w, r)
			}
		}
	}
}

func securityHeadersHandler(h http.Handler) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("X-XSS-Protection", "1; mode=block")
		h.ServeHTTP(w, r)
	}
}

func (s *Server) basicAuthHandler(h http.Handler) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if s.authUser == "" && s.authPass == "" && s.authHtpasswd == "" {
			h.ServeHTTP(w, r)
			return
		}

		s.initializeAuth()

		w.Header().Set("WWW-Authenticate", "Basic realm=\"Restricted\"")

		username, password, authOK := r.BasicAuth()
		if s.isAuthorized(username, password, authOK, r) {
			h.ServeHTTP(w, r)
			return
		}

		http.Error(w, "Not authorized", http.StatusUnauthorized)
	}
}

// requireAuthHandler wraps a handler and requires authentication to be configured.
// Unlike basicAuthHandler, this rejects requests with 503 if no auth is configured,
// preventing unauthenticated access to sensitive endpoints like /scan and /virustotal.
func (s *Server) requireAuthHandler(h http.Handler) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if s.authUser == "" && s.authPass == "" && s.authHtpasswd == "" && s.authIPFilterOptions == nil {
			http.Error(w, "Authentication required for this endpoint", http.StatusServiceUnavailable)
			return
		}

		s.initializeAuth()

		w.Header().Set("WWW-Authenticate", "Basic realm=\"Restricted\"")

		username, password, authOK := r.BasicAuth()
		if s.isAuthorized(username, password, authOK, r) {
			h.ServeHTTP(w, r)
			return
		}

		http.Error(w, "Not authorized", http.StatusUnauthorized)
	}
}

func (s *Server) initializeAuth() {
	s.authInitMutex.Lock()
	defer s.authInitMutex.Unlock()

	if s.htpasswdFile == nil && s.authHtpasswd != "" {
		htpasswdFile, err := htpasswd.New(s.authHtpasswd, htpasswd.DefaultSystems, nil)
		if err == nil {
			s.htpasswdFile = htpasswdFile
		}
	}

	if s.authIPFilter == nil && s.authIPFilterOptions != nil {
		s.authIPFilter = newIPFilter(s.authIPFilterOptions)
	}
}

func (s *Server) isAuthorized(username, password string, authOK bool, r *http.Request) bool {
	authorized := false

	if s.authIPFilter != nil {
		remoteIP := s.remoteIP(r)
		authorized = s.authIPFilter.Allowed(remoteIP)
	}

	if !authorized && authOK && s.authUser != "" && s.authPass != "" {
		if subtle.ConstantTimeCompare([]byte(username), []byte(s.authUser)) == 1 &&
			subtle.ConstantTimeCompare([]byte(password), []byte(s.authPass)) == 1 {
			authorized = true
		}
	}

	if !authorized && s.htpasswdFile != nil {
		authorized = s.htpasswdFile.Match(username, password)
	}

	return authorized
}
