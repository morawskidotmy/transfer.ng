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

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/ProtonMail/go-crypto/openpgp/armor"
	"github.com/ProtonMail/go-crypto/openpgp/packet"
	"github.com/ProtonMail/gopenpgp/v2/constants"
	"github.com/morawskidotmy/transfer.ng/server/storage"
	"github.com/tg123/go-htpasswd"
	"github.com/tomasen/realip"

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
const maxTokenLength = 200

func stripPrefix(p string) string {
	return strings.TrimPrefix(p, web.Prefix+"/")
}

func initTextTemplates() *textTemplate.Template {
	templateMap := textTemplate.FuncMap{"format": formatNumber}
	var templates = textTemplate.New("").Funcs(templateMap)
	return templates
}

func initHTMLTemplates() *htmlTemplate.Template {
	templateMap := htmlTemplate.FuncMap{"format": formatNumber}
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

func canContainsXSS(contentType string) bool {
	switch {
	case strings.Contains(contentType, "cache-manifest"):
		fallthrough
	case strings.Contains(contentType, "html"):
		fallthrough
	case strings.Contains(contentType, "rdf"):
		fallthrough
	case strings.Contains(contentType, "vtt"):
		fallthrough
	case strings.Contains(contentType, "xml"):
		fallthrough
	case strings.Contains(contentType, "xsl"):
		return true
	case strings.Contains(contentType, "x-mixed-replace"):
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
		return htmlTemplate.HTML(output), "download.markdown.html", nil
	}
	if strings.HasPrefix(contentType, "text/plain") {
		return htmlTemplate.HTML(fmt.Sprintf("<pre>%s</pre>", html.EscapeString(string(data)))), "download.markdown.html", nil
	}
	return "", "download.sandbox.html", nil
}

func isBotUserAgent(userAgent string) bool {
	ua := strings.ToLower(userAgent)
	return strings.Contains(ua, "whatsapp") ||
		strings.Contains(ua, "discordbot") ||
		strings.Contains(ua, "telegrambot") ||
		strings.Contains(ua, "twitterbot") ||
		strings.Contains(ua, "facebookexternalhit") ||
		strings.Contains(ua, "linkedinbot") ||
		strings.Contains(ua, "slackbot") ||
		strings.Contains(ua, "embedly")
}

func (s *Server) previewHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Vary", "Accept, Range, Referer, X-Decrypt-Password, User-Agent")

	vars := mux.Vars(r)
	token := vars["token"]
	filename := vars["filename"]

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

	if !metadata.Compressed && strings.HasPrefix(contentType, "text/") {
		content, templatePath, err = s.getTextContent(r.Context(), token, filename, contentType)
		if err != nil {
			s.respondError(w, http.StatusInternalServerError, "Could not retrieve file.", "preview: %v", err)
			return
		}
	}

	relativeURL, _ := url.Parse(path.Join(s.proxyPath, token, filename))
	resolvedURL := resolveURL(r, relativeURL, s.proxyPort)
	relativeURLGet, _ := url.Parse(path.Join(s.proxyPath, getPathPart, token, filename))
	resolvedURLGet := resolveURL(r, relativeURLGet, s.proxyPort)

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
		token,
		getURL(r, s.proxyPort).Host,
		resolveWebAddress(r, s.proxyPath, s.proxyPort),
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

	hostname := getURL(r, s.proxyPort).Host
	webAddress := resolveWebAddress(r, s.proxyPath, s.proxyPort)

	maxUploadSize := ""
	if s.maxUploadSize > 0 {
		maxUploadSize = formatSize(s.maxUploadSize)
	}

	purgeTime := ""
	if s.purgeDays > 0 {
		purgeTime = formatDurationDays(s.purgeDays)
	}

	tokenA, _ := token(s.randomTokenLength)
	tokenB, _ := token(s.randomTokenLength)
	data := struct {
		Hostname      string
		WebAddress    string
		EmailContact  string
		GAKey         string
		UserVoiceKey  string
		PurgeTime     string
		MaxUploadSize string
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
		tokenA,
		tokenB,
	}

	w.Header().Set("Vary", "Accept")
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
	http.Error(w, http.StatusText(404), 404)
}

func sanitize(fileName string) string {
	fileName = strings.ReplaceAll(fileName, "\\", "/")
	fileName = strings.ReplaceAll(fileName, "..", "")
	fileName = strings.ReplaceAll(fileName, ":", "")

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
	newName, _, err := transform.String(t, fileName)
	if err != nil {
		newName = path.Base(fileName)
	} else {
		newName = path.Base(newName)
	}

	newName = strings.TrimLeft(newName, ".")

	if len(newName) == 0 {
		newName = "_"
	}

	if len(newName) > maxFilenameLength {
		newName = newName[:maxFilenameLength]
	}

	return newName
}

func validateTokenAndFilename(token, filename string) error {
	if len(token) > maxTokenLength {
		return fmt.Errorf("token too long")
	}
	if len(filename) > maxFilenameLength {
		return fmt.Errorf("filename too long")
	}
	return nil
}

func (s *Server) postHandler(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseMultipartForm(_24K); nil != err {
		s.logger.Printf("%s", err.Error())
		http.Error(w, "Error occurred copying to output stream", http.StatusInternalServerError)
		return
	}

	uploadToken, tokenErr := token(s.randomTokenLength)
	if tokenErr != nil {
		s.logger.Printf("%s", tokenErr.Error())
		http.Error(w, "Error occurred generating token", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/plain")

	var responseBody strings.Builder

	for _, fHeaders := range r.MultipartForm.File {
		for _, fHeader := range fHeaders {
			if !s.processUploadFile(w, r, uploadToken, fHeader, &responseBody) {
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

func (s *Server) processUploadFile(w http.ResponseWriter, r *http.Request, uploadToken string, fHeader *multipart.FileHeader, responseBody *strings.Builder) bool {
	filename := sanitize(fHeader.Filename)
	contentType := mime.TypeByExtension(filepath.Ext(fHeader.Filename))

	f, err := fHeader.Open()
	if err != nil {
		s.logger.Printf("upload: failed to open file: %v", err)
		http.Error(w, "Could not process upload.", http.StatusInternalServerError)
		return false
	}

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

	if s.performClamavPrescan {
		if !s.runVirusScan(w, file.Name()) {
			return false
		}
	}

	if !s.saveFileWithMetadata(w, r, uploadToken, filename, contentType, contentLength, file) {
		return false
	}

	s.addResponseURL(w, r, uploadToken, filename, responseBody)
	return true
}

func (s *Server) copyAndValidateFile(w http.ResponseWriter, file *os.File, f io.Reader) (int64, error) {
	n, err := io.Copy(file, f)
	if err != nil {
		s.logger.Printf("upload: failed to copy file: %v", err)
		http.Error(w, "Could not process upload.", http.StatusInternalServerError)
		return 0, err
	}

	_, err = file.Seek(0, io.SeekStart)
	if err != nil {
		s.logger.Printf("upload: failed to seek file: %v", err)
		return 0, err
	}

	if s.maxUploadSize > 0 && n > s.maxUploadSize {
		s.logger.Print("Entity too large")
		http.Error(w, http.StatusText(http.StatusRequestEntityTooLarge), http.StatusRequestEntityTooLarge)
		return 0, err
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

func (s *Server) saveFileWithMetadata(w http.ResponseWriter, r *http.Request, uploadToken, filename, contentType string, contentLength int64, file *os.File) bool {
	metadata := metadataForRequest(contentType, contentLength, s.randomTokenLength, r)

	buffer := &bytes.Buffer{}
	if err := json.NewEncoder(buffer).Encode(metadata); err != nil {
		s.logger.Printf("%s", err.Error())
		http.Error(w, "Could not encode metadata", http.StatusInternalServerError)
		return false
	}

	if err := s.storage.Put(r.Context(), uploadToken, fmt.Sprintf("%s.metadata", filename), buffer, "text/json", uint64(buffer.Len())); err != nil {
		s.logger.Printf("%s", err.Error())
		http.Error(w, "Could not save metadata", http.StatusInternalServerError)
		return false
	}

	s.logger.Printf("Uploading %s %s %d %s", uploadToken, filename, contentLength, contentType)

	reader, err := attachEncryptionReader(file, r.Header.Get("X-Encrypt-Password"))
	if err != nil {
		http.Error(w, "Could not crypt file", http.StatusInternalServerError)
		return false
	}

	if err = s.storage.Put(r.Context(), uploadToken, filename, reader, contentType, uint64(contentLength)); err != nil {
		s.logger.Printf("upload: backend storage error: %v", err)
		http.Error(w, "Could not save file.", http.StatusInternalServerError)
		return false
	}

	return true
}

func (s *Server) addResponseURL(w http.ResponseWriter, r *http.Request, uploadToken, filename string, responseBody *strings.Builder) {
	escapedFilename := url.PathEscape(filename)
	metadata := metadataForRequest(mime.TypeByExtension(filepath.Ext(filename)), 0, s.randomTokenLength, r)

	relativeURL, _ := url.Parse(path.Join(s.proxyPath, uploadToken, escapedFilename))
	deleteURL, _ := url.Parse(path.Join(s.proxyPath, uploadToken, escapedFilename, metadata.DeletionToken))
	w.Header().Add("X-Url-Delete", resolveURL(r, deleteURL, s.proxyPort))
	responseBody.WriteString(getURL(r, s.proxyPort).ResolveReference(relativeURL).String())
	responseBody.WriteString("\n")
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

func metadataForRequest(contentType string, contentLength int64, randomTokenLength int, r *http.Request) metadata {
	delToken1, _ := token(randomTokenLength)
	delToken2, _ := token(randomTokenLength)
	metadata := metadata{
		ContentType:   strings.ToLower(contentType),
		ContentLength: contentLength,
		MaxDate:       time.Time{},
		Downloads:     0,
		MaxDownloads:  -1,
		DeletionToken: delToken1 + delToken2,
	}

	if v := r.Header.Get("Max-Downloads"); v == "" {
	} else if v, err := strconv.Atoi(v); err != nil {
	} else {
		metadata.MaxDownloads = v
	}

	if v := r.Header.Get("Max-Days"); v == "" {
	} else if v, err := strconv.Atoi(v); err != nil {
	} else {
		metadata.MaxDate = time.Now().Add(time.Hour * 24 * time.Duration(v))
	}

	if password := r.Header.Get("X-Encrypt-Password"); password != "" {
		metadata.Encrypted = true
		metadata.ContentType = "text/plain; charset=utf-8"
		metadata.DecryptedContentType = contentType
	} else {
		metadata.Encrypted = false
	}

	return metadata
}

func (s *Server) putHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	filename := sanitize(vars["filename"])

	defer storage.CloseCheck(r.Body)

	reader := r.Body
	contentLength := r.ContentLength

	if contentLength < 1 || s.performClamavPrescan {
		file, err := os.CreateTemp(s.tempPath, "transfer-")
		if err != nil {
			s.logger.Printf("put: failed to create temp file: %v", err)
			http.Error(w, "Could not process upload.", http.StatusInternalServerError)
			return
		}
		defer s.cleanTmpFile(file)

		var bufferErr error
		contentLength, bufferErr = s.bufferFileToTemp(w, file, r.Body)
		if bufferErr != nil {
			return
		}

		if s.performClamavPrescan && !s.runVirusScan(w, file.Name()) {
			return
		}

		reader = file
	}

	if !s.validateUploadSize(w, contentLength) {
		return
	}

	contentType := mime.TypeByExtension(filepath.Ext(vars["filename"]))
	putToken, err := token(s.randomTokenLength)
	if err != nil {
		s.logger.Printf("%s", err.Error())
		http.Error(w, "Error occurred generating token", http.StatusInternalServerError)
		return
	}

	if !s.processPutUpload(w, r, putToken, filename, contentType, contentLength, reader) {
		return
	}

	s.writePutResponse(w, r, putToken, filename)
}

func (s *Server) bufferFileToTemp(w http.ResponseWriter, file *os.File, requestBody io.Reader) (int64, error) {
	n, err := io.Copy(file, requestBody)
	if err != nil {
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
	if s.maxUploadSize > 0 && contentLength > s.maxUploadSize {
		s.logger.Print("Entity too large")
		http.Error(w, http.StatusText(http.StatusRequestEntityTooLarge), http.StatusRequestEntityTooLarge)
		return false
	}

	if contentLength == 0 {
		s.logger.Print("Empty content-length")
		http.Error(w, "Could not upload empty file", http.StatusBadRequest)
		return false
	}

	return true
}

func (s *Server) processPutUpload(w http.ResponseWriter, r *http.Request, putToken, filename, contentType string, contentLength int64, reader io.ReadCloser) bool {
	metadata := metadataForRequest(contentType, contentLength, s.randomTokenLength, r)

	shouldCompress := s.compressionThreshold > 0 && contentLength > s.compressionThreshold
	if shouldCompress {
		metadata.Compressed = true
		s.logger.Printf("File %s will be compressed (size: %d bytes)", filename, contentLength)
	}

	if !s.saveMetadata(w, r, putToken, filename, metadata) {
		return false
	}

	s.logger.Printf("Uploading %s %s %d %s", putToken, filename, contentLength, contentType)

	encryptedReader, err := attachEncryptionReader(reader, r.Header.Get("X-Encrypt-Password"))
	if err != nil {
		http.Error(w, "Could not crypt file", http.StatusInternalServerError)
		return false
	}

	finalReader := encryptedReader
	finalLength := contentLength

	if shouldCompress {
		if !s.compressAndUpdate(w, &finalReader, &finalLength) {
			return false
		}
	}

	if err = s.storage.Put(r.Context(), putToken, filename, finalReader, contentType, uint64(finalLength)); err != nil {
		s.logger.Printf("Error putting new file: %s", err.Error())
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

	if err := s.storage.Put(r.Context(), putToken, fmt.Sprintf("%s.metadata", filename), buffer, "text/json", uint64(buffer.Len())); err != nil {
		s.logger.Printf("%s", err.Error())
		http.Error(w, "Could not save metadata", http.StatusInternalServerError)
		return false
	}

	return true
}

func (s *Server) compressAndUpdate(w http.ResponseWriter, reader *io.ReadCloser, contentLength *int64) bool {
	compressedBuffer := &bytes.Buffer{}
	_, err := CompressStream(compressedBuffer, *reader)
	if err != nil {
		s.logger.Printf("Error compressing file: %s", err.Error())
		http.Error(w, "Could not compress file", http.StatusInternalServerError)
		return false
	}
	*reader = io.NopCloser(compressedBuffer)
	*contentLength = int64(compressedBuffer.Len())
	return true
}

func (s *Server) writePutResponse(w http.ResponseWriter, r *http.Request, putToken, filename string) {
	metadata := metadataForRequest(mime.TypeByExtension(filepath.Ext(filename)), 0, s.randomTokenLength, r)

	w.Header().Set("Content-Type", "text/plain")
	escapedFilename := url.PathEscape(filename)
	relativeURL, _ := url.Parse(path.Join(s.proxyPath, putToken, escapedFilename))
	deleteURL, _ := url.Parse(path.Join(s.proxyPath, putToken, escapedFilename, metadata.DeletionToken))

	w.Header().Set("X-Url-Delete", resolveURL(r, deleteURL, s.proxyPort))
	_, _ = w.Write([]byte(resolveURL(r, relativeURL, s.proxyPort)))
}

func resolveURL(r *http.Request, u *url.URL, proxyPort string) string {
	r.URL.Path = ""

	return getURL(r, proxyPort).ResolveReference(u).String()
}

func resolveKey(key, proxyPath string) string {
	key = strings.TrimPrefix(key, "/")

	key = strings.TrimPrefix(key, proxyPath)

	key = strings.Replace(key, "\\", "/", -1)

	return key
}

func resolveWebAddress(r *http.Request, proxyPath string, proxyPort string) string {
	rUrl := getURL(r, proxyPort)

	var webAddress string

	if len(proxyPath) == 0 {
		webAddress = fmt.Sprintf("%s://%s/",
			rUrl.ResolveReference(rUrl).Scheme,
			rUrl.ResolveReference(rUrl).Host)
	} else {
		webAddress = fmt.Sprintf("%s://%s/%s",
			rUrl.ResolveReference(rUrl).Scheme,
			rUrl.ResolveReference(rUrl).Host,
			strings.TrimPrefix(proxyPath, "/"))
	}

	return webAddress
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

func getURL(r *http.Request, proxyPort string) *url.URL {
	u := cloneURL(r.URL)

	if r.TLS != nil {
		u.Scheme = "https"
	} else if proto := r.Header.Get("X-Forwarded-Proto"); proto != "" {
		u.Scheme = proto
	} else {
		u.Scheme = "http"
	}

	host, port, err := net.SplitHostPort(r.Host)
	if err != nil {
		host = r.Host
		port = ""
	}

	p := idna.New(idna.ValidateForRegistration())
	var hostFromPunycode string
	hostFromPunycode, err = p.ToUnicode(host)
	if err == nil {
		host = hostFromPunycode
	}

	if len(proxyPort) != 0 {
		port = proxyPort
	}

	if len(port) == 0 {
		u.Host = host
	} else {
		if port == "80" && u.Scheme == "http" {
			u.Host = host
		} else if port == "443" && u.Scheme == "https" {
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

	lock, _ := s.locks.LoadOrStore(key, &sync.Mutex{})

	lock.(*sync.Mutex).Unlock()
}

func (s *Server) checkMetadata(ctx context.Context, token, filename string, increaseDownload bool) (metadata, error) {
	s.lock(token, filename)
	defer s.unlock(token, filename)

	var metadata metadata

	r, _, err := s.storage.Get(ctx, token, fmt.Sprintf("%s.metadata", filename), nil)
	if err != nil {
		return metadata, err
	}
	defer storage.CloseCheck(r)

	if err := json.NewDecoder(r).Decode(&metadata); err != nil {
		return metadata, err
	} else if metadata.MaxDownloads != -1 && metadata.Downloads >= metadata.MaxDownloads {
		return metadata, errors.New("maxDownloads expired")
	} else if !metadata.MaxDate.IsZero() && time.Now().After(metadata.MaxDate) {
		return metadata, errors.New("maxDate expired")
	} else if metadata.MaxDownloads != -1 && increaseDownload {
		metadata.Downloads++

		buffer := &bytes.Buffer{}
		if err := json.NewEncoder(buffer).Encode(metadata); err != nil {
			return metadata, errors.New("could not encode metadata")
		} else if err := s.storage.Put(ctx, token, fmt.Sprintf("%s.metadata", filename), buffer, "text/json", uint64(buffer.Len())); err != nil {
			return metadata, errors.New("could not save metadata")
		}
	}

	return metadata, nil
}

func (s *Server) checkDeletionToken(ctx context.Context, deletionToken, token, filename string) error {
	s.lock(token, filename)
	defer s.unlock(token, filename)

	var metadata metadata

	r, _, err := s.storage.Get(ctx, token, fmt.Sprintf("%s.metadata", filename), nil)
	if s.storage.IsNotExist(err) {
		return errors.New("metadata doesn't exist")
	} else if err != nil {
		return err
	}
	defer storage.CloseCheck(r)

	if err := json.NewDecoder(r).Decode(&metadata); err != nil {
		return err
	} else if subtle.ConstantTimeCompare([]byte(metadata.DeletionToken), []byte(deletionToken)) != 1 {
		return errors.New("deletion token doesn't match")
	}

	return nil
}

func (s *Server) purgeHandler() {
	ticker := time.NewTicker(s.purgeInterval)
	go func() {
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
	}()
}

func (s *Server) deleteHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)

	token := vars["token"]
	filename := vars["filename"]
	deletionToken := vars["deletionToken"]

	if deletionToken == "" {
		deletionToken = r.Header.Get("X-Deletion-Token")
	}

	if deletionToken == "" {
		s.respondError(w, http.StatusNotFound, "", "delete: missing deletion token")
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
		specs = append(specs, archiveFileSpec{
			token:    parts[0],
			filename: sanitize(parts[1]),
		})
	}
	return specs, nil
}

func (s *Server) zipHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)

	specs, err := s.parseArchiveFiles(vars["files"])
	if err != nil {
		s.respondError(w, http.StatusBadRequest, err.Error(), "")
		return
	}

	zipfilename := fmt.Sprintf("transfersh-%d.zip", time.Now().UnixNano())

	w.Header().Set("Content-Type", "application/zip")
	commonHeader(w, zipfilename)

	zw := zip.NewWriter(w)

	for _, spec := range specs {
		if _, err := s.checkMetadata(r.Context(), spec.token, spec.filename, true); err != nil {
			s.logger.Printf("Error metadata: %s", err.Error())
			continue
		}

		reader, _, err := s.storage.Get(r.Context(), spec.token, spec.filename, nil)
		if err != nil {
			if s.storage.IsNotExist(err) {
				s.respondError(w, http.StatusNotFound, "File not found", "")
				return
			}
			s.respondError(w, http.StatusInternalServerError, "Could not retrieve file.", "%v", err)
			return
		}

		header := &zip.FileHeader{
			Name:     spec.filename,
			Method:   zip.Store,
			Modified: time.Now().UTC(),
		}

		fw, err := zw.CreateHeader(header)
		if err != nil {
			storage.CloseCheck(reader)
			s.respondError(w, http.StatusInternalServerError, "", "%v", err)
			return
		}

		_, err = io.Copy(fw, reader)
		storage.CloseCheck(reader)
		if err != nil {
			s.respondError(w, http.StatusInternalServerError, "", "%v", err)
			return
		}
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

	tarfilename := fmt.Sprintf("transfersh-%d.tar.gz", time.Now().UnixNano())

	w.Header().Set("Content-Type", "application/x-gzip")
	commonHeader(w, tarfilename)

	gw := gzip.NewWriter(w)
	defer storage.CloseCheck(gw)

	zw := tar.NewWriter(gw)
	defer storage.CloseCheck(zw)

	for _, spec := range specs {
		if _, err := s.checkMetadata(r.Context(), spec.token, spec.filename, true); err != nil {
			s.logger.Printf("Error metadata: %s", err.Error())
			continue
		}

		reader, contentLength, err := s.storage.Get(r.Context(), spec.token, spec.filename, nil)
		if err != nil {
			if s.storage.IsNotExist(err) {
				s.respondError(w, http.StatusNotFound, "File not found", "")
				return
			}
			s.respondError(w, http.StatusInternalServerError, "Could not retrieve file.", "%v", err)
			return
		}

		header := &tar.Header{
			Name: spec.filename,
			Size: int64(contentLength),
		}

		err = zw.WriteHeader(header)
		if err != nil {
			storage.CloseCheck(reader)
			s.respondError(w, http.StatusInternalServerError, "", "%v", err)
			return
		}

		_, err = io.Copy(zw, reader)
		storage.CloseCheck(reader)
		if err != nil {
			s.respondError(w, http.StatusInternalServerError, "", "%v", err)
			return
		}
	}
}

func (s *Server) tarHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)

	specs, err := s.parseArchiveFiles(vars["files"])
	if err != nil {
		s.respondError(w, http.StatusBadRequest, err.Error(), "")
		return
	}

	tarfilename := fmt.Sprintf("transfersh-%d.tar", time.Now().UnixNano())

	w.Header().Set("Content-Type", "application/x-tar")
	commonHeader(w, tarfilename)

	zw := tar.NewWriter(w)
	defer storage.CloseCheck(zw)

	for _, spec := range specs {
		if _, err := s.checkMetadata(r.Context(), spec.token, spec.filename, true); err != nil {
			s.logger.Printf("Error metadata: %s", err.Error())
			continue
		}

		reader, contentLength, err := s.storage.Get(r.Context(), spec.token, spec.filename, nil)
		if err != nil {
			if s.storage.IsNotExist(err) {
				s.respondError(w, http.StatusNotFound, "File not found", "")
				return
			}
			s.respondError(w, http.StatusInternalServerError, "Could not retrieve file.", "%v", err)
			return
		}

		header := &tar.Header{
			Name: spec.filename,
			Size: int64(contentLength),
		}

		err = zw.WriteHeader(header)
		if err != nil {
			storage.CloseCheck(reader)
			s.respondError(w, http.StatusInternalServerError, "", "%v", err)
			return
		}

		_, err = io.Copy(zw, reader)
		storage.CloseCheck(reader)
		if err != nil {
			s.respondError(w, http.StatusInternalServerError, "", "%v", err)
			return
		}
	}
}

func (s *Server) headHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)

	token := vars["token"]
	filename := vars["filename"]

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
	} else if err != nil {
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

func (s *Server) getHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)

	action := vars["action"]
	token := vars["token"]
	filename := vars["filename"]

	if err := validateTokenAndFilename(token, filename); err != nil {
		s.respondError(w, http.StatusBadRequest, err.Error(), "")
		return
	}

	metadata, err := s.checkMetadata(r.Context(), token, filename, true)
	if err != nil {
		s.respondError(w, http.StatusNotFound, "", "Error metadata: %s", err.Error())
		return
	}

	rng := s.parseRange(r)
	contentType := metadata.ContentType

	reader, contentLength, err := s.storage.Get(r.Context(), token, filename, rng)
	if s.storage.IsNotExist(err) {
		s.respondError(w, http.StatusNotFound, "", "")
		return
	} else if err != nil {
		s.respondError(w, http.StatusInternalServerError, "Could not retrieve file.", "%v", err)
		return
	}
	defer storage.CloseCheck(reader)

	reader = s.handleRangeHeaders(w, reader, rng)

	disposition := s.getDisposition(action, contentType)

	if action == "inline" && strings.TrimSpace(contentType) == "" {
		contentType = "text/plain; charset=utf-8"
	}

	remainingDownloads, remainingDays := metadata.remainingLimitHeaderValues()
	s.setCommonHeaders(w, filename, disposition, remainingDownloads, remainingDays)

	password := r.Header.Get("X-Decrypt-Password")
	reader, err = attachDecryptionReader(reader, password)
	if err != nil {
		http.Error(w, "Could not decrypt file", http.StatusInternalServerError)
		return
	}

	reader, contentLength = s.handleDecryptionAndCompression(reader, contentLength, &metadata, password)

	w.Header().Set("Content-Type", contentType)
	w.Header().Set("Content-Length", strconv.FormatUint(contentLength, 10))
	w.Header().Set("Vary", "Accept, Range, Referer, X-Decrypt-Password")

	if rng != nil && rng.ContentRange() != "" {
		w.WriteHeader(http.StatusPartialContent)
	}

	if disposition == "inline" && canContainsXSS(contentType) {
		reader = io.NopCloser(bluemonday.UGCPolicy().SanitizeReader(reader))
	}

	if _, err = io.Copy(w, reader); err != nil {
		s.logger.Printf("%s", err.Error())
		http.Error(w, "Error occurred copying to output stream", http.StatusInternalServerError)
		return
	}
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
				reader = io.NopCloser(io.LimitReader(reader, int64(rng.Limit)))
			}
		}
	}
	return reader
}

func (s *Server) getDisposition(action, contentType string) string {
	if action == "inline" {
		return "inline"
	}
	return "attachment"
}

func (s *Server) setCommonHeaders(w http.ResponseWriter, filename, disposition, remainingDownloads, remainingDays string) {
	w.Header().Set("Content-Disposition", fmt.Sprintf(`%s; filename="%s"`, disposition, filename))
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Remaining-Downloads", remainingDownloads)
	w.Header().Set("X-Remaining-Days", remainingDays)
}

func (s *Server) handleDecryptionAndCompression(reader io.ReadCloser, contentLength uint64, metadata *metadata, password string) (io.ReadCloser, uint64) {
	if metadata.Encrypted && len(password) > 0 {
		contentLength = uint64(metadata.ContentLength)
	}

	if metadata.Compressed {
		compressionReader, err := NewCompressionReader(reader, true)
		if err != nil {
			return reader, contentLength
		}
		reader = compressionReader
		contentLength = uint64(metadata.ContentLength)
	}

	return reader, contentLength
}

func commonHeader(w http.ResponseWriter, filename string) {
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=\"%s\"", filename))
	w.Header().Set("Connection", "close")
	w.Header().Set("Cache-Control", "no-store")
}

// RedirectHandler handles redirect
func (s *Server) RedirectHandler(h http.Handler) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !s.forceHTTPS {
			// we don't want to enforce https
		} else if r.URL.Path == "/health.html" {
			// health check url won't redirect
		} else if strings.HasSuffix(ipAddrFromRemoteAddr(r.Host), ".onion") {
			// .onion addresses cannot get a valid certificate, so don't redirect
		} else if r.Header.Get("X-Forwarded-Proto") == "https" {
		} else if r.TLS != nil {
		} else {
			u := getURL(r, s.proxyPort)
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

func ipFilterHandler(h http.Handler, ipFilterOptions *IPFilterOptions) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if ipFilterOptions == nil {
			h.ServeHTTP(w, r)
		} else {
			WrapIPFilter(h, ipFilterOptions).ServeHTTP(w, r)
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
		remoteIP := realip.FromRequest(r)
		authorized = s.authIPFilter.Allowed(remoteIP)
	}

	if !authorized && authOK {
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
