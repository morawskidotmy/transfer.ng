package server

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"path"
	"strconv"
	"strings"
	"time"

	"github.com/gorilla/mux"
	"github.com/morawskidotmy/transfer.ng/server/storage"
)

// dirIndexName is the reserved object name that stores the directory index for a token.
const dirIndexName = ".dir.json"

// reservedFilenames contains filenames that cannot be uploaded as they conflict
// with internal directory metadata.
var reservedFilenames = map[string]bool{
	dirIndexName: true,
}

// fileEntry represents a file in a directory with its size.
type fileEntry struct {
	Name     string
	Size     int64
	Modified time.Time
}

// dirIndex describes a directory (token) and the files it contains.
//
// A directory groups multiple files under a single token, like a folder.
// Every file inside is reachable through its own direct link
// (/{token}/{filename}) and the directory itself can be listed at /{token}/.
//
// UploadToken is a reusable write-secret. Anyone who has it can add more files
// to the directory from anywhere using a plain curl command and the
// X-Upload-Token header. This lets you upload files to the same directory from
// different machines without exposing your other credentials.
type dirIndex struct {
	UploadToken string      `json:"uploadToken"`
	Created     time.Time   `json:"created"`
	Files       []fileEntry `json:"files"`
	TotalSize   int64       `json:"totalSize"`
	SizeKnown   bool        `json:"sizeKnown"`
}

// makeUploadToken generates a directory write-secret.
func (s *Server) makeUploadToken() (string, error) {
	a, err := token(s.randomTokenLength)
	if err != nil {
		return "", err
	}
	b, err := token(s.randomTokenLength)
	if err != nil {
		return "", err
	}
	return a + b, nil
}

func (s *Server) loadDirIndex(ctx context.Context, dirToken string) (dirIndex, error) {
	var idx dirIndex

	r, _, err := s.storage.Get(ctx, dirToken, dirIndexName, nil)
	if err != nil {
		return idx, err
	}
	defer storage.CloseCheck(r)

	if err := json.NewDecoder(r).Decode(&idx); err != nil {
		return idx, err
	}

	if !idx.SizeKnown && len(idx.Files) > 0 {
		idx.TotalSize = s.recalculateDirSize(ctx, dirToken, idx.Files)
		idx.SizeKnown = true
		if saveErr := s.saveDirIndex(ctx, dirToken, idx); saveErr != nil {
			s.logger.Printf("directory: failed to save recalculated size for %s: %v", dirToken, saveErr)
		}
	}

	return idx, nil
}

// recalculateDirSize recalculates the total size of files in a directory
// by checking the size of each file in storage.
func (s *Server) recalculateDirSize(ctx context.Context, dirToken string, files []fileEntry) int64 {
	var totalSize int64
	for _, entry := range files {
		if entry.Size > 0 {
			totalSize += entry.Size
			continue
		}
		// Legacy entry without size, check storage
		if size, err := s.storage.Head(ctx, dirToken, entry.Name); err == nil {
			totalSize += storage.SafeUint64ToInt64(size)
		}
	}
	return totalSize
}

func (s *Server) saveDirIndex(ctx context.Context, dirToken string, idx dirIndex) error {
	buffer := &bytes.Buffer{}
	if err := json.NewEncoder(buffer).Encode(idx); err != nil {
		return err
	}
	return s.storage.Put(ctx, dirToken, dirIndexName, buffer, "text/json", storage.SafeIntToUint64(buffer.Len()))
}

// createDirectory creates a new, empty directory and returns its token and
// write-secret (upload token).
func (s *Server) createDirectory(ctx context.Context) (dirToken, uploadToken string, err error) {
	dirToken, err = token(s.randomTokenLength)
	if err != nil {
		return "", "", err
	}

	uploadToken, err = s.makeUploadToken()
	if err != nil {
		return "", "", err
	}

	idx := dirIndex{
		UploadToken: uploadToken,
		Created:     time.Now(),
		Files:       []fileEntry{},
		TotalSize:   0,
		SizeKnown:   true,
	}

	if err := s.saveDirIndex(ctx, dirToken, idx); err != nil {
		return "", "", err
	}

	return dirToken, uploadToken, nil
}

// registerFileInDir records filename as a member of the directory identified by
// dirToken. If no index exists yet (e.g. a legacy upload) one is created
// without an upload token so the directory is still listable.
func (s *Server) registerFileInDir(ctx context.Context, dirToken, filename string, fileSize int64) error {
	s.lock(dirToken, dirIndexName)
	defer s.unlock(dirToken, dirIndexName)
	now := time.Now()

	idx, err := s.loadDirIndex(ctx, dirToken)
	if err != nil {
		if !s.storage.IsNotExist(err) {
			return err
		}
		idx = dirIndex{Created: time.Now()}
	}

	if s.maxDirSize > 0 && fileSize > s.maxDirSize {
		return fmt.Errorf("file size exceeds directory size limit (max %d bytes)", s.maxDirSize)
	}

	files := idx.Files[:0]
	for _, f := range idx.Files {
		if f.Name == filename {
			idx.TotalSize -= f.Size
			continue
		}
		files = append(files, f)
	}
	idx.Files = files

	if s.maxDirFiles > 0 && len(idx.Files) >= s.maxDirFiles {
		return fmt.Errorf("directory file count limit exceeded (max %d files)", s.maxDirFiles)
	}

	idx.Files = append(idx.Files, fileEntry{Name: filename, Size: fileSize, Modified: now})
	idx.TotalSize += fileSize
	if err := s.pruneDirToSize(ctx, dirToken, &idx, filename); err != nil {
		return err
	}
	return s.saveDirIndex(ctx, dirToken, idx)
}

func (s *Server) pruneDirToSize(ctx context.Context, dirToken string, idx *dirIndex, protectedFilename string) error {
	if s.maxDirSize <= 0 {
		return nil
	}

	for idx.TotalSize > s.maxDirSize {
		oldest := -1
		for i, f := range idx.Files {
			if f.Name == protectedFilename {
				continue
			}
			if oldest == -1 || fileEntryOlder(f, idx.Files[oldest]) {
				oldest = i
			}
		}
		if oldest == -1 {
			return fmt.Errorf("directory size limit exceeded (max %d bytes)", s.maxDirSize)
		}

		entry := idx.Files[oldest]
		if err := s.deleteDirFileObjects(ctx, dirToken, entry.Name); err != nil {
			if saveErr := s.saveDirIndex(ctx, dirToken, removeFileFromDirIndex(idx, protectedFilename)); saveErr != nil {
				s.logger.Printf("directory: failed to save partially pruned index for %s: %v", dirToken, saveErr)
			}
			return err
		}
		idx.TotalSize -= entry.Size
		idx.Files = append(idx.Files[:oldest], idx.Files[oldest+1:]...)
		s.logger.Printf("directory: pruned %s/%s to enforce max directory size", dirToken, entry.Name)
	}

	return nil
}

func removeFileFromDirIndex(idx *dirIndex, filename string) dirIndex {
	clone := *idx
	clone.Files = make([]fileEntry, 0, len(idx.Files))
	for _, f := range idx.Files {
		if f.Name == filename {
			clone.TotalSize -= f.Size
			continue
		}
		clone.Files = append(clone.Files, f)
	}
	return clone
}

func fileEntryOlder(a, b fileEntry) bool {
	if a.Modified.IsZero() && b.Modified.IsZero() {
		return false
	}
	if a.Modified.IsZero() {
		return true
	}
	if b.Modified.IsZero() {
		return false
	}
	return a.Modified.Before(b.Modified)
}

func (s *Server) deleteDirFileObjects(ctx context.Context, dirToken, filename string) error {
	if err := s.storage.Delete(ctx, dirToken, filename); err != nil && !s.storage.IsNotExist(err) {
		return fmt.Errorf("delete %s: %w", filename, err)
	}
	metadataName := fmt.Sprintf("%s.metadata", filename)
	if err := s.storage.Delete(ctx, dirToken, metadataName); err != nil && !s.storage.IsNotExist(err) {
		return fmt.Errorf("delete %s: %w", metadataName, err)
	}
	return nil
}

// unregisterFileFromDir removes filename from the directory index (best effort).
func (s *Server) unregisterFileFromDir(ctx context.Context, dirToken, filename string) {
	s.lock(dirToken, dirIndexName)
	defer s.unlock(dirToken, dirIndexName)

	idx, err := s.loadDirIndex(ctx, dirToken)
	if err != nil {
		return
	}

	kept := idx.Files[:0]
	for _, f := range idx.Files {
		if f.Name != filename {
			kept = append(kept, f)
		} else {
			idx.TotalSize -= f.Size
		}
	}
	idx.Files = kept

	if len(idx.Files) == 0 {
		if err := s.storage.Delete(ctx, dirToken, dirIndexName); err != nil && !s.storage.IsNotExist(err) {
			s.logger.Printf("directory: failed to delete empty index for %s: %v", dirToken, err)
		}
		return
	}

	if err := s.saveDirIndex(ctx, dirToken, idx); err != nil {
		s.logger.Printf("directory: failed to update index for %s: %v", dirToken, err)
	}
}

// removeStaleFilesFromDir removes multiple files from the directory index.
// Called when files are found to be missing during directory listing (e.g., after purge).
func (s *Server) removeStaleFilesFromDir(ctx context.Context, dirToken string, staleFiles []string) {
	s.lock(dirToken, dirIndexName)
	defer s.unlock(dirToken, dirIndexName)

	idx, err := s.loadDirIndex(ctx, dirToken)
	if err != nil {
		return
	}

	staleSet := make(map[string]struct{}, len(staleFiles))
	for _, f := range staleFiles {
		staleSet[f] = struct{}{}
	}

	kept := idx.Files[:0]
	for _, f := range idx.Files {
		if _, isStale := staleSet[f.Name]; !isStale {
			kept = append(kept, f)
		} else {
			idx.TotalSize -= f.Size
		}
	}
	idx.Files = kept

	if len(idx.Files) == 0 {
		if err := s.storage.Delete(ctx, dirToken, dirIndexName); err != nil && !s.storage.IsNotExist(err) {
			s.logger.Printf("directory: failed to delete empty index for %s: %v", dirToken, err)
		}
		return
	}

	if err := s.saveDirIndex(ctx, dirToken, idx); err != nil {
		s.logger.Printf("directory: failed to remove stale files from %s: %v", dirToken, err)
	}
}

// deleteDirIndex removes the directory index file entirely.
// Called when a directory becomes empty after all files are purged.
func (s *Server) deleteDirIndex(ctx context.Context, dirToken string) {
	s.lock(dirToken, dirIndexName)
	defer s.unlock(dirToken, dirIndexName)

	if err := s.storage.Delete(ctx, dirToken, dirIndexName); err != nil && !s.storage.IsNotExist(err) {
		s.logger.Printf("directory: failed to delete index for %s: %v", dirToken, err)
	}
}

// verifyUploadToken checks that provided matches the directory's write-secret.
func (s *Server) verifyUploadToken(ctx context.Context, dirToken, provided string) error {
	idx, err := s.loadDirIndex(ctx, dirToken)
	if err != nil {
		return err
	}
	if idx.UploadToken == "" {
		return errors.New("directory is not open for uploads")
	}
	if subtle.ConstantTimeCompare([]byte(idx.UploadToken), []byte(provided)) != 1 {
		return errors.New("invalid upload token")
	}
	return nil
}

// directoryURL builds the absolute listing URL for a directory token.
func (s *Server) directoryURL(r *http.Request, dirToken string) string {
	relativeURL, _ := url.Parse(path.Join(s.proxyPath, dirToken) + "/")
	return resolveURL(r, relativeURL, s.proxyPort)
}

// writeDirHeaders adds the directory listing URL and (optionally) the upload
// token to the response headers.
func (s *Server) writeDirHeaders(w http.ResponseWriter, r *http.Request, dirToken, uploadToken string) {
	w.Header().Set("X-Url-Directory", s.directoryURL(r, dirToken))
	if uploadToken != "" {
		w.Header().Set("X-Upload-Token", uploadToken)
	}
}

// createDirHandler handles POST /dir: it creates an empty directory and returns
// its listing URL together with the upload token needed to add files to it.
func (s *Server) createDirHandler(w http.ResponseWriter, r *http.Request) {
	dirToken, uploadToken, err := s.createDirectory(r.Context())
	if err != nil {
		s.respondError(w, http.StatusInternalServerError, "Could not create directory", "createDir: %v", err)
		return
	}

	s.writeDirHeaders(w, r, dirToken, uploadToken)
	w.Header().Set("Content-Type", "text/plain")

	dirURL := s.directoryURL(r, dirToken)
	var body strings.Builder
	body.WriteString("Upload-Token: " + uploadToken + "\n")
	body.WriteString("\n")
	body.WriteString("Add files with:\n")
	fmt.Fprintf(&body, "  curl --upload-file ./file.txt %sfile.txt -H \"X-Upload-Token: %s\"\n", dirURL, uploadToken)
	_, _ = w.Write([]byte(body.String()))
}

// parsePaginationParams extracts page and limit from query parameters
func parsePaginationParams(r *http.Request) (page, limit int) {
	page = 1
	limit = 0
	if p := r.URL.Query().Get("page"); p != "" {
		if v, err := strconv.Atoi(p); err == nil && v > 0 {
			page = v
		}
	}
	if l := r.URL.Query().Get("limit"); l != "" {
		if v, err := strconv.Atoi(l); err == nil && v > 0 {
			limit = v
		}
	}
	return
}

// dirFileEntry represents a file entry in directory listings
type dirFileEntry struct {
	Name string
	URL  string
}

// dirSubdirEntry represents a subdirectory in directory listings
type dirSubdirEntry struct {
	Name string // "nested/" (display name with trailing slash)
	URL  string // "/TOKEN/subpath/nested/" (full URL)
}

// breadcrumb represents a navigation breadcrumb
type breadcrumb struct {
	Name string // "subpath" (display name)
	URL  string // "/TOKEN/subpath/" (full URL, root = "/TOKEN/")
}

// applyPagination slices the entries based on page and limit
func applyPagination(entries []dirFileEntry, page, limit int) (paginated []dirFileEntry, totalPages, adjustedPage int) {
	totalFiles := len(entries)
	totalPages = 1

	if limit <= 0 {
		return entries, totalPages, page
	}

	if totalFiles == 0 {
		return []dirFileEntry{}, 1, 1
	}

	totalPages = (totalFiles + limit - 1) / limit
	adjustedPage = page
	if adjustedPage > totalPages {
		adjustedPage = totalPages
	}
	if adjustedPage < 1 {
		adjustedPage = 1
	}

	start := (adjustedPage - 1) * limit
	end := start + limit
	if end > totalFiles {
		end = totalFiles
	}

	if start < totalFiles {
		paginated = entries[start:end]
	} else {
		paginated = []dirFileEntry{}
	}

	return paginated, totalPages, adjustedPage
}

// directoryListData is the unified template data for both root and subdirectory listings.
type directoryListData struct {
	Token       string
	Subpath     string
	RootURL     string
	Breadcrumbs []breadcrumb
	Subdirs     []dirSubdirEntry
	Files       []dirFileEntry
	Page        int
	Limit       int
	TotalFiles  int
	TotalPages  int
	WebAddress  string
}

func (s *Server) writeDirectoryHTMLResponse(w http.ResponseWriter, data directoryListData) {
	s.htmlTemplatesMutex.RLock()
	err := s.htmlTemplates.ExecuteTemplate(w, "directory.html", data)
	s.htmlTemplatesMutex.RUnlock()
	if err != nil {
		s.logger.Printf("directory: failed to execute template: %v", err)
		http.Error(w, "Internal server error.", http.StatusInternalServerError)
	}
}

func writeDirectoryTextResponse(w http.ResponseWriter, data directoryListData) {
	w.Header().Set("Content-Type", "text/plain")
	w.Header().Set("X-Total-Files", strconv.Itoa(data.TotalFiles))
	if data.Limit > 0 {
		w.Header().Set("X-Page", strconv.Itoa(data.Page))
		w.Header().Set("X-Limit", strconv.Itoa(data.Limit))
		w.Header().Set("X-Total-Pages", strconv.Itoa(data.TotalPages))
	}
	var body strings.Builder
	for _, sd := range data.Subdirs {
		body.WriteString(sd.URL)
		body.WriteString("\n")
	}
	for _, e := range data.Files {
		body.WriteString(e.URL)
		body.WriteString("\n")
	}
	_, _ = w.Write([]byte(body.String()))
}

// filterAndSplitDirEntries filters files by subpath prefix and splits them into
// immediate subdirectories and immediate files.
func filterAndSplitDirEntries(files []fileEntry, subpath string) (subdirs []dirSubdirEntry, dirFiles []fileEntry) {
	seen := make(map[string]bool)

	for _, f := range files {
		var remainder string
		if subpath == "" {
			// Root level: files without "/" are immediate, files with "/" define subdirs
			remainder = f.Name
		} else {
			prefix := subpath + "/"
			if !strings.HasPrefix(f.Name, prefix) {
				continue
			}
			remainder = strings.TrimPrefix(f.Name, prefix)
		}

		if remainder == "" {
			continue
		}

		slashIdx := strings.Index(remainder, "/")
		if slashIdx == -1 {
			// Immediate file
			dirFiles = append(dirFiles, f)
		} else {
			// Subdirectory
			subdirName := remainder[:slashIdx+1]
			if !seen[subdirName] {
				seen[subdirName] = true
				subdirs = append(subdirs, dirSubdirEntry{
					Name: subdirName,
				})
			}
		}
	}

	return subdirs, dirFiles
}

// buildBreadcrumbs creates breadcrumb navigation for a subpath.
func buildBreadcrumbs(r *http.Request, token, subpath, proxyPath, proxyPort string) []breadcrumb {
	if subpath == "" {
		return nil
	}

	parts := strings.Split(subpath, "/")
	crumbs := make([]breadcrumb, 0, len(parts))

	// Build cumulative paths
	cumulative := ""
	for _, part := range parts {
		if cumulative == "" {
			cumulative = part
		} else {
			cumulative = cumulative + "/" + part
		}

		relativeURL, _ := url.Parse(path.Join(proxyPath, token, escapePathForURL(cumulative)) + "/")
		crumbs = append(crumbs, breadcrumb{
			Name: part,
			URL:  resolveURL(r, relativeURL, proxyPort),
		})
	}

	return crumbs
}

// listDirectoryHandler handles GET /{token}/ and GET /{token}/{subpath}/:
// it lists files and subdirectories at the given path within a directory.
// Browsers receive an HTML page, other clients (curl) receive a plain URL list.
// Supports pagination via ?page=N&limit=N query parameters.
func (s *Server) listDirectoryHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	dirToken := vars["token"]
	subpath := vars["subpath"]

	if len(dirToken) > maxTokenLength {
		s.respondError(w, http.StatusBadRequest, "token too long", "")
		return
	}

	if subpath != "" {
		subpath = sanitizePath(subpath)
		if subpath == "" || subpath == "_" {
			// #nosec G710 -- dirToken is server-generated, subpath is sanitized
			http.Redirect(w, r, path.Join(s.proxyPath, dirToken)+"/", http.StatusMovedPermanently)
			return
		}
	}

	page, limit := parsePaginationParams(r)

	idx, err := s.loadDirIndex(r.Context(), dirToken)
	if err != nil {
		s.respondError(w, http.StatusNotFound, "", "directory: %v", err)
		return
	}

	subdirs, dirFiles := filterAndSplitDirEntries(idx.Files, subpath)

	var entries []dirFileEntry
	var staleFiles []string
	for _, f := range dirFiles {
		if _, err := s.storage.Head(r.Context(), dirToken, f.Name); err != nil {
			if s.storage.IsNotExist(err) {
				staleFiles = append(staleFiles, f.Name)
			}
			continue
		}
		relativeURL, _ := url.Parse(path.Join(s.proxyPath, dirToken, escapePathForURL(f.Name)))
		entries = append(entries, dirFileEntry{
			Name: path.Base(f.Name),
			URL:  resolveURL(r, relativeURL, s.proxyPort),
		})
	}

	if len(staleFiles) > 0 {
		s.removeStaleFilesFromDir(r.Context(), dirToken, staleFiles)
	}

	subdirBase := path.Join(s.proxyPath, dirToken, escapePathForURL(subpath))
	for i := range subdirs {
		name := strings.TrimSuffix(subdirs[i].Name, "/")
		relativeURL, _ := url.Parse(path.Join(subdirBase, escapePathForURL(name)) + "/")
		subdirs[i].URL = resolveURL(r, relativeURL, s.proxyPort)
	}

	crumbs := buildBreadcrumbs(r, dirToken, subpath, s.proxyPath, s.proxyPort)
	rootRelative, _ := url.Parse(path.Join(s.proxyPath, dirToken) + "/")
	rootURL := resolveURL(r, rootRelative, s.proxyPort)

	totalFiles := len(entries)
	entries, totalPages, page := applyPagination(entries, page, limit)

	data := directoryListData{
		Token:       dirToken,
		Subpath:     subpath,
		RootURL:     rootURL,
		Breadcrumbs: crumbs,
		Subdirs:     subdirs,
		Files:       entries,
		Page:        page,
		Limit:       limit,
		TotalFiles:  totalFiles,
		TotalPages:  totalPages,
		WebAddress:  resolveWebAddress(r, s.proxyPath, s.proxyPort),
	}

	w.Header().Set("Vary", "Accept")
	w.Header().Set("Cache-Control", "no-store")

	if acceptsHTML(r.Header) {
		s.writeDirectoryHTMLResponse(w, data)
		return
	}

	writeDirectoryTextResponse(w, data)
}

func (s *Server) checkDirLimits(w http.ResponseWriter, r *http.Request, dirToken, filename string) (dirIndex, bool) {
	idx, err := s.loadDirIndex(r.Context(), dirToken)
	if err != nil {
		s.respondError(w, http.StatusNotFound, "", "directory: %v", err)
		return idx, false
	}

	if s.maxDirFiles > 0 && len(idx.Files) >= s.maxDirFiles && !dirIndexContainsFile(idx, filename) {
		s.respondError(w, http.StatusRequestEntityTooLarge,
			fmt.Sprintf("directory file count limit exceeded (max %d files)", s.maxDirFiles), "")
		return idx, false
	}

	if s.maxDirSize > 0 && r.ContentLength > s.maxDirSize {
		s.respondError(w, http.StatusRequestEntityTooLarge,
			fmt.Sprintf("file size exceeds directory size limit (max %d bytes)", s.maxDirSize), "")
		return idx, false
	}

	return idx, true
}

func dirIndexContainsFile(idx dirIndex, filename string) bool {
	for _, f := range idx.Files {
		if f.Name == filename {
			return true
		}
	}
	return false
}

func (s *Server) cleanupOrphanedUpload(ctx context.Context, dirToken, filename string) {
	if delErr := s.storage.Delete(ctx, dirToken, filename); delErr != nil && !s.storage.IsNotExist(delErr) {
		s.logger.Printf("directory: failed to clean up orphaned file %s/%s: %v", dirToken, filename, delErr)
	}
	if delErr := s.storage.Delete(ctx, dirToken, fmt.Sprintf("%s.metadata", filename)); delErr != nil && !s.storage.IsNotExist(delErr) {
		s.logger.Printf("directory: failed to clean up orphaned metadata %s/%s.metadata: %v", dirToken, filename, delErr)
	}
}

// putToDirHandler handles PUT /{token}/{filename}: it adds a file to an
// existing directory after verifying the X-Upload-Token header.
func (s *Server) putToDirHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	dirToken := vars["token"]
	filename := sanitizePath(vars["filename"])

	if err := validateTokenAndFilename(dirToken, filename); err != nil {
		s.respondError(w, http.StatusBadRequest, err.Error(), "")
		return
	}

	provided := r.Header.Get("X-Upload-Token")
	if provided == "" {
		s.respondError(w, http.StatusUnauthorized, "Missing X-Upload-Token", "")
		return
	}

	if err := s.verifyUploadToken(r.Context(), dirToken, provided); err != nil {
		s.respondError(w, http.StatusForbidden, "Invalid upload token or directory", "directory: %v", err)
		return
	}

	if _, ok := s.checkDirLimits(w, r, dirToken, filename); !ok {
		return
	}

	ok, contentLength := s.doPutUpload(w, r, dirToken, filename)
	if !ok {
		return
	}

	if err := s.registerFileInDir(r.Context(), dirToken, filename, contentLength); err != nil {
		s.cleanupOrphanedUpload(r.Context(), dirToken, filename)
		s.respondError(w, http.StatusRequestEntityTooLarge, err.Error(), "directory: %v", err)
		return
	}

	s.writePutResponse(w, r, dirToken, filename, "")
}

// deleteDirHandler handles DELETE /{token}/: it deletes all files in a directory
// and the directory index itself. Requires the X-Upload-Token header.
func (s *Server) deleteDirHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	dirToken := vars["token"]

	if len(dirToken) > maxTokenLength {
		s.respondError(w, http.StatusBadRequest, "token too long", "")
		return
	}

	provided := r.Header.Get("X-Upload-Token")
	if provided == "" {
		s.respondError(w, http.StatusUnauthorized, "Missing X-Upload-Token", "")
		return
	}

	if err := s.verifyUploadToken(r.Context(), dirToken, provided); err != nil {
		s.respondError(w, http.StatusForbidden, "Invalid upload token or directory", "directory: %v", err)
		return
	}

	idx, err := s.loadDirIndex(r.Context(), dirToken)
	if err != nil {
		s.respondError(w, http.StatusNotFound, "", "directory: %v", err)
		return
	}

	var deletedCount int
	for _, entry := range idx.Files {
		if err := s.storage.Delete(r.Context(), dirToken, entry.Name); err != nil && !s.storage.IsNotExist(err) {
			s.logger.Printf("directory: failed to delete %s/%s: %v", dirToken, entry.Name, err)
			continue
		}
		if err := s.storage.Delete(r.Context(), dirToken, fmt.Sprintf("%s.metadata", entry.Name)); err != nil && !s.storage.IsNotExist(err) {
			s.logger.Printf("directory: failed to delete metadata for %s/%s: %v", dirToken, entry.Name, err)
		}
		deletedCount++
	}

	s.deleteDirIndex(r.Context(), dirToken)

	w.Header().Set("Content-Type", "text/plain")
	// dirToken is server-generated, safe to output
	// #nosec G705 -- dirToken is server-generated random token
	_, _ = fmt.Fprintf(w, "Deleted %d file(s) from directory %s\n", deletedCount, dirToken)
}

// dirZipHandler handles GET /{token}/.zip: it downloads all files in a directory
// as a zip archive.
func (s *Server) dirZipHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	dirToken := vars["token"]

	if len(dirToken) > maxTokenLength {
		s.respondError(w, http.StatusBadRequest, "token too long", "")
		return
	}

	idx, err := s.loadDirIndex(r.Context(), dirToken)
	if err != nil {
		s.respondError(w, http.StatusNotFound, "", "directory: %v", err)
		return
	}

	if len(idx.Files) == 0 {
		s.respondError(w, http.StatusNotFound, "Directory is empty", "")
		return
	}

	maxFiles := s.maxArchiveFiles
	if maxFiles <= 0 {
		maxFiles = defaultMaxArchiveFiles
	}
	if len(idx.Files) > maxFiles {
		s.respondError(w, http.StatusBadRequest, fmt.Sprintf("Too many files in directory (max %d)", maxFiles), "")
		return
	}

	zipfilename := fmt.Sprintf("directory-%s-%d.zip", dirToken, time.Now().UnixNano())
	w.Header().Set("Content-Type", "application/zip")
	commonHeader(w, zipfilename)

	zw := zip.NewWriter(w)
	defer func() { _ = zw.Close() }()
	password := r.Header.Get("X-Decrypt-Password")

	var addedFiles int
	for _, entry := range idx.Files {
		reader, _, err := s.fetchFileForArchive(r.Context(), dirToken, entry.Name, password)
		if err != nil {
			s.logger.Printf("directory: skipping %s/%s in zip: %v", dirToken, entry.Name, err)
			continue
		}

		header := &zip.FileHeader{
			Name:     entry.Name,
			Method:   zip.Store,
			Modified: time.Now().UTC(),
		}

		fw, err := zw.CreateHeader(header)
		if err != nil {
			storage.CloseCheck(reader)
			s.logger.Printf("directory: failed to create zip entry for %s: %v", entry.Name, err)
			continue
		}

		_, err = io.Copy(fw, reader)
		storage.CloseCheck(reader)
		if err != nil {
			s.logger.Printf("directory: failed to copy %s to zip: %v", entry.Name, err)
			continue
		}
		addedFiles++
	}

	if addedFiles == 0 {
		s.logger.Printf("directory: no valid files found for zip archive %s", dirToken)
	}
}

// dirTarGzHandler handles GET /{token}/.tar.gz: it downloads all files in a
// directory as a tar.gz archive.
func (s *Server) dirTarGzHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	dirToken := vars["token"]

	if len(dirToken) > maxTokenLength {
		s.respondError(w, http.StatusBadRequest, "token too long", "")
		return
	}

	idx, err := s.loadDirIndex(r.Context(), dirToken)
	if err != nil {
		s.respondError(w, http.StatusNotFound, "", "directory: %v", err)
		return
	}

	if len(idx.Files) == 0 {
		s.respondError(w, http.StatusNotFound, "Directory is empty", "")
		return
	}

	maxFiles := s.maxArchiveFiles
	if maxFiles <= 0 {
		maxFiles = defaultMaxArchiveFiles
	}
	if len(idx.Files) > maxFiles {
		s.respondError(w, http.StatusBadRequest, fmt.Sprintf("Too many files in directory (max %d)", maxFiles), "")
		return
	}

	tarfilename := fmt.Sprintf("directory-%s-%d.tar.gz", dirToken, time.Now().UnixNano())
	w.Header().Set("Content-Type", "application/x-gzip")
	commonHeader(w, tarfilename)

	gw := gzip.NewWriter(w)
	defer storage.CloseCheck(gw)

	zw := tar.NewWriter(gw)
	defer storage.CloseCheck(zw)
	password := r.Header.Get("X-Decrypt-Password")

	var addedFiles int
	for _, entry := range idx.Files {
		reader, contentLength, err := s.fetchFileForArchive(r.Context(), dirToken, entry.Name, password)
		if err != nil {
			s.logger.Printf("directory: skipping %s/%s in tar.gz: %v", dirToken, entry.Name, err)
			continue
		}

		header := &tar.Header{
			Name: entry.Name,
			Size: storage.SafeUint64ToInt64(contentLength),
		}

		if err := zw.WriteHeader(header); err != nil {
			storage.CloseCheck(reader)
			s.logger.Printf("directory: failed to write header for %s: %v", entry.Name, err)
			continue
		}

		if _, err := io.Copy(zw, reader); err != nil {
			storage.CloseCheck(reader)
			s.logger.Printf("directory: failed to copy %s to tar: %v", entry.Name, err)
			continue
		}
		storage.CloseCheck(reader)
		addedFiles++
	}

	if addedFiles == 0 {
		s.logger.Printf("directory: no valid files found for tar.gz archive %s", dirToken)
	}
}

// dirZipHeadHandler handles HEAD /{token}/.zip: it returns archive headers
// without generating the archive body.
func (s *Server) dirZipHeadHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	dirToken := vars["token"]

	if len(dirToken) > maxTokenLength {
		s.respondError(w, http.StatusBadRequest, "token too long", "")
		return
	}

	idx, err := s.loadDirIndex(r.Context(), dirToken)
	if err != nil {
		s.respondError(w, http.StatusNotFound, "", "directory: %v", err)
		return
	}

	if len(idx.Files) == 0 {
		s.respondError(w, http.StatusNotFound, "Directory is empty", "")
		return
	}

	zipfilename := fmt.Sprintf("directory-%s.zip", dirToken)
	w.Header().Set("Content-Type", "application/zip")
	commonHeader(w, zipfilename)
}

// dirTarGzHeadHandler handles HEAD /{token}/.tar.gz: it returns archive headers
// without generating the archive body.
func (s *Server) dirTarGzHeadHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	dirToken := vars["token"]

	if len(dirToken) > maxTokenLength {
		s.respondError(w, http.StatusBadRequest, "token too long", "")
		return
	}

	idx, err := s.loadDirIndex(r.Context(), dirToken)
	if err != nil {
		s.respondError(w, http.StatusNotFound, "", "directory: %v", err)
		return
	}

	if len(idx.Files) == 0 {
		s.respondError(w, http.StatusNotFound, "Directory is empty", "")
		return
	}

	tarfilename := fmt.Sprintf("directory-%s.tar.gz", dirToken)
	w.Header().Set("Content-Type", "application/x-gzip")
	commonHeader(w, tarfilename)
}
