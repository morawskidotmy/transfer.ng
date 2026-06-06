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
	Name string
	Size int64
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

	idx, err := s.loadDirIndex(ctx, dirToken)
	if err != nil {
		if !s.storage.IsNotExist(err) {
			return err
		}
		idx = dirIndex{Created: time.Now()}
	}

	for _, f := range idx.Files {
		if f.Name == filename {
			return nil
		}
	}

	// Check directory size limit
	if s.maxDirSize > 0 && idx.TotalSize+fileSize > s.maxDirSize {
		return fmt.Errorf("directory size limit exceeded (max %d bytes)", s.maxDirSize)
	}

	// Check directory file count limit
	if s.maxDirFiles > 0 && len(idx.Files) >= s.maxDirFiles {
		return fmt.Errorf("directory file count limit exceeded (max %d files)", s.maxDirFiles)
	}

	idx.Files = append(idx.Files, fileEntry{Name: filename, Size: fileSize})
	idx.TotalSize += fileSize
	return s.saveDirIndex(ctx, dirToken, idx)
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

	totalPages = (totalFiles + limit - 1) / limit
	adjustedPage = page
	if adjustedPage > totalPages {
		adjustedPage = totalPages
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

// writeDirHTMLResponse writes the HTML directory listing
func (s *Server) writeDirHTMLResponse(w http.ResponseWriter, r *http.Request, dirToken string, subdirs []dirSubdirEntry, entries []dirFileEntry, page, limit, totalFiles, totalPages int) {
	data := struct {
		Token      string
		WebAddress string
		Subdirs    []dirSubdirEntry
		Files      []dirFileEntry
		Page       int
		Limit      int
		TotalFiles int
		TotalPages int
	}{
		Token:      dirToken,
		WebAddress: resolveWebAddress(r, s.proxyPath, s.proxyPort),
		Subdirs:    subdirs,
		Files:      entries,
		Page:       page,
		Limit:      limit,
		TotalFiles: totalFiles,
		TotalPages: totalPages,
	}

	s.htmlTemplatesMutex.RLock()
	err := s.htmlTemplates.ExecuteTemplate(w, "directory.html", data)
	s.htmlTemplatesMutex.RUnlock()
	if err != nil {
		s.logger.Printf("directory: failed to execute template: %v", err)
		http.Error(w, "Internal server error.", http.StatusInternalServerError)
	}
}

// writeDirTextResponse writes the plain text directory listing
func writeDirTextResponse(w http.ResponseWriter, subdirs []dirSubdirEntry, entries []dirFileEntry, page, limit, totalFiles, totalPages int) {
	w.Header().Set("Content-Type", "text/plain")
	w.Header().Set("X-Total-Files", strconv.Itoa(totalFiles))
	if limit > 0 {
		w.Header().Set("X-Page", strconv.Itoa(page))
		w.Header().Set("X-Limit", strconv.Itoa(limit))
		w.Header().Set("X-Total-Pages", strconv.Itoa(totalPages))
	}
	var body strings.Builder
	// Subdirectories first (with trailing /)
	for _, sd := range subdirs {
		body.WriteString(sd.URL)
		body.WriteString("\n")
	}
	// Then files
	for _, e := range entries {
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

		relativeURL, _ := url.Parse(path.Join(proxyPath, token, cumulative) + "/")
		crumbs = append(crumbs, breadcrumb{
			Name: part,
			URL:  resolveURL(r, relativeURL, proxyPort),
		})
	}

	return crumbs
}

// subDirHandler handles GET /{token}/{subpath}/: it lists files and subdirectories
// at a specific subpath within a directory.
func (s *Server) subDirHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	dirToken := vars["token"]
	subpath := vars["subpath"]

	if len(dirToken) > maxTokenLength {
		s.respondError(w, http.StatusBadRequest, "token too long", "")
		return
	}

	// Sanitize subpath
	subpath = sanitizePath(subpath)
	if subpath == "" || subpath == "_" {
		// Redirect to root directory
		http.Redirect(w, r, path.Join(s.proxyPath, dirToken)+"/", http.StatusMovedPermanently)
		return
	}

	idx, err := s.loadDirIndex(r.Context(), dirToken)
	if err != nil {
		s.respondError(w, http.StatusNotFound, "", "directory: %v", err)
		return
	}

	// Filter and split entries
	subdirs, dirFiles := filterAndSplitDirEntries(idx.Files, subpath)

	// Build file entries with URLs
	var fileEntries []dirFileEntry
	for _, f := range dirFiles {
		relativeURL, _ := url.Parse(path.Join(s.proxyPath, dirToken, escapePathForURL(f.Name)))
		fileEntries = append(fileEntries, dirFileEntry{
			Name: f.Name,
			URL:  resolveURL(r, relativeURL, s.proxyPort),
		})
	}

	// Build subdirectory URLs
	for i := range subdirs {
		relativeURL, _ := url.Parse(path.Join(s.proxyPath, dirToken, subpath, subdirs[i].Name) + "/")
		subdirs[i].URL = resolveURL(r, relativeURL, s.proxyPort)
	}

	// Build breadcrumbs
	crumbs := buildBreadcrumbs(r, dirToken, subpath, s.proxyPath, s.proxyPort)

	w.Header().Set("Vary", "Accept")

	if acceptsHTML(r.Header) {
		s.writeSubDirHTMLResponse(w, r, dirToken, subpath, crumbs, subdirs, fileEntries)
		return
	}

	s.writeSubDirTextResponse(w, subdirs, fileEntries)
}

// writeSubDirHTMLResponse writes the HTML subdirectory listing
func (s *Server) writeSubDirHTMLResponse(w http.ResponseWriter, r *http.Request, dirToken, subpath string, breadcrumbs []breadcrumb, subdirs []dirSubdirEntry, files []dirFileEntry) {
	data := struct {
		Token       string
		Subpath     string
		Breadcrumbs []breadcrumb
		Subdirs     []dirSubdirEntry
		Files       []dirFileEntry
		WebAddress  string
	}{
		Token:       dirToken,
		Subpath:     subpath,
		Breadcrumbs: breadcrumbs,
		Subdirs:     subdirs,
		Files:       files,
		WebAddress:  resolveWebAddress(r, s.proxyPath, s.proxyPort),
	}

	s.htmlTemplatesMutex.RLock()
	err := s.htmlTemplates.ExecuteTemplate(w, "directory.html", data)
	s.htmlTemplatesMutex.RUnlock()
	if err != nil {
		s.logger.Printf("subdirectory: failed to execute template: %v", err)
		http.Error(w, "Internal server error.", http.StatusInternalServerError)
	}
}

// writeSubDirTextResponse writes the plain text subdirectory listing
func (s *Server) writeSubDirTextResponse(w http.ResponseWriter, subdirs []dirSubdirEntry, files []dirFileEntry) {
	w.Header().Set("Content-Type", "text/plain")
	var body strings.Builder

	// Subdirectories first
	for _, sd := range subdirs {
		body.WriteString(sd.URL)
		body.WriteString("\n")
	}

	// Then files
	for _, f := range files {
		body.WriteString(f.URL)
		body.WriteString("\n")
	}

	_, _ = w.Write([]byte(body.String()))
}

// dirHandler handles GET /{token}/ and GET /{token}: it lists the files in a
// directory. Browsers receive an HTML page, other clients (curl) receive a
// plain list of direct download URLs.
// Supports pagination via ?page=N&limit=N query parameters.
func (s *Server) dirHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	dirToken := vars["token"]

	if len(dirToken) > maxTokenLength {
		s.respondError(w, http.StatusBadRequest, "token too long", "")
		return
	}

	page, limit := parsePaginationParams(r)

	idx, err := s.loadDirIndex(r.Context(), dirToken)
	if err != nil {
		s.respondError(w, http.StatusNotFound, "", "directory: %v", err)
		return
	}

	// Get immediate children only (not recursive)
	rootSubdirs, immediateFiles := filterAndSplitDirEntries(idx.Files, "")

	// Build entries only for immediate files
	var entries []dirFileEntry
	var staleFiles []string
	for _, f := range immediateFiles {
		if _, err := s.storage.Head(r.Context(), dirToken, f.Name); err != nil {
			if s.storage.IsNotExist(err) {
				staleFiles = append(staleFiles, f.Name)
			}
			continue
		}
		relativeURL, _ := url.Parse(path.Join(s.proxyPath, dirToken, escapePathForURL(f.Name)))
		entries = append(entries, dirFileEntry{
			Name: f.Name,
			URL:  resolveURL(r, relativeURL, s.proxyPort),
		})
	}

	if len(staleFiles) > 0 {
		s.removeStaleFilesFromDir(r.Context(), dirToken, staleFiles)
	}

	// Build URLs for subdirectories
	for i := range rootSubdirs {
		relativeURL, _ := url.Parse(path.Join(s.proxyPath, dirToken, rootSubdirs[i].Name) + "/")
		rootSubdirs[i].URL = resolveURL(r, relativeURL, s.proxyPort)
	}

	totalFiles := len(entries)
	entries, totalPages, page := applyPagination(entries, page, limit)

	w.Header().Set("Vary", "Accept")

	if acceptsHTML(r.Header) {
		s.writeDirHTMLResponse(w, r, dirToken, rootSubdirs, entries, page, limit, totalFiles, totalPages)
		return
	}

	writeDirTextResponse(w, rootSubdirs, entries, page, limit, totalFiles, totalPages)
}

func (s *Server) checkDirLimits(w http.ResponseWriter, r *http.Request, dirToken string) (dirIndex, bool) {
	idx, err := s.loadDirIndex(r.Context(), dirToken)
	if err != nil {
		s.respondError(w, http.StatusNotFound, "", "directory: %v", err)
		return idx, false
	}

	if s.maxDirFiles > 0 && len(idx.Files) >= s.maxDirFiles {
		s.respondError(w, http.StatusRequestEntityTooLarge,
			fmt.Sprintf("directory file count limit exceeded (max %d files)", s.maxDirFiles), "")
		return idx, false
	}

	if s.maxDirSize > 0 && r.ContentLength > 0 && idx.TotalSize+r.ContentLength > s.maxDirSize {
		s.respondError(w, http.StatusRequestEntityTooLarge,
			fmt.Sprintf("directory size limit exceeded (max %d bytes)", s.maxDirSize), "")
		return idx, false
	}

	return idx, true
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

	if _, ok := s.checkDirLimits(w, r, dirToken); !ok {
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

	var addedFiles int
	for _, entry := range idx.Files {
		reader, _, err := s.fetchFileForArchive(r.Context(), dirToken, entry.Name)
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

	var addedFiles int
	for _, entry := range idx.Files {
		reader, contentLength, err := s.fetchFileForArchive(r.Context(), dirToken, entry.Name)
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
