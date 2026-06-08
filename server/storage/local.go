package storage

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"time"
)

const localDirIndexName = ".dir.json"

// LocalStorage is a local storage
type LocalStorage struct {
	Storage
	basedir string
	logger  *log.Logger
}

// NewLocalStorage creates a local filesystem storage backend rooted at basedir.
func NewLocalStorage(basedir string, logger *log.Logger) (*LocalStorage, error) {
	return &LocalStorage{basedir: basedir, logger: logger}, nil
}

func (s *LocalStorage) buildPath(token, filename string) (string, error) {
	if strings.ContainsAny(token, "/\\") || strings.Contains(token, "..") {
		return "", fmt.Errorf("invalid token")
	}
	// Allow forward slashes in filename for nested paths, but reject backslashes
	// and path traversal sequences as defense-in-depth.
	if strings.ContainsAny(filename, "\\") || strings.Contains(filename, "..") {
		return "", fmt.Errorf("invalid filename")
	}
	if strings.Contains(filename, "//") {
		return "", fmt.Errorf("invalid filename: empty path component")
	}
	if strings.HasPrefix(filename, "/") {
		return "", fmt.Errorf("invalid filename: absolute path")
	}
	if len(token) > 200 || len(filename) > 1024 {
		return "", fmt.Errorf("token or filename too long")
	}

	result := filepath.Join(s.basedir, token, filename)
	tokenDir := filepath.Clean(filepath.Join(s.basedir, token)) + string(os.PathSeparator)
	if !strings.HasPrefix(filepath.Clean(result), tokenDir) {
		return "", fmt.Errorf("path escapes token directory")
	}
	return result, nil
}

// Type returns the storage type
func (s *LocalStorage) Type() string {
	return "local"
}

// Head returns the content length of a file without reading its body.
func (s *LocalStorage) Head(_ context.Context, token string, filename string) (contentLength uint64, err error) {
	path, err := s.buildPath(token, filename)
	if err != nil {
		return 0, err
	}

	fi, err := os.Lstat(path)
	if err != nil {
		return 0, err
	}

	return SafeInt64ToUint64(fi.Size()), nil
}

// Get retrieves a file from local storage, optionally with a byte range.
func (s *LocalStorage) Get(_ context.Context, token string, filename string, rng *Range) (reader io.ReadCloser, contentLength uint64, err error) {
	path, err := s.buildPath(token, filename)
	if err != nil {
		return nil, 0, err
	}

	// #nosec G304 -- path is validated by buildPath() which prevents traversal
	file, err := os.Open(path)
	if err != nil {
		return nil, 0, err
	}

	fi, err := file.Stat()
	if err != nil {
		_ = file.Close()
		return nil, 0, err
	}

	contentLength = SafeInt64ToUint64(fi.Size())
	if rng != nil {
		contentLength = rng.AcceptLength(contentLength)
		if rng.ContentRange() == "" {
			return file, contentLength, nil
		}
		if _, err = file.Seek(SafeUint64ToInt64(rng.Start), io.SeekStart); err != nil {
			_ = file.Close()
			return nil, 0, err
		}
	}

	return file, contentLength, nil
}

// Delete removes a file and its metadata from local storage.
func (s *LocalStorage) Delete(_ context.Context, token string, filename string) error {
	path, err := s.buildPath(token, filename)
	if err != nil {
		return err
	}

	metadataPath, _ := s.buildPath(token, fmt.Sprintf("%s.metadata", filename))
	if metadataPath != "" {
		_ = os.Remove(metadataPath)
	}

	return os.Remove(path)
}

// Purge removes files older than the specified duration from local storage.
func (s *LocalStorage) Purge(_ context.Context, days time.Duration) (err error) {
	err = filepath.WalkDir(s.basedir,
		func(path string, d fs.DirEntry, walkErr error) error {
			if walkErr != nil {
				s.logger.Printf("purge: walk error for %s: %v", path, walkErr)
				return nil
			}
			if d.IsDir() {
				return nil
			}
			info, statErr := d.Info()
			if statErr != nil {
				s.logger.Printf("purge: stat error for %s: %v", path, statErr)
				return nil
			}

			if info.ModTime().Before(time.Now().Add(-1 * days)) {
				// #nosec G122 -- TOCTOU is acceptable for purge cleanup;
				// worst case is a recently-modified file gets removed, which
				// is mitigated by the mtime check above.
				if rmErr := os.Remove(path); rmErr != nil && !os.IsNotExist(rmErr) {
					s.logger.Printf("purge: failed to remove %s: %v", path, rmErr)
				}
			}

			return nil
		})
	if err != nil {
		return err
	}

	return s.cleanupPurgeArtifacts()
}

func (s *LocalStorage) cleanupPurgeArtifacts() error {
	if err := s.removeOrphanMetadata(); err != nil {
		return err
	}
	if err := s.removeOrphanDirIndexes(); err != nil {
		return err
	}
	return s.removeEmptyDirs()
}

func (s *LocalStorage) removeOrphanMetadata() error {
	return filepath.WalkDir(s.basedir, func(path string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			s.logger.Printf("purge: walk error for %s: %v", path, walkErr)
			return nil
		}
		if d.IsDir() || !strings.HasSuffix(path, ".metadata") {
			return nil
		}
		dataPath := strings.TrimSuffix(path, ".metadata")
		if _, err := os.Stat(dataPath); os.IsNotExist(err) {
			// #nosec G122 -- purge cleanup is best-effort; paths are discovered under basedir
			// and stale metadata removal is safe if a concurrent upload recreates the file.
			if rmErr := os.Remove(path); rmErr != nil && !os.IsNotExist(rmErr) {
				s.logger.Printf("purge: failed to remove orphan metadata %s: %v", path, rmErr)
			}
		}
		return nil
	})
}

func (s *LocalStorage) removeOrphanDirIndexes() error {
	entries, err := os.ReadDir(s.basedir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		tokenDir := filepath.Join(s.basedir, entry.Name())
		hasData, err := hasLocalDataFiles(tokenDir)
		if err != nil {
			s.logger.Printf("purge: failed to inspect %s: %v", tokenDir, err)
			continue
		}
		if !hasData {
			idxPath := filepath.Join(tokenDir, localDirIndexName)
			if rmErr := os.Remove(idxPath); rmErr != nil && !os.IsNotExist(rmErr) {
				s.logger.Printf("purge: failed to remove orphan index %s: %v", idxPath, rmErr)
			}
		}
	}
	return nil
}

func hasLocalDataFiles(root string) (bool, error) {
	hasData := false
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if d.IsDir() {
			return nil
		}
		name := filepath.Base(path)
		if name == localDirIndexName || strings.HasSuffix(name, ".metadata") {
			return nil
		}
		hasData = true
		return filepath.SkipAll
	})
	return hasData, err
}

func (s *LocalStorage) removeEmptyDirs() error {
	var dirs []string
	if err := filepath.WalkDir(s.basedir, func(path string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			s.logger.Printf("purge: walk error for %s: %v", path, walkErr)
			return nil
		}
		if d.IsDir() && path != s.basedir {
			dirs = append(dirs, path)
		}
		return nil
	}); err != nil {
		return err
	}
	sort.Slice(dirs, func(i, j int) bool { return len(dirs[i]) > len(dirs[j]) })
	for _, dir := range dirs {
		if err := os.Remove(dir); err != nil && !os.IsNotExist(err) && !errors.Is(err, syscall.ENOTEMPTY) && !errors.Is(err, syscall.EEXIST) {
			s.logger.Printf("purge: failed to remove empty directory %s: %v", dir, err)
		}
	}
	return nil
}

// IsNotExist indicates if a file doesn't exist on storage
func (s *LocalStorage) IsNotExist(err error) bool {
	if err == nil {
		return false
	}

	return os.IsNotExist(err)
}

// Put stores a file in local storage at the given token/filename path.
func (s *LocalStorage) Put(_ context.Context, token string, filename string, reader io.Reader, _ string, _ uint64) error {
	fullPath, err := s.buildPath(token, filename)
	if err != nil {
		return err
	}

	dir := filepath.Dir(fullPath)
	if err = os.MkdirAll(dir, 0700); err != nil && !os.IsExist(err) {
		return err
	}

	// #nosec G304 -- fullPath is validated by buildPath() which prevents traversal
	f, err := os.OpenFile(fullPath, os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return err
	}

	defer CloseCheck(f)

	if _, err = io.Copy(f, reader); err != nil {
		return err
	}

	return nil
}

// IsRangeSupported returns true because local storage supports HTTP Range requests.
func (s *LocalStorage) IsRangeSupported() bool { return true }
