package storage

import (
	"context"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// LocalStorage is a local storage
type LocalStorage struct {
	Storage
	basedir string
	logger  *log.Logger
}

func NewLocalStorage(basedir string, logger *log.Logger) (*LocalStorage, error) {
	return &LocalStorage{basedir: basedir, logger: logger}, nil
}

func (s *LocalStorage) buildPath(token, filename string) (string, error) {
	if strings.ContainsAny(token, "/\\") || strings.Contains(token, "..") {
		return "", fmt.Errorf("invalid token")
	}
	if strings.ContainsAny(filename, "/\\") || strings.Contains(filename, "..") {
		return "", fmt.Errorf("invalid filename")
	}
	if len(token) > 200 || len(filename) > 200 {
		return "", fmt.Errorf("token or filename too long")
	}

	path := filepath.Join(s.basedir, token, filename)
	cleanBase := filepath.Clean(s.basedir) + string(os.PathSeparator)
	if !strings.HasPrefix(filepath.Clean(path)+string(os.PathSeparator), cleanBase) {
		return "", fmt.Errorf("path escapes basedir")
	}
	return path, nil
}

// Type returns the storage type
func (s *LocalStorage) Type() string {
	return "local"
}

func (s *LocalStorage) Head(_ context.Context, token string, filename string) (contentLength uint64, err error) {
	path, err := s.buildPath(token, filename)
	if err != nil {
		return 0, err
	}

	fi, err := os.Lstat(path)
	if err != nil {
		return 0, err
	}

	return uint64(fi.Size()), nil
}

func (s *LocalStorage) Get(_ context.Context, token string, filename string, rng *Range) (reader io.ReadCloser, contentLength uint64, err error) {
	path, err := s.buildPath(token, filename)
	if err != nil {
		return nil, 0, err
	}

	file, err := os.Open(path)
	if err != nil {
		return nil, 0, err
	}

	fi, err := file.Stat()
	if err != nil {
		_ = file.Close()
		return nil, 0, err
	}

	contentLength = uint64(fi.Size())
	if rng != nil {
		contentLength = rng.AcceptLength(contentLength)
		if _, err = file.Seek(int64(rng.Start), io.SeekStart); err != nil {
			_ = file.Close()
			return nil, 0, err
		}
	}

	return file, contentLength, nil
}

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

func (s *LocalStorage) Purge(_ context.Context, days time.Duration) (err error) {
	err = filepath.Walk(s.basedir,
		func(path string, info os.FileInfo, walkErr error) error {
			if walkErr != nil {
				s.logger.Printf("purge: walk error for %s: %v", path, walkErr)
				return nil
			}
			if info.IsDir() {
				return nil
			}

			if info.ModTime().Before(time.Now().Add(-1 * days)) {
				if rmErr := os.Remove(path); rmErr != nil && !os.IsNotExist(rmErr) {
					s.logger.Printf("purge: failed to remove %s: %v", path, rmErr)
				}
			}

			return nil
		})

	return
}

// IsNotExist indicates if a file doesn't exist on storage
func (s *LocalStorage) IsNotExist(err error) bool {
	if err == nil {
		return false
	}

	return os.IsNotExist(err)
}

func (s *LocalStorage) Put(_ context.Context, token string, filename string, reader io.Reader, contentType string, contentLength uint64) error {
	fullPath, err := s.buildPath(token, filename)
	if err != nil {
		return err
	}

	dir := filepath.Dir(fullPath)
	if err = os.MkdirAll(dir, 0700); err != nil && !os.IsExist(err) {
		return err
	}

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

func (s *LocalStorage) IsRangeSupported() bool { return true }
