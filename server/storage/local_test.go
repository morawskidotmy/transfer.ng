package storage

import (
	"bytes"
	"context"
	"io"
	"log"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestLocalStorage_Type(t *testing.T) {
	storage, err := NewLocalStorage(t.TempDir(), log.New(io.Discard, "", 0))
	if err != nil {
		t.Fatalf("failed to create storage: %v", err)
	}
	if storage.Type() != "local" {
		t.Errorf("expected type 'local', got %q", storage.Type())
	}
}

func TestLocalStorage_PutAndGet(t *testing.T) {
	basedir := t.TempDir()
	storage, err := NewLocalStorage(basedir, log.New(io.Discard, "", 0))
	if err != nil {
		t.Fatalf("failed to create storage: %v", err)
	}

	ctx := context.Background()
	token := "testtoken"
	filename := "testfile.txt"
	content := []byte("hello world")

	err = storage.Put(ctx, token, filename, bytes.NewReader(content), "text/plain", uint64(len(content)))
	if err != nil {
		t.Fatalf("Put failed: %v", err)
	}

	reader, contentLength, err := storage.Get(ctx, token, filename, nil)
	if err != nil {
		t.Fatalf("Get failed: %v", err)
	}
	defer func() { _ = reader.Close() }()

	if contentLength != uint64(len(content)) {
		t.Errorf("expected content length %d, got %d", len(content), contentLength)
	}

	result, err := io.ReadAll(reader)
	if err != nil {
		t.Fatalf("ReadAll failed: %v", err)
	}

	if !bytes.Equal(result, content) {
		t.Errorf("expected content %q, got %q", content, result)
	}
}

func TestLocalStorage_Head(t *testing.T) {
	basedir := t.TempDir()
	storage, err := NewLocalStorage(basedir, log.New(io.Discard, "", 0))
	if err != nil {
		t.Fatalf("failed to create storage: %v", err)
	}

	ctx := context.Background()
	token := "testtoken"
	filename := "testfile.txt"
	content := []byte("hello world")

	err = storage.Put(ctx, token, filename, bytes.NewReader(content), "text/plain", uint64(len(content)))
	if err != nil {
		t.Fatalf("Put failed: %v", err)
	}

	contentLength, err := storage.Head(ctx, token, filename)
	if err != nil {
		t.Fatalf("Head failed: %v", err)
	}

	if contentLength != uint64(len(content)) {
		t.Errorf("expected content length %d, got %d", len(content), contentLength)
	}
}

func TestLocalStorage_Delete(t *testing.T) {
	basedir := t.TempDir()
	storage, err := NewLocalStorage(basedir, log.New(io.Discard, "", 0))
	if err != nil {
		t.Fatalf("failed to create storage: %v", err)
	}

	ctx := context.Background()
	token := "testtoken"
	filename := "testfile.txt"
	content := []byte("hello world")

	err = storage.Put(ctx, token, filename, bytes.NewReader(content), "text/plain", uint64(len(content)))
	if err != nil {
		t.Fatalf("Put failed: %v", err)
	}

	err = storage.Delete(ctx, token, filename)
	if err != nil {
		t.Fatalf("Delete failed: %v", err)
	}

	_, _, err = storage.Get(ctx, token, filename, nil)
	if !storage.IsNotExist(err) {
		t.Errorf("expected file to not exist after delete, got err: %v", err)
	}
}

func TestLocalStorage_IsNotExist(t *testing.T) {
	basedir := t.TempDir()
	storage, err := NewLocalStorage(basedir, log.New(io.Discard, "", 0))
	if err != nil {
		t.Fatalf("failed to create storage: %v", err)
	}

	ctx := context.Background()
	_, _, err = storage.Get(ctx, "nonexistent", "nonexistent.txt", nil)
	if !storage.IsNotExist(err) {
		t.Errorf("expected IsNotExist to return true for nonexistent file")
	}

	if storage.IsNotExist(nil) {
		t.Errorf("expected IsNotExist to return false for nil error")
	}
}

func TestLocalStorage_GetWithRange(t *testing.T) {
	basedir := t.TempDir()
	storage, err := NewLocalStorage(basedir, log.New(io.Discard, "", 0))
	if err != nil {
		t.Fatalf("failed to create storage: %v", err)
	}

	ctx := context.Background()
	token := "testtoken"
	filename := "testfile.txt"
	content := []byte("0123456789")

	err = storage.Put(ctx, token, filename, bytes.NewReader(content), "text/plain", uint64(len(content)))
	if err != nil {
		t.Fatalf("Put failed: %v", err)
	}

	rng := &Range{Start: 2, Limit: 5}
	reader, contentLength, err := storage.Get(ctx, token, filename, rng)
	if err != nil {
		t.Fatalf("Get with range failed: %v", err)
	}
	defer func() { _ = reader.Close() }()

	if contentLength != 5 {
		t.Errorf("expected content length 5, got %d", contentLength)
	}

	result, err := io.ReadAll(io.LimitReader(reader, int64(contentLength)))
	if err != nil {
		t.Fatalf("ReadAll failed: %v", err)
	}

	expected := "23456"
	if string(result) != expected {
		t.Errorf("expected content %q, got %q", expected, result)
	}
}

func TestLocalStorage_IsRangeSupported(t *testing.T) {
	storage, err := NewLocalStorage(t.TempDir(), log.New(io.Discard, "", 0))
	if err != nil {
		t.Fatalf("failed to create storage: %v", err)
	}
	if !storage.IsRangeSupported() {
		t.Errorf("expected IsRangeSupported to return true")
	}
}

func TestLocalStorage_BuildPathSecurity(t *testing.T) {
	basedir := t.TempDir()
	storage, err := NewLocalStorage(basedir, log.New(io.Discard, "", 0))
	if err != nil {
		t.Fatalf("failed to create storage: %v", err)
	}

	tests := []struct {
		name     string
		token    string
		filename string
		wantErr  bool
	}{
		{"valid", "abc123", "file.txt", false},
		{"token with slash", "abc/123", "file.txt", true},
		{"token with backslash", "abc\\123", "file.txt", true},
		{"token with dotdot", "abc..123", "file.txt", true},
		{"filename with slash", "abc123", "path/file.txt", true},
		{"filename with dotdot", "abc123", "../file.txt", true},
		{"token too long", string(make([]byte, 201)), "file.txt", true},
		{"filename too long", "abc123", string(make([]byte, 201)), true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := storage.buildPath(tt.token, tt.filename)
			if (err != nil) != tt.wantErr {
				t.Errorf("buildPath() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestLocalStorage_Purge(t *testing.T) {
	basedir := t.TempDir()
	logger := log.New(io.Discard, "", 0)
	storage, err := NewLocalStorage(basedir, logger)
	if err != nil {
		t.Fatalf("failed to create storage: %v", err)
	}

	ctx := context.Background()
	token := "testtoken"
	filename := "oldfile.txt"
	content := []byte("old content")

	err = storage.Put(ctx, token, filename, bytes.NewReader(content), "text/plain", uint64(len(content)))
	if err != nil {
		t.Fatalf("Put failed: %v", err)
	}

	filePath := filepath.Join(basedir, token, filename)
	oldTime := time.Now().Add(-48 * time.Hour)
	if err := os.Chtimes(filePath, oldTime, oldTime); err != nil {
		t.Fatalf("failed to change file time: %v", err)
	}

	err = storage.Purge(ctx, 24*time.Hour)
	if err != nil {
		t.Fatalf("Purge failed: %v", err)
	}

	_, _, err = storage.Get(ctx, token, filename, nil)
	if !storage.IsNotExist(err) {
		t.Errorf("expected file to be purged")
	}
}
