# AGENTS.md — transfer.ng

## Project Overview

transfer.ng is a Go-based file sharing service — a fork of [transfer.sh](https://github.com/dutchcoders/transfer.sh) with gofile-style directory support. Users upload files via HTTP (PUT/POST/curl) and receive shareable URLs. Files are organized into directories identified by random tokens, with write-protected access via `X-Upload-Token` headers.

- **Module**: `github.com/morawskidotmy/transfer.ng`
- **Go version**: 1.24+
- **Entry point**: `main.go`
- **Build**: `go build ./...`
- **Test**: `go test ./...`

## Architecture

```
main.go → cmd/cmd.go → server.New() → server.Run()
                              ↓
                    ┌─────────────────────┐
                    │    Server (mux)     │
                    │  routing + handlers │
                    └─────────┬───────────┘
                              ↓
                    ┌─────────────────────┐
                    │  Storage Interface  │
                    │  Put/Get/Delete/Head│
                    └─────────┬───────────┘
                              ↓
              ┌───────┬───────┼───────┬───────┐
              │ local │  s3   │ storj │gdrive │
              └───────┴───────┴───────┴───────┘
```

### Key Components

| Package | Purpose |
|---------|---------|
| `cmd/` | CLI entry point, flag parsing, server bootstrap |
| `server/` | HTTP handlers, routing, metadata, directory management |
| `server/storage/` | Pluggable storage backends (local, S3, Storj, GDrive) |
| `web/` | Embedded static assets (HTML templates, CSS, JS) |

### Upload Flow

1. **Single file PUT** → `putHandler` creates a new directory token, stores file, returns URL + deletion token + upload token
2. **Multi-file POST** → `postHandler` creates a directory, iterates multipart files, stores each
3. **Add to directory PUT** → `putToDirHandler` verifies `X-Upload-Token`, adds file to existing directory
4. All uploads go through `doPutUpload` which buffers to temp (for chunked/unknown length or ClamAV prescan), validates size, then delegates to the storage backend

### Directory System

- Each directory has a random **token** (read access) and an **upload token** (write secret)
- Directory index stored as `.dir.json` per token — contains file list, sizes, upload token
- Files are registered via `registerFileInDir` (enforces file count and size limits)
- Directory listing at `/{token}/` supports HTML (browsers) and plain text (curl) with pagination

### Storage Interface (`server/storage/common.go`)

```go
type Storage interface {
    Get(ctx, token, filename, range) (reader, contentLength, err)
    Head(ctx, token, filename) (contentLength, err)
    Put(ctx, token, filename, reader, contentType, contentLength) error
    Delete(ctx, token, filename) error
    IsNotExist(err) bool
    Purge(ctx, days) error
    IsRangeSupported() bool
    Type() string
}
```

Key storage behaviors:
- **Local**: Files at `basedir/token/filename`. Supports nested paths. Defense-in-depth path prefix check.
- **S3**: Object key = `token/filename`. `/` in filename creates virtual directory structure.
- **Storj**: Same as S3 — key = `token/filename`.
- **GDrive**: Flat only — rejects filenames containing `/`. No native nested path support.

## Conventions

### Filename Sanitization

- Use `sanitizePath()` for all user-supplied filenames (upload handlers, archive parsing, etc.)
- `sanitizePath()` preserves `/` separators, strips `..` and `.`, normalizes unicode, removes colons, limits depth to 10 and total length to 1024
- Individual path components capped at 255 bytes
- Reserved filenames (`.dir.json`) checked per-component

### Token & Auth

- `X-Upload-Token` header required for adding files to existing directories
- Deletion requires either `?delete=TOKEN` query param or `X-Deletion-Token` header
- Deletion tokens are stored in per-file `.metadata` JSON files

### Metadata

- Stored as `{filename}.metadata` alongside each file in storage
- Contains: ContentType, ContentLength, Downloads, MaxDownloads, MaxDate, DeletionToken, Encrypted, Compressed
- Accessed via `checkMetadata()` which enforces download limits and expiry

### Locking

- Per-file mutex via `sync.Map` keyed on `path.Join(token, filename)`
- Used for metadata reads/writes and directory index mutations

### Constants

| Constant | Value | Purpose |
|----------|-------|---------|
| `maxFilenameLength` | 255 | Max length per path component |
| `maxPathDepth` | 10 | Max number of path components |
| `maxPathLength` | 1024 | Max total path length |
| `maxTokenLength` | 200 | Max directory token length |
| `defaultMaxArchiveFiles` | 100 | Max files in a zip/tar archive |

## Security Constraints

- **No path traversal**: `..` components stripped by `sanitizePath()`, rejected by `buildPath()`
- **No absolute paths**: Leading `/` rejected by `buildPath()`
- **No backslashes**: Converted to `/` by `sanitizePath()`, rejected by `buildPath()`
- **No empty path components**: `//` rejected by `buildPath()`
- **Basedir escape prevention**: `buildPath()` verifies resolved path stays within `basedir/token/`
- **Reserved names**: `.dir.json` cannot be uploaded (stripped to `dir.json` by sanitization)
- **Unicode normalization**: Control/format/private-use characters removed
- **Constant-time comparison**: Deletion tokens and upload tokens compared via `subtle.ConstantTimeCompare`

## Linting Standards

Required checks before any commit:

```bash
gofmt -w $(find . -name "*.go" -not -path "./vendor/*")
go vet ./...
gocyclo -over 15 .
golangci-lint run --config .golangci.yml ./...
gosec ./...
go test ./...
```

- **gofmt**: Formatting must be clean
- **govet**: No issues allowed
- **gocyclo**: Cyclomatic complexity must be ≤ 15
- **golangci-lint**: CI uses `golangci-lint` (not the deprecated `golint`) with config in `.golangci.yml`. Enabled linters: `gofmt`, `govet`, `revive`, `staticcheck`, `gosimple`, `ineffassign`, `misspell`, `goimports`. Naming convention: `rURL` not `rUrl`, `CORSDomains` not `CorsDomains`.
- **gosec**: Security issues must be resolved. Install via `go install github.com/securego/gosec/v2/cmd/gosec@latest`. Run with `gosec ./...` or `gosec -exclude-generated -quiet ./...`.

## Testing

- Use `go test ./...` — runs all packages
- Tests use `gopkg.in/check.v1` (gocheck) and `testing` standard library
- Update tests when changing validation thresholds (length limits, reserved names, etc.)
- Storage tests use `t.TempDir()` for isolated local storage

## CLI Usage

```bash
# Build
go build -o transfer.ng .

# Run with local storage
./transfer.ng --listener ":8080" --provider local --basedir /tmp/uploads

# Run with S3
./transfer.ng --listener ":8080" --provider s3 --s3-bucket mybucket
```

## Bash Snippet (user-facing)

The `transfer()` function in README.md parses `X-Url-Directory` header (not body text) for the directory URL. Directory uploads use process substitution (`while read ... done < <(find ...)`) with `&` and `wait` for parallel uploads.

## Design Principles

- **No client-side JavaScript**: All web pages are pure HTML/CSS. QR codes, previews, and directory listings are rendered server-side. No JS frameworks, no inline scripts, no external script dependencies.
- **Server-side rendering**: All dynamic content (QR codes, file previews, directory listings) is generated on the server and delivered as static HTML.
- **Minimal dependencies**: The web UI uses only embedded HTML templates and CSS. No build tools, no bundlers, no npm.
