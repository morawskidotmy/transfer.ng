# transfer.ng vs transfer.sh

This document provides a detailed comparison between **transfer.ng** (this project) and the original **transfer.sh**.

## Overview

| Feature | transfer.sh | transfer.ng |
|---------|-------------|-------------|
| **Status** | Archived/unmaintained | Active development |
| **Directory support** | No | Yes (gofile-style) |
| **Upload token** | No | Yes (write-secret per directory) |
| **Nested paths** | No | Yes |
| **Directory archives** | No | Yes (zip/tar.gz) |
| **Rolling size cap** | No | Yes (`--max-dir-size`) |
| **File count limit** | No | Yes (`--max-dir-files`) |

## Key Differences

### 1. Directory System

**transfer.sh**: Each file gets a random token. Files are independent.

```bash
# transfer.sh
curl --upload-file ./file.txt https://transfer.sh/file.txt
# Returns: https://transfer.sh/abc123/file.txt
```

**transfer.ng**: Every upload lives in a directory. Multiple files can be grouped together.

```bash
# transfer.ng
curl -X POST https://transfer.morawski.my/dir
# Returns: X-Upload-Token: secret
#          X-Url-Directory: https://transfer.morawski.my/abc123/

curl --upload-file ./file.txt https://transfer.morawski.my/abc123/file.txt \
    -H "X-Upload-Token: secret"
```

### 2. Adding Files to Existing Directories

**transfer.sh**: Not possible. Each upload creates a new token.

**transfer.ng**: Use `X-Upload-Token` header to add files to an existing directory.

```bash
# Add files from different machines to the same directory
curl --upload-file ./report.pdf https://transfer.morawski.my/abc123/report.pdf \
    -H "X-Upload-Token: secret"

# From another machine:
curl --upload-file ./data.csv https://transfer.morawski.my/abc123/data.csv \
    -H "X-Upload-Token: secret"
```

### 3. Nested Paths

**transfer.sh**: Flat file structure within each token.

**transfer.ng**: Supports subdirectory structure.

```bash
curl --upload-file ./src/main.go https://transfer.morawski.my/abc123/src/main.go \
    -H "X-Upload-Token: secret"
```

### 4. Directory Listing

**transfer.sh**: Not available.

**transfer.ng**: List all files in a directory.

```bash
curl https://transfer.morawski.my/abc123/
# Returns list of file URLs (plain text for curl, HTML for browsers)
```

### 5. Directory Archives

**transfer.sh**: Not available.

**transfer.ng**: Download entire directories as archives.

```bash
# Download as zip
curl -O https://transfer.morawski.my/zip/abc123/

# Download as tar.gz
curl -O https://transfer.morawski.my/tar.gz/abc123/

# Download subdirectory
curl -O https://transfer.morawski.my/zip/abc123/photos/2026/
```

### 6. Directory Size Management

**transfer.sh**: No built-in size limits per upload group.

**transfer.ng**: Rolling size cap with `--max-dir-size`.

```bash
# Keep directory under 5GB; oldest files are deleted on new upload
transfer.ng --max-dir-size=5g
```

### 7. File Count Limits

**transfer.sh**: No file count limits.

**transfer.ng**: Optional file count limit with `--max-dir-files`.

```bash
# Max 100 files per directory
transfer.ng --max-dir-files=100
```

## Shared Features

Both projects support:

- Upload via PUT/POST/curl
- Server-side encryption (AES-256)
- Automatic compression for large files
- Virus scanning with ClamAV
- Rate limiting and IP filtering
- Multiple storage backends (S3, Google Drive, Storj, local)
- QR codes for mobile transfers
- File preview (images, video, audio, text)
- Download limits (`Max-Downloads`)
- Expiration (`Max-Days`)
- Range requests for partial downloads
- Deletion tokens

## Why Fork?

transfer.sh was archived and unmaintained. The directory system was added to transfer.ng to support:

1. **Grouping related files** - Upload multiple files as a set
2. **Multi-machine uploads** - Add files from different locations to the same directory
3. **Bulk downloads** - Download entire directories as archives
4. **Better organization** - Nested paths and directory listings

See the main [README](README.md) for full documentation.

## Security Note

**Important Security Fix**: transfer.ng has addressed the IP filter and HTTP auth bypass vulnerability from transfer.sh (see [issue](https://github.com/dutchcoders/transfer.sh/issues/670)) with secure proxy settings. This security issue is **not present** in transfer.ng.

## Migration from transfer.sh

transfer.ng is API-compatible for basic single-file uploads:

```bash
# This works the same in both:
curl --upload-file ./hello.txt https://transfer.morawski.my/hello.txt
```

The difference is transfer.ng returns additional headers:

| Header | Description |
|--------|-------------|
| `X-Url-Directory` | Directory listing URL |
| `X-Upload-Token` | Write-secret for adding more files |

Existing transfer.sh client scripts will continue to work. The extra headers are additive and can be ignored.

## Code Differences

The diff percentage badge in the README shows how much of the Go codebase differs from transfer.sh. Key areas of divergence:

- `server/directory.go` - Directory creation, listing, archive, and delete logic
- `server/handlers.go` - Upload, download, metadata, and response header logic
- `server/server.go` - Routing for directory, archive, and nested-path endpoints
- `server/storage/` - Storage backend support for nested paths and range handling
- `cmd/cmd.go` - CLI flags including `--max-dir-size`, `--max-dir-files`, and archive limits

## Why Fork?

transfer.sh was archived and unmaintained. The directory system was added to transfer.ng to support:

1. **Grouping related files** - Upload multiple files as a set
2. **Multi-machine uploads** - Add files from different locations to the same directory
3. **Bulk downloads** - Download entire directories as archives
4. **Better organization** - Nested paths and directory listings

See the main [README](README.md) for full documentation.
