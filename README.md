# [SECURITY WARNING](https://github.com/dutchcoders/transfer.sh/issues/670)

IP filter and HTTP auth bypass via unauthenticated X-Forwarded-For header spoofing


# transfer.sh [![Go Report Card](https://goreportcard.com/badge/github.com/dutchcoders/transfer.sh)](https://goreportcard.com/report/github.com/dutchcoders/transfer.sh) [![Docker pulls](https://img.shields.io/docker/pulls/dutchcoders/transfer.sh.svg)](https://hub.docker.com/r/dutchcoders/transfer.sh/) [![Build Status](https://github.com/dutchcoders/transfer.sh/actions/workflows/test.yml/badge.svg?branch=main)](https://github.com/dutchcoders/transfer.sh/actions/workflows/test.yml?query=branch%3Amain)

[![Go Report Card](https://goreportcard.com/badge/github.com/morawskidotmy/transfer.ng)](https://goreportcard.com/report/github.com/morawskidotmy/transfer.ng)
[![Build Status](https://github.com/morawskidotmy/transfer.ng/actions/workflows/test.yml/badge.svg?branch=main)](https://github.com/morawskidotmy/transfer.ng/actions/workflows/test.yml?query=branch%3Amain)

Easy and fast file sharing from the command-line. Self-hostable with support for S3, Google Drive, Storj, and local storage.

> [!IMPORTANT]
> **transfer.ng vs transfer.sh: Directory Support**
>
> Unlike the original transfer.sh, transfer.ng includes **gofile-style directories**. Every upload automatically gets its own directory, and you can group multiple files together, add files from different machines, list directory contents, and download entire directories as archives.
>
> See the [Directories](#directories) section for details.

## Features

- Upload and download files via curl, wget, or any HTTP client
- **Directory support** - group files, add from multiple machines, download as archive
- Server-side encryption (AES-256)
- Automatic compression for large files
- Virus scanning with ClamAV
- Rate limiting and IP filtering
- Multiple storage backends: S3, Google Drive, Storj, local filesystem
- QR codes for mobile transfers
- File preview for images, video, audio, and text

> [!TIP]
> **Missing a MIME type?** PRs adding new file extension mappings to [`server/mime_types.json`](server/mime_types.json) are always welcome.

## Quick Start

```bash
# Upload a file
curl --upload-file ./hello.txt https://transferng.example.com/hello.txt

# Download a file
curl https://transferng.example.com/TOKEN/hello.txt -o hello.txt

# Delete a file
curl -X DELETE "https://transferng.example.com/TOKEN/hello.txt?delete=DELETION_TOKEN"
```

> **Self-hosting?** See [host.md](host.md) for a complete guide to all CLI flags, storage backends, TLS, authentication, and deployment scenarios.

## Directories

Every upload in transfer.ng lives inside a **directory** identified by a token. Even a single file gets its own directory. This allows you to:

- Group multiple files together
- Add files from different machines to the same directory
- List all files in a directory
- Download all files as a zip or tar.gz archive
- Delete an entire directory at once

Each upload returns two headers:

| Header | Description |
|--------|-------------|
| `X-Url-Directory` | Listing URL of the directory |
| `X-Upload-Token` | Write-secret to add more files to the directory |

### Create a directory

```bash
curl -X POST https://transferng.example.com/dir
# Returns:
# Upload-Token: s3cretUploadToken
```

The directory URL is returned in the `X-Url-Directory` response header.

### Add files to a directory

```bash
curl --upload-file ./report.pdf \
    https://transferng.example.com/abcd1234/report.pdf \
    -H "X-Upload-Token: s3cretUploadToken"
```

### Upload a whole folder

```bash
cd ./myfolder && find . -type f | xargs -P 8 -I {} \
    curl -H "X-Upload-Token: s3cretUploadToken" \
        --upload-file {} "https://transferng.example.com/abcd1234/{}"
```

### List a directory

```bash
curl https://transferng.example.com/abcd1234/
# Returns list of file URLs
```

### Download as archive

```bash
curl -O https://transferng.example.com/abcd1234/.zip
curl -O https://transferng.example.com/abcd1234/.tar.gz
```

### Nested paths

Files can be uploaded with subdirectory structure preserved:

```bash
curl --upload-file ./src/main.go \
    https://transferng.example.com/abcd1234/src/main.go \
    -H "X-Upload-Token: s3cretUploadToken"
```

### Delete a file

```bash
curl -X DELETE "https://transferng.example.com/abcd1234/report.pdf?delete=DELETION_TOKEN"
```

Or using a header:

```bash
curl -X DELETE https://transferng.example.com/abcd1234/report.pdf \
    -H "X-Deletion-Token: DELETION_TOKEN"
```

## Upload Options

```bash
# Limit downloads
curl --upload-file ./file.txt https://transferng.example.com/file.txt \
    -H "Max-Downloads: 5"

# Set expiration
curl --upload-file ./file.txt https://transferng.example.com/file.txt \
    -H "Max-Days: 7"

# Encrypt on upload
curl --upload-file ./file.txt https://transferng.example.com/file.txt \
    -H "X-Encrypt-Password: mysecret"

# Decrypt on download
curl https://transferng.example.com/TOKEN/file.txt \
    -H "X-Decrypt-Password: mysecret"
```

## HTTP Headers

### Request Headers

| Header | Description |
|--------|-------------|
| `Max-Downloads` | Limit number of downloads |
| `Max-Days` | Days until file expires |
| `X-Encrypt-Password` | Encrypt file server-side (AES-256) |
| `X-Decrypt-Password` | Decrypt file on download |
| `X-Deletion-Token` | Token for deleting the file |
| `X-Upload-Token` | Directory write-secret |
| `Range` | Request partial content (bytes) |

### Response Headers

| Header | Description |
|--------|-------------|
| `X-Url-Delete` | URL to delete the file |
| `X-Url-Directory` | Directory listing URL |
| `X-Upload-Token` | Directory write-secret |
| `X-Remaining-Downloads` | Downloads remaining |
| `X-Remaining-Days` | Days remaining |

## Configuration

Run with local storage:

```bash
transfer.ng --provider=local --listener :8080 --basedir /data/
```

### Environment Variables

| Variable | Description |
|----------|-------------|
| `LISTENER` | HTTP listener address (default: `:80`) |
| `TLS_LISTENER` | HTTPS listener address |
| `TLS_LISTENER_ONLY` | Only listen on TLS |
| `TLS_CERT_FILE` | Path to TLS certificate |
| `TLS_PRIVATE_KEY` | Path to TLS private key |
| `FORCE_HTTPS` | Redirect HTTP to HTTPS |
| `BASEDIR` | Base directory for local/gdrive storage |
| `TEMP_PATH` | Temporary file directory |
| `MAX_UPLOAD_SIZE` | Max upload size in KB |
| `PURGE_DAYS` | Auto-purge files after N days |
| `PURGE_INTERVAL` | Purge check interval in hours (defaults to 24 when `PURGE_DAYS` is set) |
| `RATE_LIMIT` | Download requests per minute per IP |
| `RATE_LIMIT_UPLOADS` | Upload requests per minute per IP |
| `CLAMAV_TIMEOUT` | ClamAV scan timeout (default: 60s) |
| `COMPRESS_LARGE` | Compress files larger than this (e.g., `10m`) |
| `RANDOM_TOKEN_LENGTH` | Length of random tokens (default: 6) |
| `CORS_DOMAINS` | Comma-separated CORS allowed domains |
| `HTTP_AUTH_USER` | Basic auth username |
| `HTTP_AUTH_PASS` | Basic auth password |
| `HTTP_AUTH_HTPASSWD` | Path to htpasswd file |

### Storage Providers

#### S3

```bash
transfer.ng --provider=s3 \
    --aws-access-key KEY \
    --aws-secret-key SECRET \
    --bucket mybucket \
    --s3-region eu-west-1
```

For custom S3-compatible endpoints (MinIO, etc.), add `--s3-endpoint` and `--s3-path-style`.

#### Storj

```bash
transfer.ng --provider=storj \
    --storj-access ACCESS_GRANT \
    --storj-bucket mybucket
```

#### Google Drive

```bash
transfer.ng --provider=gdrive \
    --gdrive-client-json-filepath /path/to/client.json \
    --gdrive-local-config-path /path/to/config \
    --basedir /path/to/data
```

## Compression

Files larger than `--compress-large` are automatically compressed with zstd on upload and decompressed on download. This is transparent to users.

```bash
transfer.ng --provider=local --compress-large=10m
```

## Development

```bash
go run main.go --provider=local --listener :8080 --temp-path=/tmp/ --basedir=/tmp/
```

## Build

```bash
git clone https://github.com/morawskidotmy/transfer.ng.git
cd transfer.ng
go build -o transfer.ng main.go
```

## Docker

```bash
# Build
docker build -t transfer.ng:latest .

# Run with local storage
docker run -p 8080:8080 transfer.ng:latest --provider local --basedir /data/

# Run with custom UID/GID
docker build -t transfer.ng:noroot \
    --build-arg RUNAS=transferng \
    --build-arg PUID=1000 \
    --build-arg PGID=1000 .
docker run -p 8080:8080 transfer.ng:noroot --provider local --basedir /data/
```

Or use Docker Compose:

```bash
docker-compose up -d
```

## Shell Functions

### Bash/Zsh

Add to your `.bashrc` or `.zshrc`:

```bash
transfer() {
    if [ $# -eq 0 ]; then
        echo "Usage: transfer <file|directory> [file2 ...]"
        return 1
    fi
    local tmpdir=$(mktemp -d)
    curl --silent --show-error -D "$tmpdir/headers" -o "$tmpdir/body" -X POST "https://transfer.morawski.my/dir"
    local dir_url=$(grep -i '^X-Url-Directory:' "$tmpdir/headers" | sed 's/^[^:]*: *//')
    local upload_token=$(sed -n 's/^Upload-Token: //p' "$tmpdir/body")
    rm -rf "$tmpdir"
    if [ -z "$dir_url" ] || [ -z "$upload_token" ]; then
        echo "Failed to create directory"
        return 1
    fi
    local arg f
    for arg in "$@"; do
        if [ -d "$arg" ]; then
            while read -r f; do
                curl --silent --show-error -H "X-Upload-Token: $upload_token" \
                    --upload-file "$f" "${dir_url}$(basename "$f")" >/dev/null \
                    && echo "Uploaded: $(basename "$f")" &
            done < <(find "$arg" -type f)
            wait
        else
            curl --silent --show-error -H "X-Upload-Token: $upload_token" \
                --upload-file "$arg" "${dir_url}$(basename "$arg")" >/dev/null \
                && echo "Uploaded: $(basename "$arg")"
        fi
    done
    echo "Directory: $dir_url"
}
```

Usage:

```bash
transfer hello.txt
# Uploaded: hello.txt
# Directory: https://transfer.morawski.my/abcd1234/

transfer myfolder/
# Uploaded: file1.txt
# Uploaded: file2.txt
# Directory: https://transfer.morawski.my/efgh5678/

transfer file1.txt file2.txt file3.txt
# Uploaded: file1.txt
# Uploaded: file2.txt
# Uploaded: file3.txt
# Directory: https://transfer.morawski.my/ijkl9012/
```

## Credits

- **Remco Verhoef** - Original author (transfer.sh)
- **Andrea Spacca** - Maintainer
- **Stefan Benten** - Maintainer
- **morawskidotmy** - transfer.ng fork with directory support

Code released under the [MIT License](LICENSE).
