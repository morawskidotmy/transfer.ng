# Hosting transfer.ng

## Quick Start

Minimal setup with local storage:

```bash
transfer.ng --provider=local --listener :8080 --basedir /data/
```

Test it:

```bash
curl --upload-file hello.txt http://localhost:8080/hello.txt
```

## Client Upload Utility

For users who want a fast CLI client with parallel uploads, directory support, and automatic retries, see the [Transfer CLI](README.md#transfer-cli) section in the main README.

```bash
# Install the transfer CLI
curl -sL https://raw.githubusercontent.com/morawskidotmy/transfer.ng/main/install-transfer.sh | bash

# Upload files and directories
transfer file.txt
transfer myfolder/
```

The CLI supports custom hosts via `--host` or `TRANSFER_HOST` environment variable, making it easy to use with self-hosted instances.

## All Flags

### Network

| Flag | Env Var | Default | Description |
|------|---------|---------|-------------|
| `--listener` | `LISTENER` | `127.0.0.1:8080` | HTTP listen address |
| `--tls-listener` | `TLS_LISTENER` | `127.0.0.1:8443` | HTTPS listen address |
| `--tls-listener-only` | `TLS_LISTENER_ONLY` | `false` | Listen only on TLS (no plain HTTP) |
| `--tls-cert-file` | `TLS_CERT_FILE` | `""` | Path to TLS certificate file |
| `--tls-private-key` | `TLS_PRIVATE_KEY` | `""` | Path to TLS private key file |
| `--lets-encrypt-hosts` | `HOSTS` | `""` | Comma-separated hosts for Let's Encrypt auto-TLS |
| `--lets-encrypt-cache` | `LETS_ENCRYPT_CACHE` | `"./cache/"` | Directory for Let's Encrypt certificate cache |
| `--force-https` | `FORCE_HTTPS` | `false` | Redirect all HTTP to HTTPS |
| `--proxy-path` | `PROXY_PATH` | `""` | URL prefix when behind a reverse proxy (e.g. `/sharing`) |
| `--proxy-port` | `PROXY_PORT` | `""` | Port of the proxy when behind one |
| `--profile-listener` | `PROFILE_LISTENER` | `""` | pprof debug listener (e.g. `127.0.0.1:6060`) |
| `--profiler` | `PROFILER` | `false` | Enable Go pprof profiling |

### Storage Provider

| Flag | Env Var | Default | Description |
|------|---------|---------|-------------|
| `--provider` | `PROVIDER` | `""` | Storage backend: `local`, `s3`, `gdrive`, `storj` |
| `--basedir` | `BASEDIR` | `""` | Base directory for local/GDrive storage |
| `--temp-path` | `TEMP_PATH` | `os.TempDir()` | Directory for temporary files |

#### S3 (`--provider=s3`)

| Flag | Env Var | Description |
|------|---------|-------------|
| `--aws-access-key` | `AWS_ACCESS_KEY` | AWS access key ID |
| `--aws-secret-key` | `AWS_SECRET_KEY` | AWS secret access key |
| `--bucket` | `BUCKET` | S3 bucket name |
| `--s3-region` | `S3_REGION` | S3 region (default: `eu-west-1`) |
| `--s3-endpoint` | `S3_ENDPOINT` | Custom S3 endpoint (MinIO, etc.) |
| `--s3-no-multipart` | `S3_NO_MULTIPART` | Disable multipart uploads |
| `--s3-path-style` | `S3_PATH_STYLE` | Force path-style URLs (required for MinIO) |

#### Google Drive (`--provider=gdrive`)

| Flag | Env Var | Description |
|------|---------|-------------|
| `--gdrive-client-json-filepath` | `GDRIVE_CLIENT_JSON_FILEPATH` | Path to OAuth client JSON |
| `--gdrive-local-config-path` | `GDRIVE_LOCAL_CONFIG_PATH` | Path to store tokens |
| `--gdrive-chunk-size` | `GDRIVE_CHUNK_SIZE` | Upload chunk size in MB (default: 16) |

#### Storj (`--provider=storj`)

| Flag | Env Var | Description |
|------|---------|-------------|
| `--storj-access` | `STORJ_ACCESS` | Storj access grant |
| `--storj-bucket` | `STORJ_BUCKET` | Storj bucket name |

### Security

| Flag | Env Var | Default | Description |
|------|---------|---------|-------------|
| `--insecure` | `INSECURE` | `false` | **Disable** IP filtering and CORS checks — use only when a reverse proxy or firewall handles security |
| `--ip-whitelist` | `IP_WHITELIST` | `""` | Comma-separated IPs allowed to connect |
| `--ip-blacklist` | `IP_BLACKLIST` | `""` | Comma-separated IPs denied from connecting |
| `--http-auth-user` | `HTTP_AUTH_USER` | `""` | HTTP basic auth username |
| `--http-auth-pass` | `HTTP_AUTH_PASS` | `""` | HTTP basic auth password |
| `--http-auth-htpasswd` | `HTTP_AUTH_HTPASSWD` | `""` | Path to htpasswd file for auth |
| `--http-auth-ip-whitelist` | `HTTP_AUTH_IP_WHITELIST` | `""` | IPs that can upload without auth |
| `--cors-domains` | `CORS_DOMAINS` | `""` | Comma-separated CORS-allowed origins |

### Upload Limits

| Flag | Env Var | Default | Description |
|------|---------|---------|-------------|
| `--max-upload-size` | `MAX_UPLOAD_SIZE` | `0` | Max upload size in KB (`0` = unlimited) |
| `--rate-limit` | `RATE_LIMIT` | `0` | Max download requests per minute per IP (`0` = unlimited) |
| `--rate-limit-uploads` | `RATE_LIMIT_UPLOADS` | `0` | Max upload requests per minute per IP (`0` = unlimited) |
| `--rate-limit-archives` | `RATE_LIMIT_ARCHIVES` | `0` | Max archive download requests per minute per IP (`0` = unlimited) |
| `--max-dir-size` | `MAX_DIR_SIZE` | `0` | Rolling directory size cap (e.g. `5g`, `500m`). On new upload, oldest files in that directory are deleted until the new file fits. A single file larger than the cap is rejected. `0` = unlimited |
| `--max-dir-files` | `MAX_DIR_FILES` | `0` | Max number of files per directory. `0` = unlimited |
| `--max-archive-files` | `MAX_ARCHIVE_FILES` | `100` | Max files in a zip/tar.gz archive download |
| `--max-archive-size` | `MAX_ARCHIVE_SIZE` | `0` | Max total size of files in an archive download (e.g. `5g`, `500m`). `0` = use max-upload-size |

Directory uploads always create or use a directory token. `MAX_DIR_SIZE` is enforced per directory, not globally across storage.

### Retention

| Flag | Env Var | Default | Description |
|------|---------|---------|-------------|
| `--purge-days` | `PURGE_DAYS` | `0` | Auto-delete files after N days |
| `--purge-interval` | `PURGE_INTERVAL` | `24` (when `--purge-days` set) | How often (hours) to check for expired files |

### Compression

| Flag | Env Var | Default | Description |
|------|---------|---------|-------------|
| `--compress-large` | `COMPRESS_LARGE` | `10m` | Transparently zstd-compress files larger than this (e.g. `10m`, `1g`). Set to `0` to disable |

Compressed files are decompressed automatically on download and in directory archives. Range requests are disabled for transformed content because stored byte offsets do not match served bytes.

### Timeouts

| Flag | Env Var | Default | Description |
|------|---------|---------|-------------|
| `--read-header-timeout` | `READ_HEADER_TIMEOUT` | `10s` | HTTP read header timeout |
| `--read-timeout` | `READ_TIMEOUT` | `5m` | HTTP read timeout |
| `--write-timeout` | `WRITE_TIMEOUT` | `10m` | HTTP write timeout |
| `--idle-timeout` | `IDLE_TIMEOUT` | `2m` | HTTP idle timeout |

### Virus Scanning

| Flag | Env Var | Default | Description |
|------|---------|---------|-------------|
| `--clamav-host` | `CLAMAV_HOST` | `""` | ClamAV daemon address |
| `--clamav-timeout` | `CLAMAV_TIMEOUT` | `60s` | ClamAV scan timeout |
| `--perform-clamav-prescan` | `PERFORM_CLAMAV_PRESCAN` | `false` | Scan every upload with ClamAV before storing |
| `--virustotal-key` | `VIRUSTOTAL_KEY` | `""` | VirusTotal API key |

### Misc

| Flag | Env Var | Default | Description |
|------|---------|---------|-------------|
| `--random-token-length` | `RANDOM_TOKEN_LENGTH` | `10` | Length of random file/directory tokens |
| `--log` | `LOG` | `""` | Log file path (logs to stdout if empty) |
| `--web-path` | `WEB_PATH` | `""` | Path to custom static web assets |
| `--email-contact` | `EMAIL_CONTACT` | `""` | Contact email shown on the web UI |
| `--ga-key` | `GA_KEY` | `""` | Google Analytics tracking ID |
| `--uservoice-key` | `USERVOICE_KEY` | `""` | UserVoice widget key |

### Supported Go / CI

The module targets Go `1.26` with toolchain `go1.26.4`. CI installs Go `1.26.4` for tests, formatting, security scanning, Docker/release builds, and builds golangci-lint from source with that same Go version so linting supports the module target.

## Hosting Scenarios

### Behind a Reverse Proxy (Recommended)

When Nginx/Caddy/Traefik handles TLS, restrict the app to localhost and disable its own security:

```bash
transfer.ng --provider=local \
    --listener 127.0.0.1:8080 \
    --basedir /data \
    --insecure \
    --proxy-path /sharing
```

The `--insecure` flag disables IP filtering and CORS checks since the reverse proxy handles those. The `--proxy-path` tells the app it's served under a sub-path.

### Public-Facing with Let's Encrypt

```bash
transfer.ng --provider=local \
    --listener :80 \
    --tls-listener :443 \
    --lets-encrypt-hosts transfer.example.com \
    --force-https \
    --basedir /data
```

### Public-Facing with Own TLS Certificates

```bash
transfer.ng --provider=local \
    --tls-listener :443 \
    --tls-listener-only \
    --tls-cert-file /etc/certs/fullchain.pem \
    --tls-private-key /etc/certs/privkey.pem \
    --basedir /data
```

### With HTTP Basic Auth

```bash
transfer.ng --provider=local \
    --listener :8080 \
    --basedir /data \
    --http-auth-user admin \
    --http-auth-pass changeme
```

Or with an htpasswd file:

```bash
transfer.ng --provider=local \
    --listener :8080 \
    --basedir /data \
    --http-auth-htpasswd /etc/transfer.ng/.htpasswd
```

### With IP Whitelist

```bash
transfer.ng --provider=local \
    --listener :8080 \
    --basedir /data \
    --ip-whitelist 192.168.1.0/24,10.0.0.0/8
```

### S3 Backend (MinIO Example)

```bash
transfer.ng --provider=s3 \
    --listener :8080 \
    --s3-endpoint http://minio:9000 \
    --s3-region us-east-1 \
    --s3-path-style \
    --aws-access-key minioadmin \
    --aws-secret-key minioadmin \
    --bucket transfers
```

## Docker

```bash
docker run -p 8080:8080 \
    -v /data:/data \
    transfer.ng:latest \
    --provider local --basedir /data
```

## Environment Variables Only

Every flag has a corresponding `UPPERCASE_UNDERSCORED` env var. You can run without any flags:

```bash
export PROVIDER=local
export LISTENER=:8080
export BASEDIR=/data
transfer.ng
```
