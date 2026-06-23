# Examples

This page shows current `transfer.ng` workflows. Replace `https://transfer.morawski.my` with your own host when self-hosting.

## Transfer CLI

Install the CLI:

```bash
curl -sL https://raw.githubusercontent.com/morawskidotmy/transfer.ng/main/install-transfer.sh | bash
```

Upload with the CLI:

```bash
# Single file
transfer file.txt

# Multiple files
transfer file1.txt file2.txt file3.txt

# Directory upload with preserved structure
transfer myfolder/

# Explicit concurrency instead of auto-tuned workers
transfer --workers=16 largefolder/

# Use a self-hosted instance
transfer --host=https://files.example.com file.txt
```

CLI flags and environment variables:

- `--host=URL` or `TRANSFER_HOST`
- `--workers=N` or `TRANSFER_WORKERS`
- `--delay=MS` or `TRANSFER_MIN_DELAY`
- `TRANSFER_MAX_RETRIES` with default `0` for unlimited retries
- `--insecure` to disable TLS verification
- `--update` to self-update

## Single-File Uploads

Upload a file with curl:

```bash
curl --upload-file ./hello.txt https://transfer.morawski.my/hello.txt
```

Upload from standard input:

```bash
grep 'error' /var/log/app.log | curl --upload-file - https://transfer.morawski.my/errors.log
```

Upload with PowerShell:

```powershell
Invoke-WebRequest -Method Put -InFile .\file.txt https://transfer.morawski.my/file.txt
```

Upload with wget:

```bash
wget --method PUT --body-file=/tmp/file.tar https://transfer.morawski.my/file.tar -O - -nv
```

## Directory Workflow

Create an empty directory and get an upload token:

```bash
curl -i -X POST https://transfer.morawski.my/dir
```

Add a file to that directory:

```bash
curl --upload-file ./report.pdf \
    https://transfer.morawski.my/TOKEN/report.pdf \
    -H "X-Upload-Token: SECRET"
```

Upload nested paths into the same directory:

```bash
curl --upload-file ./src/main.go \
    https://transfer.morawski.my/TOKEN/src/main.go \
    -H "X-Upload-Token: SECRET"
```

Upload a whole folder with plain curl:

```bash
cd ./myfolder && find . -type f | xargs -P 8 -I {} \
    curl -H "X-Upload-Token: SECRET" \
        --upload-file {} "https://transfer.morawski.my/TOKEN/{}"
```

List a directory:

```bash
curl https://transfer.morawski.my/TOKEN/
```

Delete a directory and all files in it:

```bash
curl -X DELETE https://transfer.morawski.my/TOKEN/ \
    -H "X-Upload-Token: SECRET"
```

## Downloads

Download a file:

```bash
curl https://transfer.morawski.my/TOKEN/hello.txt -o hello.txt
```

Force direct download behavior:

```bash
curl https://transfer.morawski.my/download/TOKEN/hello.txt -o hello.txt
```

Fetch only headers:

```bash
curl -I https://transfer.morawski.my/TOKEN/hello.txt
```

## Archive Downloads

Download a whole directory as zip:

```bash
curl -O https://transfer.morawski.my/zip/TOKEN/
```

Download a whole directory as tar.gz:

```bash
curl -O https://transfer.morawski.my/tar.gz/TOKEN/
```

Download a subdirectory as zip:

```bash
curl -O https://transfer.morawski.my/zip/TOKEN/photos/2026/
```

## Upload Options

Limit downloads:

```bash
curl --upload-file ./file.txt https://transfer.morawski.my/file.txt \
    -H "Max-Downloads: 5"
```

Set expiration:

```bash
curl --upload-file ./file.txt https://transfer.morawski.my/file.txt \
    -H "Max-Days: 7"
```

Encrypt on upload:

```bash
curl --upload-file ./secret.txt https://transfer.morawski.my/secret.txt \
    -H "X-Encrypt-Password: mysecret"
```

Decrypt on download:

```bash
curl https://transfer.morawski.my/TOKEN/secret.txt \
    -H "X-Decrypt-Password: mysecret" -o secret.txt
```

## File Deletion

Delete with query parameter:

```bash
curl -X DELETE "https://transfer.morawski.my/TOKEN/file.txt?delete=DELETION_TOKEN"
```

Delete with header:

```bash
curl -X DELETE https://transfer.morawski.my/TOKEN/file.txt \
    -H "X-Deletion-Token: DELETION_TOKEN"
```

## Malware Scanning

Ask the server to scan a file with ClamAV:

```bash
curl -X PUT --upload-file ./eicar.com https://transfer.morawski.my/eicar.com/scan
```

Submit a file to VirusTotal when the server is configured with an API key:

```bash
curl -X PUT --upload-file ./sample.bin https://transfer.morawski.my/sample.bin/virustotal
```

## Notes

- Every upload lives inside a directory token, even single-file uploads.
- `X-Url-Directory` and `X-Upload-Token` are returned on upload responses.
- Google Drive storage is flat-only and rejects nested paths containing `/`.
