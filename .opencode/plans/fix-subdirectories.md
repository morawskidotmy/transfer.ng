# Fix Subdirectories and Routing Bugs

## Summary

Two bugs found via manual testing:
1. **Route ordering**: `/{action:(?:download|get|inline)}/{token}/{filename}` GET routes are registered AFTER `/{token}/{filename}`, so gorilla/mux matches the generic route first with token="download"/"get"/"inline".
2. **redirectToSubdirectory double-token**: `path.Join(s.proxyPath, token, filename)` produces `/TOKEN/TOKEN/sub/` instead of `/TOKEN/sub/` because the redirect URL already contains the token in the request path.

## Changes

### 1. server/server.go line 778-779 - Fix route ordering (setupRoutes)

Swap the order so action-prefixed routes come first:

Before:
```go
r.HandleFunc("/{token}/{filename:.+}", getHandlerFn).Methods("GET")
r.HandleFunc("/{action:(?:download|get|inline)}/{token}/{filename:.+}", getHandlerFn).Methods("GET")
```

After:
```go
r.HandleFunc("/{action:(?:download|get|inline)}/{token}/{filename:.+}", getHandlerFn).Methods("GET")
r.HandleFunc("/{token}/{filename:.+}", getHandlerFn).Methods("GET")
```

### 2. server/handlers.go line 1468 - Fix redirectToSubdirectory

Before (produces /TOKEN/TOKEN/sub/):
```go
http.Redirect(w, r, path.Join(s.proxyPath, token, filename)+"/", http.StatusMovedPermanently)
```

After (uses request path to produce /TOKEN/sub/):
```go
http.Redirect(w, r, r.URL.Path+"/", http.StatusMovedPermanently)
```

## Verification

- `go build ./...`
- `go test ./...`
- Manual tests: upload, download, directory listing, subdirectories, archives, /download/ /get/ /inline/ prefixes
