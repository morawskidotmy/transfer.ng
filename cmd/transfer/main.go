package main

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/fatih/color"
	"golang.org/x/term"
)

var (
	Version     = "dev"
	BuildCommit = "unknown"
)

const (
	defaultHost       = "https://transfer.morawski.my"
	defaultWorkers    = 4
	maxWorkers        = 8
	minWorkers        = 1
	defaultMaxRetries = 0
	defaultMinDelay   = 500
	defaultMaxDelay   = 30 * time.Second
	barWidth          = 30

	githubRepo    = "morawskidotmy/transfer.ng"
	githubRepoURL = "https://github.com/" + githubRepo + ".git"
	updateTimeout = 5 * time.Second
)

type Config struct {
	Host            string
	Workers         int
	MaxRetries      int
	Insecure        bool
	MinDelay        time.Duration
	WorkersExplicit bool
	ForceUpdate     bool
	ShowVersion     bool
	ShowHelp        bool
}

type UploadResult struct {
	Path    string
	URL     string
	Success bool
	Error   error
}

type DirResponse struct {
	DirectoryURL string
	UploadToken  string
}

type concurrencyLimiter struct {
	mu      sync.Mutex
	current int
	max     int
	min     int
	sem     chan struct{}
}

func newConcurrencyLimiter(initial, max, min int) *concurrencyLimiter {
	if initial < min {
		initial = min
	}
	if initial > max {
		initial = max
	}
	return &concurrencyLimiter{
		current: initial,
		max:     max,
		min:     min,
		sem:     make(chan struct{}, max),
	}
}

func (c *concurrencyLimiter) Acquire() {
	c.sem <- struct{}{}
}

func (c *concurrencyLimiter) Release() {
	<-c.sem
}

func (c *concurrencyLimiter) Current() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.current
}

func (c *concurrencyLimiter) Reduce() {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.current > c.min {
		c.current /= 2
		if c.current < c.min {
			c.current = c.min
		}
	}
}

func (c *concurrencyLimiter) Increase() {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.current < c.max {
		c.current++
	}
}

func (c *concurrencyLimiter) ShouldAllow() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.sem) < c.current
}

type globalThrottle struct {
	mu          sync.Mutex
	lastTime    time.Time
	minDelay    time.Duration
	maxDelay    time.Duration
	delay       time.Duration
	pauseUntil  time.Time
	serverPause time.Time
}

func newGlobalThrottle(minDelay time.Duration) *globalThrottle {
	if minDelay <= 0 {
		minDelay = time.Duration(defaultMinDelay) * time.Millisecond
	}
	return &globalThrottle{
		minDelay: minDelay,
		maxDelay: defaultMaxDelay,
		delay:    minDelay,
	}
}

func (t *globalThrottle) Wait() {
	for {
		t.mu.Lock()
		now := time.Now()

		if !t.serverPause.IsZero() {
			if now.Before(t.serverPause) {
				waitUntil := t.serverPause
				t.mu.Unlock()
				time.Sleep(time.Until(waitUntil))
				continue
			}
			t.serverPause = time.Time{}
		}

		if !t.pauseUntil.IsZero() {
			if now.Before(t.pauseUntil) {
				waitUntil := t.pauseUntil
				t.mu.Unlock()
				time.Sleep(time.Until(waitUntil))
				continue
			}
			t.pauseUntil = time.Time{}
		}

		delay := t.delay
		if delay <= 0 {
			delay = t.minDelay
		}

		if !t.lastTime.IsZero() {
			elapsed := now.Sub(t.lastTime)
			if elapsed < delay {
				sleepFor := delay - elapsed
				t.mu.Unlock()
				time.Sleep(sleepFor)
				continue
			}
		}
		t.lastTime = time.Now()
		t.mu.Unlock()
		return
	}
}

func (t *globalThrottle) RecordFailure(retryAfter time.Duration) time.Duration {
	t.mu.Lock()
	defer t.mu.Unlock()

	current := t.delay
	if current <= 0 {
		current = t.minDelay
	}

	nextDelay := current * 2
	if nextDelay > t.maxDelay {
		nextDelay = t.maxDelay
	}

	pauseFor := nextDelay
	if retryAfter > pauseFor {
		pauseFor = retryAfter
	}

	if retryAfter > nextDelay {
		nextDelay = retryAfter
		if nextDelay > t.maxDelay {
			nextDelay = t.maxDelay
		}
	}

	t.delay = nextDelay

	if retryAfter > 0 {
		t.serverPause = time.Now().Add(pauseFor)
	} else {
		t.pauseUntil = time.Now().Add(pauseFor)
	}

	waitTime := pauseFor
	if retryAfter <= 0 {
		jitterRange := waitTime / 2
		if jitterRange > 0 {
			// #nosec G404 -- math/rand used for retry jitter, not cryptographic
			waitTime += time.Duration(rand.Int63n(int64(jitterRange)))
		}
	}

	return waitTime
}

func (t *globalThrottle) RecordSuccess() {
	t.mu.Lock()
	defer t.mu.Unlock()

	t.pauseUntil = time.Time{}
	if t.delay > t.minDelay {
		nextDelay := t.delay - t.delay/4
		if nextDelay < t.minDelay {
			nextDelay = t.minDelay
		}
		t.delay = nextDelay
	}
}

type progressDisplay struct {
	mu             sync.Mutex
	dirURL         string
	fileName       string
	bytes          int64
	total          int64
	totalFiles     int64
	completedFiles int64
	workers        int
	isTTY          bool
}

func newProgressDisplay(dirURL string, totalFiles int64, workers int) *progressDisplay {
	return &progressDisplay{
		dirURL:     dirURL,
		totalFiles: totalFiles,
		workers:    workers,
		isTTY:      term.IsTerminal(int(os.Stdout.Fd())),
	}
}

func (p *progressDisplay) Update(fileName string, current, total int64) {
	p.mu.Lock()
	p.fileName = fileName
	p.bytes = current
	p.total = total
	p.mu.Unlock()
	p.render()
}

func (p *progressDisplay) FileCompleted() {
	p.mu.Lock()
	p.completedFiles++
	p.mu.Unlock()
	p.render()
}

func (p *progressDisplay) SetWorkers(n int) {
	p.mu.Lock()
	p.workers = n
	p.mu.Unlock()
}

func (p *progressDisplay) render() {
	if !p.isTTY {
		return
	}

	p.mu.Lock()
	name := p.fileName
	current := p.bytes
	total := p.total
	dirURL := p.dirURL
	completed := p.completedFiles
	totalF := p.totalFiles
	workers := p.workers
	p.mu.Unlock()

	var filePct float64
	if total > 0 {
		filePct = float64(current) / float64(total) * 100
	}

	filled := int(filePct / 100 * float64(barWidth))
	if filled > barWidth {
		filled = barWidth
	}
	bar := strings.Repeat("█", filled) + strings.Repeat("░", barWidth-filled)

	sizeStr := formatBytes(current)
	if total > 0 {
		sizeStr += " / " + formatBytes(total)
	}

	var sb strings.Builder
	sb.WriteString("\033[2K\r")
	sb.WriteString(name)
	sb.WriteString("\n")
	sb.WriteString("\033[2K\r")
	fmt.Fprintf(&sb, "[%s] %3.0f%% %s | %d/%d files | w%d\n", bar, filePct, sizeStr, completed, totalF, workers)
	sb.WriteString("\033[2K\r")
	sb.WriteString(dirURL)
	sb.WriteString("\n")
	sb.WriteString("\033[3A\r")

	fmt.Print(sb.String())
}

func (p *progressDisplay) Finish() {
	if p.isTTY {
		fmt.Print("\033[3B\n")
	}
}

func (p *progressDisplay) ShowError(fileName string) {
	p.mu.Lock()
	p.fileName = fileName
	p.bytes = 0
	p.total = 0
	p.mu.Unlock()
	p.render()
}

func formatBytes(b int64) string {
	const unit = 1024
	if b < unit {
		return fmt.Sprintf("%d B", b)
	}
	div, exp := int64(unit), 0
	for n := b / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(b)/float64(div), "KMGTPE"[exp])
}

func main() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	config := loadConfig()

	if config.ShowHelp {
		printUsage()
		os.Exit(0)
	}

	if config.ShowVersion {
		fmt.Printf("transfer %s (%s)\n", Version, BuildCommit)
		os.Exit(0)
	}

	if config.ForceUpdate {
		if err := selfUpdate(config, true); err != nil {
			fmt.Fprintf(os.Stderr, "Update failed: %v\n", err)
			os.Exit(1)
		}
		os.Exit(0)
	}

	args := os.Args[1:]

	files, basePaths, err := collectFiles(args)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error collecting files: %v\n", err)
		os.Exit(1)
	}

	if len(files) == 0 {
		fmt.Fprintf(os.Stderr, "No files to upload\n")
		os.Exit(1)
	}

	dirResp, err := createDirectory(config)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error creating directory: %v\n", err)
		os.Exit(1)
	}

	throttle := newGlobalThrottle(config.MinDelay)

	var limiter *concurrencyLimiter
	if config.WorkersExplicit {
		limiter = newConcurrencyLimiter(config.Workers, config.Workers, config.Workers)
	} else {
		limiter = newConcurrencyLimiter(defaultWorkers, maxWorkers, minWorkers)
	}

	display := newProgressDisplay(dirResp.DirectoryURL, int64(len(files)), limiter.Current())

	results := uploadFiles(config, dirResp, files, basePaths, throttle, display, limiter)

	display.Finish()

	printResults(results, dirResp.DirectoryURL)
}

func loadConfig() Config {
	config := Config{
		Host:       getEnv("TRANSFER_HOST", defaultHost),
		Workers:    getEnvInt("TRANSFER_WORKERS", defaultWorkers),
		MaxRetries: getEnvInt("TRANSFER_MAX_RETRIES", defaultMaxRetries),
		MinDelay:   time.Duration(getEnvInt("TRANSFER_MIN_DELAY", defaultMinDelay)) * time.Millisecond,
	}

	if os.Getenv("TRANSFER_WORKERS") != "" {
		config.WorkersExplicit = true
	}

	args := []string{}
	for i := 1; i < len(os.Args); i++ {
		arg := os.Args[i]
		if strings.HasPrefix(arg, "--host=") {
			config.Host = strings.TrimPrefix(arg, "--host=")
		} else if strings.HasPrefix(arg, "--workers=") {
			var workers int
			if _, err := fmt.Sscanf(strings.TrimPrefix(arg, "--workers="), "%d", &workers); err == nil {
				config.Workers = workers
				config.WorkersExplicit = true
			}
		} else if strings.HasPrefix(arg, "--delay=") {
			var delay int
			if _, err := fmt.Sscanf(strings.TrimPrefix(arg, "--delay="), "%d", &delay); err == nil {
				config.MinDelay = time.Duration(delay) * time.Millisecond
			}
		} else if arg == "--insecure" {
			config.Insecure = true
		} else if arg == "--update" {
			config.ForceUpdate = true
		} else if arg == "--version" || arg == "-v" {
			config.ShowVersion = true
		} else if arg == "--help" || arg == "-h" {
			config.ShowHelp = true
		} else {
			args = append(args, arg)
		}
	}

	os.Args = append([]string{os.Args[0]}, args...)

	return config
}

func collectFiles(args []string) ([]string, []string, error) {
	var files []string
	var basePaths []string
	seen := make(map[string]bool)

	for _, arg := range args {
		if strings.HasPrefix(arg, "--") {
			continue
		}

		// #nosec G703 -- arg is user-provided path, this is a CLI tool
		info, err := os.Stat(arg)
		if err != nil {
			return nil, nil, fmt.Errorf("cannot access %s: %w", arg, err)
		}

		if info.IsDir() {
			basePath := filepath.Dir(arg)
			// #nosec G703 -- arg is user-provided path, this is a CLI tool
			err := filepath.Walk(arg, func(path string, info os.FileInfo, err error) error {
				if err != nil {
					return err
				}
				if !info.IsDir() {
					absPath, err := filepath.Abs(path)
					if err != nil {
						return err
					}
					if !seen[absPath] {
						seen[absPath] = true
						files = append(files, path)
						basePaths = append(basePaths, basePath)
					}
				}
				return nil
			})
			if err != nil {
				return nil, nil, fmt.Errorf("error walking directory %s: %w", arg, err)
			}
		} else {
			absPath, err := filepath.Abs(arg)
			if err != nil {
				return nil, nil, err
			}
			if !seen[absPath] {
				seen[absPath] = true
				files = append(files, arg)
				basePaths = append(basePaths, filepath.Dir(arg))
			}
		}
	}

	return files, basePaths, nil
}

func newHTTPClient(config Config) *http.Client {
	if config.Insecure {
		// #nosec G402 -- --insecure is an explicit user opt-out of TLS verification
		return &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}}
	}
	return &http.Client{}
}

func createDirectory(config Config) (*DirResponse, error) {
	req, err := http.NewRequest("POST", config.Host+"/dir", nil)
	if err != nil {
		return nil, err
	}

	client := newHTTPClient(config)
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("failed to create directory: %s", string(body))
	}

	dirURL := resp.Header.Get("X-Url-Directory")
	uploadToken := resp.Header.Get("X-Upload-Token")

	if dirURL == "" || uploadToken == "" {
		return nil, fmt.Errorf("server did not return directory URL or upload token")
	}

	return &DirResponse{
		DirectoryURL: dirURL,
		UploadToken:  uploadToken,
	}, nil
}

func uploadFiles(config Config, dirResp *DirResponse, files []string, basePaths []string, throttle *globalThrottle, display *progressDisplay, limiter *concurrencyLimiter) []UploadResult {
	results := make([]UploadResult, len(files))
	var completed int64
	var successStreak int64

	var wg sync.WaitGroup
	for idx := range files {
		for !limiter.ShouldAllow() {
			time.Sleep(50 * time.Millisecond)
		}

		wg.Add(1)
		go func(fileIdx int) {
			defer wg.Done()

			limiter.Acquire()
			defer limiter.Release()

			file := files[fileIdx]
			basePath := basePaths[fileIdx]
			result := uploadFileWithRetry(config, dirResp, file, basePath, config.MaxRetries, throttle, display, limiter)
			results[fileIdx] = result

			atomic.AddInt64(&completed, 1)
			display.FileCompleted()
			display.SetWorkers(limiter.Current())

			if !result.Success {
				display.ShowError(result.Path)
				atomic.StoreInt64(&successStreak, 0)
				time.Sleep(200 * time.Millisecond)
			} else {
				streak := atomic.AddInt64(&successStreak, 1)
				if streak >= 10 && !config.WorkersExplicit {
					limiter.Increase()
					atomic.StoreInt64(&successStreak, 0)
					display.SetWorkers(limiter.Current())
				}
			}
		}(idx)
	}

	wg.Wait()
	return results
}

func uploadFileWithRetry(config Config, dirResp *DirResponse, filePath string, basePath string, maxRetries int, throttle *globalThrottle, display *progressDisplay, limiter *concurrencyLimiter) UploadResult {
	var lastErr error
	attempt := 0
	for {
		throttle.Wait()

		result := uploadFile(config, dirResp, filePath, basePath, display)
		if result.Success {
			throttle.RecordSuccess()
			return UploadResult{
				Path:    result.Path,
				URL:     result.URL,
				Success: result.Success,
				Error:   result.Error,
			}
		}

		lastErr = result.Error

		if result.Retryable {
			if maxRetries > 0 && attempt >= maxRetries-1 {
				break
			}
			if !config.WorkersExplicit {
				limiter.Reduce()
			}
			waitTime := throttle.RecordFailure(result.RetryAfter)
			time.Sleep(waitTime)
			attempt++
			continue
		}

		break
	}
	return UploadResult{
		Path:    filePath,
		Success: false,
		Error:   fmt.Errorf("failed after %d attempts: %w", attempt+1, lastErr),
	}
}

type uploadResult struct {
	Path       string
	URL        string
	Success    bool
	Error      error
	Retryable  bool
	RetryAfter time.Duration
}

func uploadFile(config Config, dirResp *DirResponse, filePath string, basePath string, display *progressDisplay) uploadResult {
	relPath := getRelativePath(filePath, basePath)

	parts := strings.Split(relPath, string(filepath.Separator))
	escapedParts := make([]string, len(parts))
	for i, part := range parts {
		escapedParts[i] = url.PathEscape(part)
	}
	uploadPath := strings.Join(escapedParts, "/")

	uploadURL := fmt.Sprintf("%s%s", dirResp.DirectoryURL, uploadPath)

	// #nosec G304,G703 -- filePath is user-provided file path, this is a CLI tool designed to upload user files
	file, err := os.Open(filePath)
	if err != nil {
		return uploadResult{Path: filePath, Success: false, Error: err}
	}
	defer func() { _ = file.Close() }()

	fileInfo, err := file.Stat()
	if err != nil {
		return uploadResult{Path: filePath, Success: false, Error: err}
	}

	totalSize := fileInfo.Size()
	progressReader := &progressReaderWrapper{
		reader:   file,
		total:    totalSize,
		fileName: filePath,
		display:  display,
	}

	req, err := http.NewRequest("PUT", uploadURL, progressReader)
	if err != nil {
		return uploadResult{Path: filePath, Success: false, Error: err}
	}

	req.ContentLength = totalSize
	req.Header.Set("X-Upload-Token", dirResp.UploadToken)

	client := newHTTPClient(config)
	// #nosec G704 -- uploadURL is constructed from user-configurable host, this is intentional for a CLI tool
	resp, err := client.Do(req)
	if err != nil {
		return uploadResult{Path: filePath, Success: false, Error: err, Retryable: true}
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode == http.StatusTooManyRequests ||
		resp.StatusCode == http.StatusRequestTimeout ||
		resp.StatusCode == http.StatusTooEarly ||
		resp.StatusCode == http.StatusInternalServerError ||
		resp.StatusCode == http.StatusServiceUnavailable ||
		resp.StatusCode == http.StatusBadGateway ||
		resp.StatusCode == http.StatusGatewayTimeout {
		retryAfter := parseRetryAfter(resp.Header.Get("Retry-After"))
		return uploadResult{
			Path:       filePath,
			Success:    false,
			Error:      fmt.Errorf("server error (%d)", resp.StatusCode),
			Retryable:  true,
			RetryAfter: retryAfter,
		}
	}

	if resp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(resp.Body)
		return uploadResult{
			Path:    filePath,
			Success: false,
			Error:   fmt.Errorf("upload failed with status %d: %s", resp.StatusCode, string(respBody)),
		}
	}

	respBody, _ := io.ReadAll(resp.Body)
	fileURL := strings.TrimSpace(string(respBody))

	return uploadResult{
		Path:    filePath,
		URL:     fileURL,
		Success: true,
	}
}

type progressReaderWrapper struct {
	reader   io.Reader
	total    int64
	current  int64
	fileName string
	display  *progressDisplay
}

func (pr *progressReaderWrapper) Read(p []byte) (int, error) {
	n, err := pr.reader.Read(p)
	pr.current += int64(n)
	pr.display.Update(pr.fileName, pr.current, pr.total)
	return n, err
}

func parseRetryAfter(value string) time.Duration {
	if value == "" {
		return 0
	}

	if seconds, err := strconv.Atoi(value); err == nil {
		return time.Duration(seconds) * time.Second
	}

	if t, err := time.Parse(time.RFC1123, value); err == nil {
		d := time.Until(t)
		if d > 0 {
			return d
		}
	}

	return 0
}

func getRelativePath(filePath string, basePath string) string {
	absPath, err := filepath.Abs(filePath)
	if err != nil {
		return filepath.Base(filePath)
	}

	absBase, err := filepath.Abs(basePath)
	if err != nil {
		return filepath.Base(filePath)
	}

	relPath, err := filepath.Rel(absBase, absPath)
	if err != nil {
		return filepath.Base(filePath)
	}

	return relPath
}

func printResults(results []UploadResult, dirURL string) {
	var success, failed int
	var failures []UploadResult
	for _, r := range results {
		if r.Success {
			success++
		} else {
			failed++
			failures = append(failures, r)
		}
	}

	fmt.Println()
	fmt.Printf("%s\n", strings.Repeat("─", 60))
	fmt.Printf("Upload complete: %s, %s\n",
		color.GreenString("%d successful", success),
		color.RedString("%d failed", failed))
	fmt.Printf("\nDirectory: %s\n", color.CyanString(dirURL))

	if len(failures) > 0 {
		fmt.Printf("\n%s\n", color.RedString("Failed files:"))
		for _, f := range failures {
			fmt.Printf("  %s %s\n", color.RedString("✗"), f.Path)
			fmt.Printf("    %s\n", color.YellowString(f.Error.Error()))
		}
	}
}

func getCacheDir() string {
	cacheDir, err := os.UserCacheDir()
	if err != nil {
		return ""
	}
	dir := filepath.Join(cacheDir, "transfer-cli")
	_ = os.MkdirAll(dir, 0700)
	return dir
}

func shouldCheckUpdate() bool {
	cacheDir := getCacheDir()
	if cacheDir == "" {
		return true
	}

	markerFile := filepath.Join(cacheDir, ".last-update-check")
	info, err := os.Stat(markerFile)
	if err != nil {
		return true
	}

	return time.Since(info.ModTime()) > 24*time.Hour
}

func markUpdateChecked() {
	cacheDir := getCacheDir()
	if cacheDir == "" {
		return
	}

	markerFile := filepath.Join(cacheDir, ".last-update-check")
	_ = os.WriteFile(markerFile, []byte(time.Now().Format(time.RFC3339)), 0600)
}

func getLatestCommit(config Config) (string, error) {
	client := &http.Client{Timeout: updateTimeout}
	if config.Insecure {
		// #nosec G402 -- --insecure is an explicit user opt-out of TLS verification
		client.Transport = &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}
	}

	req, err := http.NewRequest("GET", "https://api.github.com/repos/"+githubRepo+"/commits/main", nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Accept", "application/vnd.github.v3+json")

	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("GitHub API returned status %d", resp.StatusCode)
	}

	var result struct {
		SHA string `json:"sha"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", err
	}

	return result.SHA, nil
}

func selfUpdate(config Config, verbose bool) error {
	if !verbose && !shouldCheckUpdate() {
		return nil
	}

	if verbose {
		fmt.Println("Checking for updates...")
	}

	latestCommit, err := getLatestCommit(config)
	if err != nil {
		if verbose {
			fmt.Fprintf(os.Stderr, "Failed to check for updates: %v\n", err)
		}
		return err
	}

	markUpdateChecked()

	if BuildCommit == latestCommit {
		if verbose {
			fmt.Printf("Already up to date (commit %s)\n", BuildCommit[:7])
		}
		return nil
	}

	if verbose {
		fmt.Printf("Updating from %s to %s...\n", BuildCommit[:7], latestCommit[:7])
	}

	if err := buildAndReplace(latestCommit, verbose); err != nil {
		return err
	}

	if verbose {
		fmt.Printf("Updated to commit %s\n", latestCommit[:7])
	}

	return nil
}

func buildAndReplace(commit string, verbose bool) error {
	tmpDir, err := os.MkdirTemp("", "transfer-update-*")
	if err != nil {
		return fmt.Errorf("failed to create temp directory: %w", err)
	}
	defer func() { _ = os.RemoveAll(tmpDir) }()

	if verbose {
		fmt.Println("Cloning repository...")
	}

	// #nosec G204 -- githubRepoURL is a constant, tmpDir is a temp directory we created
	cloneCmd := exec.Command("git", "clone", githubRepoURL, tmpDir)
	cloneCmd.Stdout = nil
	cloneCmd.Stderr = nil
	if err := cloneCmd.Run(); err != nil {
		return fmt.Errorf("failed to clone repository: %w", err)
	}

	if verbose {
		fmt.Printf("Verifying commit %s...\n", commit[:7])
	}

	// #nosec G204 -- commit is from GitHub API for our own repo, tmpDir is a temp directory we created
	checkoutCmd := exec.Command("git", "checkout", commit)
	checkoutCmd.Dir = tmpDir
	checkoutCmd.Stdout = nil
	checkoutCmd.Stderr = nil
	if err := checkoutCmd.Run(); err != nil {
		return fmt.Errorf("failed to checkout commit %s: %w", commit[:7], err)
	}

	if verbose {
		fmt.Println("Building binary...")
	}

	// #nosec G204 -- commit is from GitHub API for our own repo, tmpDir is a temp directory we created
	buildCmd := exec.Command("go", "build",
		"-ldflags", fmt.Sprintf("-X main.Version=%s -X main.BuildCommit=%s", commit[:7], commit),
		"-o", filepath.Join(tmpDir, "transfer"),
		"./cmd/transfer")
	buildCmd.Dir = tmpDir
	buildCmd.Stdout = nil
	buildCmd.Stderr = nil
	if err := buildCmd.Run(); err != nil {
		return fmt.Errorf("failed to build binary: %w", err)
	}

	// #nosec G304 -- tmpDir is a temp directory we created, not user input
	newBinary, err := os.ReadFile(filepath.Join(tmpDir, "transfer"))
	if err != nil {
		return fmt.Errorf("failed to read built binary: %w", err)
	}

	if _, err := replaceExecutable(newBinary); err != nil {
		return err
	}

	return nil
}

func replaceExecutable(binaryData []byte) (string, error) {
	execPath, err := os.Executable()
	if err != nil {
		return "", fmt.Errorf("failed to get executable path: %w", err)
	}

	execPath, err = filepath.EvalSymlinks(execPath)
	if err != nil {
		return "", fmt.Errorf("failed to resolve executable path: %w", err)
	}

	info, err := os.Stat(execPath)
	if err != nil {
		return "", fmt.Errorf("failed to stat executable: %w", err)
	}

	tmpBinary := execPath + ".new"
	// #nosec G306,G703 -- binary needs execute permission, tmpBinary is derived from current executable path
	if err := os.WriteFile(tmpBinary, binaryData, info.Mode().Perm()); err != nil {
		return "", fmt.Errorf("failed to write new binary: %w", err)
	}

	backupPath := execPath + ".bak"
	_ = os.Remove(backupPath)

	if err := os.Rename(execPath, backupPath); err != nil {
		_ = os.Remove(tmpBinary)
		return "", fmt.Errorf("failed to backup current binary: %w", err)
	}

	if err := os.Rename(tmpBinary, execPath); err != nil {
		_ = os.Rename(backupPath, execPath)
		return "", fmt.Errorf("failed to replace binary: %w", err)
	}

	_ = os.Remove(backupPath)

	return execPath, nil
}

func printUsage() {
	fmt.Println("transfer - Fast file sharing from the command line")
	fmt.Println()
	fmt.Println("Usage:")
	fmt.Println("  transfer [options] <file|directory> [file2 ...]")
	fmt.Println()
	fmt.Println("Options:")
	fmt.Println("  --host=URL           Server URL (default: https://transfer.morawski.my)")
	fmt.Println("  --workers=N          Number of parallel upload workers (default: auto)")
	fmt.Println("  --delay=MS           Minimum delay between requests in ms (default: 500)")
	fmt.Println("  --insecure           Disable TLS verification")
	fmt.Println("  --update             Update to the latest version and exit")
	fmt.Println("  --version, -v        Show version")
	fmt.Println("  --help, -h           Show this help message")
	fmt.Println()
	fmt.Println("Environment variables:")
	fmt.Println("  TRANSFER_HOST          Server URL")
	fmt.Println("  TRANSFER_WORKERS       Number of parallel workers (disables auto)")
	fmt.Println("  TRANSFER_MAX_RETRIES   Maximum retry attempts (default: 0 = unlimited)")
	fmt.Println("  TRANSFER_MIN_DELAY     Minimum delay between requests in ms (default: 500)")
	fmt.Println()
	fmt.Println("Examples:")
	fmt.Println("  transfer file.txt")
	fmt.Println("  transfer file1.txt file2.txt file3.txt")
	fmt.Println("  transfer myfolder/")
	fmt.Println("  transfer --workers=2 largefolder/")
	fmt.Println("  transfer --update")
}

func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

func getEnvInt(key string, defaultValue int) int {
	if value := os.Getenv(key); value != "" {
		var intVal int
		if _, err := fmt.Sscanf(value, "%d", &intVal); err == nil {
			return intVal
		}
	}
	return defaultValue
}
