package main

import (
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/fatih/color"
)

const (
	defaultHost       = "https://transfer.morawski.my"
	defaultWorkers    = 8
	defaultMaxRetries = 3
)

type Config struct {
	Host       string
	Workers    int
	MaxRetries int
	Insecure   bool
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

func main() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	config := loadConfig()
	args := os.Args[1:]

	// Collect all files to upload
	files, basePaths, err := collectFiles(args)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error collecting files: %v\n", err)
		os.Exit(1)
	}

	if len(files) == 0 {
		fmt.Fprintf(os.Stderr, "No files to upload\n")
		os.Exit(1)
	}

	// Create directory
	dirResp, err := createDirectory(config)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error creating directory: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("%s\n", color.CyanString("Directory created: %s", dirResp.DirectoryURL))
	fmt.Printf("%s\n\n", color.YellowString("Uploading %d file(s) with %d workers...", len(files), config.Workers))

	// Upload files in parallel
	results := uploadFiles(config, dirResp, files, basePaths)

	// Print results
	printResults(results)
}

func loadConfig() Config {
	config := Config{
		Host:       getEnv("TRANSFER_HOST", defaultHost),
		Workers:    getEnvInt("TRANSFER_WORKERS", defaultWorkers),
		MaxRetries: getEnvInt("TRANSFER_MAX_RETRIES", defaultMaxRetries),
	}

	// Parse command line flags
	args := []string{}
	for i := 1; i < len(os.Args); i++ {
		arg := os.Args[i]
		if strings.HasPrefix(arg, "--host=") {
			config.Host = strings.TrimPrefix(arg, "--host=")
		} else if strings.HasPrefix(arg, "--workers=") {
			var workers int
			if _, err := fmt.Sscanf(strings.TrimPrefix(arg, "--workers="), "%d", &workers); err == nil {
				config.Workers = workers
			}
		} else if arg == "--insecure" {
			config.Insecure = true
		} else {
			args = append(args, arg)
		}
	}

	// Update os.Args to only contain file arguments
	os.Args = append([]string{os.Args[0]}, args...)

	return config
}

func collectFiles(args []string) ([]string, []string, error) {
	var files []string
	var basePaths []string
	seen := make(map[string]bool)

	for _, arg := range args {
		// Skip flags
		if strings.HasPrefix(arg, "--") {
			continue
		}

		// #nosec G703 -- arg is user-provided path, this is a CLI tool
		info, err := os.Stat(arg)
		if err != nil {
			return nil, nil, fmt.Errorf("cannot access %s: %w", arg, err)
		}

		if info.IsDir() {
			// Walk directory recursively
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

func uploadFiles(config Config, dirResp *DirResponse, files []string, basePaths []string) []UploadResult {
	results := make([]UploadResult, len(files))
	var completed int64

	// Create work channel
	work := make(chan int, len(files))
	for i := range files {
		work <- i
	}
	close(work)

	// Start workers
	var wg sync.WaitGroup
	for i := 0; i < config.Workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for idx := range work {
				file := files[idx]
				basePath := basePaths[idx]
				result := uploadFileWithRetry(config, dirResp, file, basePath, config.MaxRetries)
				results[idx] = result

				current := atomic.AddInt64(&completed, 1)
				printProgress(current, int64(len(files)), result)
			}
		}()
	}

	wg.Wait()
	return results
}

func uploadFileWithRetry(config Config, dirResp *DirResponse, filePath string, basePath string, maxRetries int) UploadResult {
	var lastErr error
	for attempt := 0; attempt < maxRetries; attempt++ {
		result := uploadFile(config, dirResp, filePath, basePath)
		if result.Success {
			return result
		}
		lastErr = result.Error
		if attempt < maxRetries-1 {
			// Wait before retry with exponential backoff
			waitTime := (attempt + 1) * 100
			<-time.After(time.Duration(waitTime) * time.Millisecond)
		}
	}
	return UploadResult{
		Path:    filePath,
		Success: false,
		Error:   fmt.Errorf("failed after %d attempts: %w", maxRetries, lastErr),
	}
}

func uploadFile(config Config, dirResp *DirResponse, filePath string, basePath string) UploadResult {
	// Determine the relative path for upload
	relPath := getRelativePath(filePath, basePath)

	// Escape each path component separately to preserve slashes
	parts := strings.Split(relPath, string(filepath.Separator))
	escapedParts := make([]string, len(parts))
	for i, part := range parts {
		escapedParts[i] = url.PathEscape(part)
	}
	uploadPath := strings.Join(escapedParts, "/")

	uploadURL := fmt.Sprintf("%s%s", dirResp.DirectoryURL, uploadPath)

	// Open file
	// #nosec G304,G703 -- filePath is user-provided file path, this is a CLI tool designed to upload user files
	file, err := os.Open(filePath)
	if err != nil {
		return UploadResult{Path: filePath, Success: false, Error: err}
	}
	defer func() { _ = file.Close() }()

	// Get file info for content length
	fileInfo, err := file.Stat()
	if err != nil {
		return UploadResult{Path: filePath, Success: false, Error: err}
	}

	// Create PUT request with file body
	req, err := http.NewRequest("PUT", uploadURL, file)
	if err != nil {
		return UploadResult{Path: filePath, Success: false, Error: err}
	}

	req.ContentLength = fileInfo.Size()
	req.Header.Set("X-Upload-Token", dirResp.UploadToken)

	// Send request
	client := newHTTPClient(config)
	// #nosec G704 -- uploadURL is constructed from user-configurable host, this is intentional for a CLI tool
	resp, err := client.Do(req)
	if err != nil {
		return UploadResult{Path: filePath, Success: false, Error: err}
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(resp.Body)
		return UploadResult{
			Path:    filePath,
			Success: false,
			Error:   fmt.Errorf("upload failed with status %d: %s", resp.StatusCode, string(respBody)),
		}
	}

	// Get the actual URL from response
	respBody, _ := io.ReadAll(resp.Body)
	fileURL := strings.TrimSpace(string(respBody))

	return UploadResult{
		Path:    filePath,
		URL:     fileURL,
		Success: true,
	}
}

func getRelativePath(filePath string, basePath string) string {
	// Make both paths absolute
	absPath, err := filepath.Abs(filePath)
	if err != nil {
		return filepath.Base(filePath)
	}

	absBase, err := filepath.Abs(basePath)
	if err != nil {
		return filepath.Base(filePath)
	}

	// Try to make relative to basePath
	relPath, err := filepath.Rel(absBase, absPath)
	if err != nil {
		return filepath.Base(filePath)
	}

	return relPath
}

func printProgress(completed, total int64, result UploadResult) {
	percent := float64(completed) / float64(total) * 100
	status := color.GreenString("✓")
	if !result.Success {
		status = color.RedString("✗")
	}

	fmt.Printf("%s [%3.0f%%] %s", status, percent, result.Path)
	if result.Success {
		fmt.Printf(" → %s\n", color.CyanString(result.URL))
	} else {
		fmt.Printf(" → %s\n", color.RedString(result.Error.Error()))
	}
}

func printResults(results []UploadResult) {
	var success, failed int
	for _, r := range results {
		if r.Success {
			success++
		} else {
			failed++
		}
	}

	fmt.Printf("\n%s\n", strings.Repeat("─", 60))
	fmt.Printf("Upload complete: %s, %s\n",
		color.GreenString("%d successful", success),
		color.RedString("%d failed", failed))
}

func printUsage() {
	fmt.Println("transfer - Fast file sharing from the command line")
	fmt.Println()
	fmt.Println("Usage:")
	fmt.Println("  transfer [options] <file|directory> [file2 ...]")
	fmt.Println()
	fmt.Println("Options:")
	fmt.Println("  --host=URL        Server URL (default: https://transfer.morawski.my)")
	fmt.Println("  --workers=N       Number of parallel upload workers (default: 8)")
	fmt.Println("  --insecure        Disable TLS verification")
	fmt.Println()
	fmt.Println("Environment variables:")
	fmt.Println("  TRANSFER_HOST          Server URL")
	fmt.Println("  TRANSFER_WORKERS       Number of parallel workers")
	fmt.Println("  TRANSFER_MAX_RETRIES   Maximum retry attempts (default: 3)")
	fmt.Println()
	fmt.Println("Examples:")
	fmt.Println("  transfer file.txt")
	fmt.Println("  transfer file1.txt file2.txt file3.txt")
	fmt.Println("  transfer myfolder/")
	fmt.Println("  transfer --workers=16 largefolder/")
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
