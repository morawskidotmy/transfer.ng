package server

import (
	"context"
	"crypto/tls"

	// embed is used to embed web assets into the binary at compile time.
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	htmlTemplate "html/template"
	"log"
	"mime"
	"net"
	"net/http"

	// net/http/pprof registers profiling handlers on the default ServeMux.
	// #nosec G108 -- pprof is only exposed when EnableProfiler() is explicitly configured
	_ "net/http/pprof"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	textTemplate "text/template"
	"time"

	"github.com/PuerkitoBio/ghost/handlers"
	"github.com/VojtechVitek/ratelimit"
	"github.com/VojtechVitek/ratelimit/memory"
	gorillaHandlers "github.com/gorilla/handlers"
	"github.com/gorilla/mux"
	"github.com/tg123/go-htpasswd"
	"golang.org/x/crypto/acme/autocert"

	"io/fs"

	"github.com/morawskidotmy/transfer.ng/server/storage"
	web "github.com/morawskidotmy/transfer.ng/web"
)

// parse request with maximum memory of 192 bytes before spilling to disk
const multipartMemLimit = 192

// parse request with maximum memory of _5Megabytes
const _5M = (1 << 20) * 5

// OptionFn is the option function type
type OptionFn func(*Server)

// ClamavHost sets clamav host
func ClamavHost(s string) OptionFn {
	return func(srvr *Server) {
		srvr.ClamAVDaemonHost = s
	}
}

// ClamavTimeout sets the timeout for ClamAV scans (default 60s).
func ClamavTimeout(d time.Duration) OptionFn {
	return func(srvr *Server) {
		srvr.clamavTimeout = d
	}
}

// PerformClamavPrescan enables clamav prescan on upload
func PerformClamavPrescan(b bool) OptionFn {
	return func(srvr *Server) {
		srvr.performClamavPrescan = b
	}
}

// VirustotalKey sets virus total key
func VirustotalKey(s string) OptionFn {
	return func(srvr *Server) {
		srvr.VirusTotalKey = s
	}
}

// Listener set listener
func Listener(s string) OptionFn {
	return func(srvr *Server) {
		srvr.ListenerString = s
	}

}

// CORSDomains sets allowed CORS origins.
func CORSDomains(s string) OptionFn {
	return func(srvr *Server) {
		srvr.CORSDomains = s
	}
}

// EmailContact sets email contact
func EmailContact(emailContact string) OptionFn {
	return func(srvr *Server) {
		srvr.emailContact = emailContact
	}
}

// GoogleAnalytics sets GA key
func GoogleAnalytics(gaKey string) OptionFn {
	return func(srvr *Server) {
		srvr.gaKey = gaKey
	}
}

// UserVoice sets UV key
func UserVoice(userVoiceKey string) OptionFn {
	return func(srvr *Server) {
		srvr.userVoiceKey = userVoiceKey
	}
}

// TLSListener sets TLS listener and option
func TLSListener(s string, t bool) OptionFn {
	return func(srvr *Server) {
		srvr.TLSListenerString = s
		srvr.TLSListenerOnly = t
	}

}

// ProfileListener sets profile listener
func ProfileListener(s string) OptionFn {
	return func(srvr *Server) {
		srvr.ProfileListenerString = s
	}
}

// WebPath sets web path
func WebPath(s string) OptionFn {
	return func(srvr *Server) {
		if len(s) > 0 && s[len(s)-1:] != "/" {
			s += "/"
		}

		srvr.webPath = s
	}
}

// ProxyPath sets proxy path
func ProxyPath(s string) OptionFn {
	return func(srvr *Server) {
		if len(s) > 0 && s[len(s)-1:] != "/" {
			s += "/"
		}

		srvr.proxyPath = s
	}
}

// ProxyPort sets proxy port
func ProxyPort(s string) OptionFn {
	return func(srvr *Server) {
		srvr.proxyPort = s
	}
}

// TempPath sets temp path
func TempPath(s string) OptionFn {
	return func(srvr *Server) {
		if len(s) > 0 && s[len(s)-1:] != "/" {
			s += "/"
		}

		srvr.tempPath = s
	}
}

// LogFile sets log file
func LogFile(logger *log.Logger, s string) OptionFn {
	return func(srvr *Server) {
		// #nosec G304 -- log file path is admin-supplied configuration
		f, err := os.OpenFile(s, os.O_RDWR|os.O_CREATE|os.O_APPEND, 0600)
		if err != nil {
			logger.Fatalf("error opening file: %v", err)
		}

		logger.SetOutput(f)
		srvr.logger = logger
		srvr.logFile = f
	}
}

// Logger sets logger
func Logger(logger *log.Logger) OptionFn {
	return func(srvr *Server) {
		srvr.logger = logger
	}
}

// MaxUploadSize sets max upload size
func MaxUploadSize(kbytes int64) OptionFn {
	return func(srvr *Server) {
		srvr.maxUploadSize = kbytes * 1024
	}

}

// RateLimit set rate limit
func RateLimit(requests int) OptionFn {
	return func(srvr *Server) {
		srvr.rateLimitRequests = requests
	}
}

// RateLimitUploads sets the rate limit for upload endpoints (PUT/POST).
func RateLimitUploads(requests int) OptionFn {
	return func(srvr *Server) {
		srvr.rateLimitUploads = requests
	}
}

// RandomTokenLength sets random token length
func RandomTokenLength(length int) OptionFn {
	return func(srvr *Server) {
		srvr.randomTokenLength = length
	}
}

// CompressionThreshold sets the minimum file size (bytes) above which uploads are zstd-compressed.
func CompressionThreshold(bytes int64) OptionFn {
	return func(srvr *Server) {
		srvr.compressionThreshold = bytes
	}
}

// MaxArchiveFiles sets the maximum number of files allowed in a single archive download.
func MaxArchiveFiles(count int) OptionFn {
	return func(srvr *Server) {
		srvr.maxArchiveFiles = count
	}
}

// MaxArchiveSize sets the maximum total size (bytes) allowed for an archive download.
func MaxArchiveSize(size int64) OptionFn {
	return func(srvr *Server) {
		srvr.maxArchiveSize = size
		srvr.maxArchiveSizeSet = true
	}
}

// RateLimitArchives sets the rate limit for archive downloads.
func RateLimitArchives(requests int) OptionFn {
	return func(srvr *Server) {
		srvr.rateLimitArchives = requests
	}
}

// MaxDirSize sets the maximum total size (bytes) allowed for a single directory.
func MaxDirSize(size int64) OptionFn {
	return func(srvr *Server) {
		srvr.maxDirSize = size
	}
}

// MaxDirFiles sets the maximum number of files allowed in a single directory.
func MaxDirFiles(count int) OptionFn {
	return func(srvr *Server) {
		srvr.maxDirFiles = count
	}
}

// Timeouts sets the HTTP server read, write, idle, and read-header timeouts.
func Timeouts(readHeader, read, write, idle time.Duration) OptionFn {
	return func(srvr *Server) {
		srvr.readHeaderTimeout = readHeader
		srvr.readTimeout = read
		srvr.writeTimeout = write
		srvr.idleTimeout = idle
	}
}

// Purge sets the age (days) and interval (hours) for automatic file expiration and cleanup.
func Purge(days, interval int) OptionFn {
	return func(srvr *Server) {
		srvr.purgeDays = time.Duration(days) * time.Hour * 24
		srvr.purgeInterval = time.Duration(interval) * time.Hour
	}
}

// ForceHTTPS sets forcing https
func ForceHTTPS() OptionFn {
	return func(srvr *Server) {
		srvr.forceHTTPS = true
	}
}

// EnableProfiler sets enable profiler
func EnableProfiler() OptionFn {
	return func(srvr *Server) {
		srvr.profilerEnabled = true
	}
}

// UseStorage set storage to use
func UseStorage(s storage.Storage) OptionFn {
	return func(srvr *Server) {
		srvr.storage = s
	}
}

// UseLetsEncrypt set letsencrypt usage
func UseLetsEncrypt(hosts []string) OptionFn {
	return func(srvr *Server) {
		cacheDir := srvr.LetsEncryptCache
		if cacheDir == "" {
			cacheDir = "./cache/"
		}

		m := autocert.Manager{
			Prompt: autocert.AcceptTOS,
			Cache:  autocert.DirCache(cacheDir),
			HostPolicy: func(_ context.Context, host string) error {
				found := false

				for _, h := range hosts {
					found = found || strings.HasSuffix(host, h)
				}

				if !found {
					return errors.New("acme/autocert: host not configured")
				}

				return nil
			},
		}

		srvr.tlsConfig = m.TLSConfig()
		srvr.tlsConfig.GetCertificate = m.GetCertificate
	}
}

// TLSConfig sets TLS config
func TLSConfig(cert, pk string) OptionFn {
	certificate, err := tls.LoadX509KeyPair(cert, pk)
	return func(srvr *Server) {
		srvr.tlsConfig = &tls.Config{
			GetCertificate: func(clientHello *tls.ClientHelloInfo) (*tls.Certificate, error) {
				return &certificate, err
			},
		}
	}
}

// HTTPAuthCredentials sets basic http auth credentials
func HTTPAuthCredentials(user string, pass string) OptionFn {
	return func(srvr *Server) {
		srvr.authUser = user
		srvr.authPass = pass
	}
}

// HTTPAuthHtpasswd sets basic http auth htpasswd file
func HTTPAuthHtpasswd(htpasswdPath string) OptionFn {
	return func(srvr *Server) {
		srvr.authHtpasswd = htpasswdPath
	}
}

// HTTPAUTHFilterOptions sets basic http auth ips whitelist
func HTTPAUTHFilterOptions(options IPFilterOptions) OptionFn {
	for i, allowedIP := range options.AllowedIPs {
		options.AllowedIPs[i] = strings.TrimSpace(allowedIP)
	}

	return func(srvr *Server) {
		srvr.authIPFilterOptions = &options
	}
}

// FilterOptions sets ip filtering
func FilterOptions(options IPFilterOptions) OptionFn {
	for i, allowedIP := range options.AllowedIPs {
		options.AllowedIPs[i] = strings.TrimSpace(allowedIP)
	}

	for i, blockedIP := range options.BlockedIPs {
		options.BlockedIPs[i] = strings.TrimSpace(blockedIP)
	}

	return func(srvr *Server) {
		srvr.ipFilterOptions = &options
	}
}

// TrustedProxies sets the CIDRs of reverse proxies whose forwarded headers
// (X-Forwarded-For, X-Real-IP, X-Forwarded-Proto) should be trusted.
// When empty, proxy headers are ignored and RemoteAddr is used directly.
func TrustedProxies(cidrs string) OptionFn {
	var nets []*net.IPNet
	for _, raw := range strings.Split(cidrs, ",") {
		raw = strings.TrimSpace(raw)
		if raw == "" {
			continue
		}
		if !strings.Contains(raw, "/") {
			if strings.Contains(raw, ":") {
				raw += "/128"
			} else {
				raw += "/32"
			}
		}
		if _, ipNet, err := net.ParseCIDR(raw); err == nil {
			nets = append(nets, ipNet)
		}
	}
	return func(srvr *Server) {
		srvr.trustedProxies = nets
	}
}

// AllowedHosts sets the list of allowed Host header values.
// When empty, all Host values are accepted.
func AllowedHosts(hosts string) OptionFn {
	var hostList []string
	for _, raw := range strings.Split(hosts, ",") {
		raw = strings.TrimSpace(raw)
		if raw != "" {
			hostList = append(hostList, raw)
		}
	}
	return func(srvr *Server) {
		srvr.allowedHosts = hostList
	}
}

// Server is the main application
type Server struct {
	authUser            string
	authPass            string
	authHtpasswd        string
	authIPFilterOptions *IPFilterOptions

	htpasswdFile  *htpasswd.File
	authIPFilter  *ipFilter
	authInitMutex sync.Mutex

	logger  *log.Logger
	logFile *os.File

	tlsConfig *tls.Config

	profilerEnabled bool

	locks sync.Map

	maxUploadSize     int64
	rateLimitRequests int
	rateLimitUploads  int

	purgeDays     time.Duration
	purgeInterval time.Duration
	purgeCtx      context.Context
	purgeCancel   context.CancelFunc

	storage storage.Storage

	forceHTTPS bool

	randomTokenLength int

	ipFilterOptions *IPFilterOptions

	trustedProxies []*net.IPNet

	allowedHosts []string

	VirusTotalKey        string
	ClamAVDaemonHost     string
	clamavTimeout        time.Duration
	performClamavPrescan bool

	tempPath string

	webPath      string
	proxyPath    string
	proxyPort    string
	emailContact string
	gaKey        string
	userVoiceKey string

	TLSListenerOnly bool

	CORSDomains           string
	ListenerString        string
	TLSListenerString     string
	ProfileListenerString string

	Certificate string

	LetsEncryptCache string

	sampleTokenA string
	sampleTokenB string

	htmlTemplates      *htmlTemplate.Template
	htmlTemplatesMutex sync.RWMutex
	textTemplates      *textTemplate.Template
	textTemplatesMutex sync.RWMutex

	compressionThreshold int64
	maxArchiveFiles      int
	maxArchiveSize       int64 // Maximum total size of files in an archive (0 = unlimited)
	maxArchiveSizeSet    bool  // Whether maxArchiveSize was explicitly configured
	maxDirSize           int64 // Maximum total size of files in a directory (0 = unlimited)
	maxDirFiles          int   // Maximum number of files in a directory (0 = unlimited)

	rateLimitArchives int // Rate limit for archive downloads (requests per minute)

	readHeaderTimeout time.Duration
	readTimeout       time.Duration
	writeTimeout      time.Duration
	idleTimeout       time.Duration
}

// New is the factory fot Server
func New(options ...OptionFn) (*Server, error) {
	s := &Server{
		locks: sync.Map{},
	}

	for _, optionFn := range options {
		optionFn(s)
	}

	if !s.maxArchiveSizeSet {
		s.maxArchiveSize = s.maxUploadSize
	}

	tokenA, err := token(s.randomTokenLength)
	if err != nil {
		return nil, fmt.Errorf("failed to generate sample token: %w", err)
	}
	tokenB, err := token(s.randomTokenLength)
	if err != nil {
		return nil, fmt.Errorf("failed to generate sample token: %w", err)
	}
	s.sampleTokenA = tokenA
	s.sampleTokenB = tokenB

	return s, nil
}

// isFromTrustedProxy reports whether r.RemoteAddr belongs to a configured
// trusted proxy CIDR. When no trusted proxies are configured, it returns false.
func (s *Server) isFromTrustedProxy(r *http.Request) bool {
	if len(s.trustedProxies) == 0 {
		return false
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return false
	}
	for _, n := range s.trustedProxies {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

// remoteIP returns the real client IP. When trusted proxies are configured and
// the request comes from one, it reads X-Forwarded-For / X-Real-IP. Otherwise
// it falls back to RemoteAddr.
func (s *Server) remoteIP(r *http.Request) string {
	if s.isFromTrustedProxy(r) {
		if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
			if ip := s.clientIPFromXFF(xff); ip != "" {
				return ip
			}
		}
		if xri := r.Header.Get("X-Real-IP"); xri != "" {
			if ip := net.ParseIP(strings.TrimSpace(xri)); ip != nil {
				return ip.String()
			}
		}
	}
	return ipAddrFromRemoteAddr(r.RemoteAddr)
}

// clientIPFromXFF extracts the client IP from an X-Forwarded-For header by
// walking right-to-left and returning the first IP that is not a trusted proxy.
// This prevents spoofing when a client prepends fake IPs to the header.
func (s *Server) clientIPFromXFF(xff string) string {
	parts := strings.Split(xff, ",")
	for i := len(parts) - 1; i >= 0; i-- {
		ipStr := strings.TrimSpace(parts[i])
		ip := net.ParseIP(ipStr)
		if ip == nil {
			continue
		}
		if !s.isTrustedIP(ip) {
			return ip.String()
		}
	}
	if len(parts) > 0 {
		ipStr := strings.TrimSpace(parts[0])
		if ip := net.ParseIP(ipStr); ip != nil {
			return ip.String()
		}
	}
	return ""
}

// isTrustedIP reports whether ip is within any of the configured trusted proxy CIDRs.
func (s *Server) isTrustedIP(ip net.IP) bool {
	for _, n := range s.trustedProxies {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

// trustForwardedHeaders reports whether X-Forwarded-Proto and similar headers
// should be honored for this request.
func (s *Server) trustForwardedHeaders(r *http.Request) bool {
	return s.isFromTrustedProxy(r)
}

// validateHost checks if the Host header is in the allowed list.
// Returns the host if valid, or empty string if not allowed.
// When allowedHosts is empty, all hosts are accepted.
func (s *Server) validateHost(r *http.Request) string {
	if len(s.allowedHosts) == 0 {
		return r.Host
	}
	host, _, err := net.SplitHostPort(r.Host)
	if err != nil {
		host = r.Host
	}
	for _, allowed := range s.allowedHosts {
		if host == allowed || r.Host == allowed {
			return r.Host
		}
	}
	return ""
}

//go:embed mime_types.json
var mimeTypesJSON []byte

func registerMimeTypes() {
	var mimeTypes map[string]string
	if err := json.Unmarshal(mimeTypesJSON, &mimeTypes); err != nil {
		panic("failed to parse mime_types.json: " + err.Error())
	}
	for ext, typ := range mimeTypes {
		_ = mime.AddExtensionType(ext, typ)
	}
}

func (s *Server) startProfiler() bool {
	if !s.profilerEnabled {
		return false
	}
	profileAddr := s.ProfileListenerString
	if profileAddr == "" {
		profileAddr = "127.0.0.1:6060"
	}
	go func() {
		s.logger.Println("Profiler listening at:", profileAddr)
		// #nosec G114 -- profiler is for debugging only, not production use
		_ = http.ListenAndServe(profileAddr, nil)
	}()
	return true
}

func (s *Server) createCORSHandler() func(http.Handler) http.Handler {
	if len(s.CORSDomains) > 0 {
		return gorillaHandlers.CORS(
			gorillaHandlers.AllowedHeaders([]string{
				"Content-Type",
				"Content-Length",
				"Accept",
				"Authorization",
				"X-Requested-With",
				"X-Deletion-Token",
				"X-Upload-Token",
				"X-Encrypt-Password",
				"X-Decrypt-Password",
				"Max-Downloads",
				"Max-Days",
				"Range",
			}),
			gorillaHandlers.AllowedOrigins(strings.Split(s.CORSDomains, ",")),
			gorillaHandlers.AllowedMethods([]string{"GET", "HEAD", "POST", "PUT", "DELETE", "OPTIONS"}),
		)
	}
	return func(h http.Handler) http.Handler {
		return h
	}
}

func (s *Server) createHTTPServer(addr string, h http.Handler) *http.Server {
	readHeaderTimeout := s.readHeaderTimeout
	if readHeaderTimeout == 0 {
		readHeaderTimeout = 10 * time.Second
	}
	readTimeout := s.readTimeout
	if readTimeout == 0 {
		readTimeout = 5 * time.Minute
	}
	writeTimeout := s.writeTimeout
	if writeTimeout == 0 {
		writeTimeout = 10 * time.Minute
	}
	idleTimeout := s.idleTimeout
	if idleTimeout == 0 {
		idleTimeout = 2 * time.Minute
	}
	return &http.Server{
		Addr:              addr,
		Handler:           h,
		ReadHeaderTimeout: readHeaderTimeout,
		ReadTimeout:       readTimeout,
		WriteTimeout:      writeTimeout,
		IdleTimeout:       idleTimeout,
	}
}

func (s *Server) startHTTPServer(h http.Handler) *http.Server {
	if s.TLSListenerOnly {
		return nil
	}
	s.logger.Printf("starting to listen on: %v\n", s.ListenerString)
	httpSrv := s.createHTTPServer(s.ListenerString, h)
	go func() {
		if err := httpSrv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			s.logger.Fatal(err)
		}
	}()
	return httpSrv
}

func (s *Server) startTLSServer(h http.Handler) *http.Server {
	if s.TLSListenerString == "" {
		return nil
	}
	s.logger.Printf("starting to listen for TLS on: %v\n", s.TLSListenerString)
	tlsSrv := s.createHTTPServer(s.TLSListenerString, h)
	tlsSrv.TLSConfig = s.tlsConfig
	go func() {
		if err := tlsSrv.ListenAndServeTLS("", ""); err != nil && !errors.Is(err, http.ErrServerClosed) {
			s.logger.Fatal(err)
		}
	}()
	return tlsSrv
}

func (s *Server) shutdownServers(servers []*http.Server) {
	s.logger.Print("Shutting down...")
	s.purgeCancel()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	for _, srv := range servers {
		if err := srv.Shutdown(ctx); err != nil {
			s.logger.Printf("server shutdown error: %v", err)
		}
	}

	if s.logFile != nil {
		_ = s.logFile.Close()
	}
	s.logger.Print("Server stopped.")
}

// Run starts the HTTP server(s) and blocks until a shutdown signal is received.
func (s *Server) Run() {
	listening := s.startProfiler()
	var servers []*http.Server

	r := mux.NewRouter()
	s.htmlTemplates = initHTMLTemplates()
	s.textTemplates = initTextTemplates()

	var fs http.FileSystem
	if s.webPath != "" {
		s.logger.Println("Using static file path: ", s.webPath)
		fs = http.Dir(s.webPath)
		s.loadTemplatesFromPath()
	} else {
		fs = s.createAssetFS()
		s.loadTemplatesFromAssets()
	}

	staticHandler := http.FileServer(fs)
	s.setupRoutes(r, staticHandler)
	registerMimeTypes()

	s.logger.Printf("Transfer.sh server started.\nusing temp folder: %s\nusing storage provider: %s", s.tempPath, s.storage.Type())

	cors := s.createCORSHandler()
	h := securityHeadersHandler(
		s.allowedHostsHandler(
			handlers.PanicHandler(
				ipFilterHandler(
					handlers.LogHandler(
						LoveHandler(
							s.RedirectHandler(cors(r))),
						handlers.NewLogOptions(s.logger.Printf, "_default_"),
					),
					s.ipFilterOptions,
					s.remoteIP,
				),
				nil,
			),
		),
	)

	if httpSrv := s.startHTTPServer(h); httpSrv != nil {
		listening = true
		servers = append(servers, httpSrv)
	}

	if tlsSrv := s.startTLSServer(h); tlsSrv != nil {
		listening = true
		servers = append(servers, tlsSrv)
	}

	s.logger.Print("---------------------------")

	s.purgeCtx, s.purgeCancel = context.WithCancel(context.Background())
	if s.purgeDays > 0 {
		go s.purgeHandler()
	}

	term := make(chan os.Signal, 1)
	signal.Notify(term, os.Interrupt)
	signal.Notify(term, syscall.SIGTERM)

	if listening {
		<-term
	} else {
		s.logger.Print("No listener active.")
	}

	s.shutdownServers(servers)
}

func (s *Server) loadTemplatesFromPath() {
	s.htmlTemplatesMutex.Lock()
	if t, err := s.htmlTemplates.ParseGlob(filepath.Join(s.webPath, "*.html")); err != nil {
		s.logger.Fatalf("failed to parse html templates: %v", err)
	} else {
		s.htmlTemplates = t
	}
	s.htmlTemplatesMutex.Unlock()
	s.textTemplatesMutex.Lock()
	if t, err := s.textTemplates.ParseGlob(filepath.Join(s.webPath, "*.txt")); err != nil {
		s.logger.Fatalf("failed to parse text templates: %v", err)
	} else {
		s.textTemplates = t
	}
	s.textTemplatesMutex.Unlock()
}

func (s *Server) createAssetFS() http.FileSystem {
	sub, err := fs.Sub(web.FS, ".")
	if err != nil {
		s.logger.Fatalf("Unable to create sub filesystem: %v", err)
	}
	return http.FS(sub)
}

func (s *Server) loadTemplatesFromAssets() {
	for _, path := range web.AssetNames() {
		bytes, err := web.Asset(path)
		if err != nil {
			s.logger.Fatalf("Unable to parse: path=%s, err=%s", path, err)
		}

		if strings.HasSuffix(path, ".html") {
			s.htmlTemplatesMutex.Lock()
			_, err = s.htmlTemplates.New(stripPrefix(path)).Parse(string(bytes))
			s.htmlTemplatesMutex.Unlock()
			if err != nil {
				s.logger.Println("Unable to parse html template", err)
			}
		}
		if strings.HasSuffix(path, ".txt") {
			s.textTemplatesMutex.Lock()
			_, err = s.textTemplates.New(stripPrefix(path)).Parse(string(bytes))
			s.textTemplatesMutex.Unlock()
			if err != nil {
				s.logger.Println("Unable to parse text template", err)
			}
		}
	}
}

func (s *Server) setupRoutes(r *mux.Router, staticHandler http.Handler) {
	r.PathPrefix("/images/").Handler(staticHandler).Methods("GET")
	r.PathPrefix("/styles/").Handler(staticHandler).Methods("GET")
	r.PathPrefix("/scripts/").Handler(staticHandler).Methods("GET")
	r.PathPrefix("/fonts/").Handler(staticHandler).Methods("GET")
	r.PathPrefix("/ico/").Handler(staticHandler).Methods("GET")
	r.HandleFunc("/favicon.ico", staticHandler.ServeHTTP).Methods("GET")
	r.HandleFunc("/robots.txt", staticHandler.ServeHTTP).Methods("GET")
	r.HandleFunc("/{filename:(?:favicon\\.ico|robots\\.txt|health\\.html)}", s.basicAuthHandler(http.HandlerFunc(s.putHandler))).Methods("PUT")
	r.HandleFunc("/health.html", healthHandler).Methods("GET")
	r.HandleFunc("/", s.viewHandler).Methods("GET")

	// Directory-level GET routes must come before catch-all file routes
	// Archive routes with optional subpath for scoped downloads
	// Shared rate limiter for all archive endpoints
	var archiveLimiter func(http.Handler) http.Handler
	if s.rateLimitArchives > 0 {
		archiveLimiter = func(h http.Handler) http.Handler {
			return ratelimit.Request(s.remoteIP).Rate(s.rateLimitArchives, 60*time.Second).LimitBy(memory.New())(h)
		}
	}

	wrapArchive := func(h http.Handler) http.Handler {
		if archiveLimiter != nil {
			return archiveLimiter(h)
		}
		return h
	}

	dirZipHandlerFn := wrapArchive(http.HandlerFunc(s.dirZipHandler))
	dirTarGzHandlerFn := wrapArchive(http.HandlerFunc(s.dirTarGzHandler))
	dirZipHeadHandlerFn := wrapArchive(http.HandlerFunc(s.dirZipHeadHandler))
	dirTarGzHeadHandlerFn := wrapArchive(http.HandlerFunc(s.dirTarGzHeadHandler))

	r.Handle("/zip/{token}/{subpath:.*}", dirZipHandlerFn).Methods("GET")
	r.Handle("/zip/{token}/", dirZipHandlerFn).Methods("GET")
	r.Handle("/zip/{token}", dirZipHandlerFn).Methods("GET")
	r.Handle("/tar.gz/{token}/{subpath:.*}", dirTarGzHandlerFn).Methods("GET")
	r.Handle("/tar.gz/{token}/", dirTarGzHandlerFn).Methods("GET")
	r.Handle("/tar.gz/{token}", dirTarGzHandlerFn).Methods("GET")
	r.Handle("/zip/{token}/{subpath:.*}", dirZipHeadHandlerFn).Methods("HEAD")
	r.Handle("/zip/{token}/", dirZipHeadHandlerFn).Methods("HEAD")
	r.Handle("/zip/{token}", dirZipHeadHandlerFn).Methods("HEAD")
	r.Handle("/tar.gz/{token}/{subpath:.*}", dirTarGzHeadHandlerFn).Methods("HEAD")
	r.Handle("/tar.gz/{token}/", dirTarGzHeadHandlerFn).Methods("HEAD")
	r.Handle("/tar.gz/{token}", dirTarGzHeadHandlerFn).Methods("HEAD")
	r.HandleFunc("/{token}/", s.listDirectoryHandler).Methods("GET")
	r.HandleFunc("/{token}", s.listDirectoryHandler).Methods("GET")
	r.HandleFunc("/{token}/{subpath:.+}/", s.listDirectoryHandler).Methods("GET")

	// Multi-file archive routes
	zipHandlerFn := wrapArchive(http.HandlerFunc(s.zipHandler))
	tarHandlerFn := wrapArchive(http.HandlerFunc(s.tarHandler))
	tarGzHandlerFn := wrapArchive(http.HandlerFunc(s.tarGzHandler))
	r.Handle("/archive/zip/{files:.*}", zipHandlerFn).Methods("GET")
	r.Handle("/archive/tar/{files:.*}", tarHandlerFn).Methods("GET")
	r.Handle("/archive/tar.gz/{files:.*}", tarGzHandlerFn).Methods("GET")

	// File routes with nested path support
	r.HandleFunc("/{token}/{filename:.+}", s.headHandler).Methods("HEAD")
	r.HandleFunc("/{action:(?:download|get|inline)}/{token}/{filename:.+}", s.headHandler).Methods("HEAD")

	getHandlerFn := s.getHandler
	if s.rateLimitRequests > 0 {
		getHandlerFn = ratelimit.Request(s.remoteIP).Rate(s.rateLimitRequests, 60*time.Second).LimitBy(memory.New())(http.HandlerFunc(getHandlerFn)).ServeHTTP
	}

	// Action routes (/get/, /download/, /inline/) must come before the preview
	// route, otherwise /{token}/{filename:.+} matches them with token="get".
	r.HandleFunc("/{action:(?:download|get|inline)}/{token}/{filename:.+}", getHandlerFn).Methods("GET")
	r.HandleFunc("/{token}/{filename:.+}", s.previewHandler).MatcherFunc(s.previewMatcher).Methods("GET")

	var putHandlerFn http.Handler = http.HandlerFunc(s.putHandler)
	var putToDirHandlerFn http.Handler = http.HandlerFunc(s.putToDirHandler)
	var postHandlerFn http.Handler = http.HandlerFunc(s.postHandler)
	if s.rateLimitUploads > 0 {
		putHandlerFn = ratelimit.Request(s.remoteIP).Rate(s.rateLimitUploads, 60*time.Second).LimitBy(memory.New())(http.HandlerFunc(s.putHandler))
		putToDirHandlerFn = ratelimit.Request(s.remoteIP).Rate(s.rateLimitUploads, 60*time.Second).LimitBy(memory.New())(http.HandlerFunc(s.putToDirHandler))
		postHandlerFn = ratelimit.Request(s.remoteIP).Rate(s.rateLimitUploads, 60*time.Second).LimitBy(memory.New())(http.HandlerFunc(s.postHandler))
	}

	r.HandleFunc("/{token}/{filename:.+}", getHandlerFn).Methods("GET")

	var scanHandlerFn http.Handler = http.HandlerFunc(s.scanHandler)
	var virusTotalHandlerFn http.Handler = http.HandlerFunc(s.virusTotalHandler)
	if s.rateLimitUploads > 0 {
		scanHandlerFn = ratelimit.Request(s.remoteIP).Rate(s.rateLimitUploads, 60*time.Second).LimitBy(memory.New())(http.HandlerFunc(s.scanHandler))
		virusTotalHandlerFn = ratelimit.Request(s.remoteIP).Rate(s.rateLimitUploads, 60*time.Second).LimitBy(memory.New())(http.HandlerFunc(s.virusTotalHandler))
	}
	r.HandleFunc("/{filename}/virustotal", s.requireAuthHandler(virusTotalHandlerFn)).Methods("PUT")
	r.HandleFunc("/{filename}/scan", s.requireAuthHandler(scanHandlerFn)).Methods("PUT")

	r.HandleFunc("/put/{filename:.+}", s.basicAuthHandler(putHandlerFn)).Methods("PUT")
	r.HandleFunc("/upload/{filename:.+}", s.basicAuthHandler(putHandlerFn)).Methods("PUT")
	// putToDirHandler must be registered before the catch-all putHandler. It only
	// matches when the caller provides an X-Upload-Token header; without that
	// header the request falls through to putHandler so that uploads to
	// subdirectory paths (e.g. PUT /subdir/file.txt) create a new directory
	// rather than failing with 401 Missing X-Upload-Token.
	hasUploadToken := func(r *http.Request, _ *mux.RouteMatch) bool {
		return r.Header.Get("X-Upload-Token") != ""
	}
	r.HandleFunc("/{token}/{filename:.+}", s.basicAuthHandler(putToDirHandlerFn)).
		Methods("PUT").
		MatcherFunc(hasUploadToken)
	r.HandleFunc("/{filename:.+}", s.basicAuthHandler(putHandlerFn)).Methods("PUT")
	r.HandleFunc("/dir", s.basicAuthHandler(http.HandlerFunc(s.createDirHandler))).Methods("POST")
	r.HandleFunc("/", s.basicAuthHandler(postHandlerFn)).Methods("POST")
	// Deletion token now passed via query param or X-Deletion-Token header
	r.HandleFunc("/{token}/{filename:.+}", s.deleteHandler).Methods("DELETE")
	r.HandleFunc("/{token}/", s.deleteDirHandler).Methods("DELETE")
	r.NotFoundHandler = http.HandlerFunc(s.notFoundHandler)
}

func (s *Server) previewMatcher(r *http.Request, rm *mux.RouteMatch) bool {
	if !acceptsHTML(r.Header) {
		return false
	}
	if r.Referer() == "" {
		return true
	}
	u, err := url.Parse(r.Referer())
	if err != nil {
		s.logger.Printf("invalid referer %q: %v", r.Referer(), err)
		return true
	}
	return u.Path != r.URL.Path
}
