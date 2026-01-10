package server

import (
	"context"
	"crypto/tls"
	"errors"
	htmlTemplate "html/template"
	"log"
	"mime"
	"net/http"
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

// parse request with maximum memory of _24Kilobits
const _24K = (1 << 3) * 24

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

// CorsDomains sets CORS domains
func CorsDomains(s string) OptionFn {
	return func(srvr *Server) {
		srvr.CorsDomains = s
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
			s = filepath.Join(s, "")
		}

		srvr.webPath = s
	}
}

// ProxyPath sets proxy path
func ProxyPath(s string) OptionFn {
	return func(srvr *Server) {
		if len(s) > 0 && s[len(s)-1:] != "/" {
			s = filepath.Join(s, "")
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
			s = filepath.Join(s, "")
		}

		srvr.tempPath = s
	}
}

// LogFile sets log file
func LogFile(logger *log.Logger, s string) OptionFn {
	return func(srvr *Server) {
		f, err := os.OpenFile(s, os.O_RDWR|os.O_CREATE|os.O_APPEND, 0666)
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

// RandomTokenLength sets random token length
func RandomTokenLength(length int) OptionFn {
	return func(srvr *Server) {
		srvr.randomTokenLength = length
	}
}

// CompressionThreshold sets compression threshold
func CompressionThreshold(bytes int64) OptionFn {
	return func(srvr *Server) {
		srvr.compressionThreshold = bytes
	}
}

// Purge sets purge days and option
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
		cacheDir := "./cache/"

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

	purgeDays     time.Duration
	purgeInterval time.Duration
	purgeCtx      context.Context
	purgeCancel   context.CancelFunc

	storage storage.Storage

	forceHTTPS bool

	randomTokenLength int

	ipFilterOptions *IPFilterOptions

	VirusTotalKey        string
	ClamAVDaemonHost     string
	performClamavPrescan bool

	tempPath string

	webPath      string
	proxyPath    string
	proxyPort    string
	emailContact string
	gaKey        string
	userVoiceKey string

	TLSListenerOnly bool

	CorsDomains           string
	ListenerString        string
	TLSListenerString     string
	ProfileListenerString string

	Certificate string

	LetsEncryptCache string

	htmlTemplates      *htmlTemplate.Template
	htmlTemplatesMutex sync.RWMutex
	textTemplates      *textTemplate.Template
	textTemplatesMutex sync.RWMutex

	compressionThreshold int64
}

// New is the factory fot Server
func New(options ...OptionFn) (*Server, error) {
	s := &Server{
		locks: sync.Map{},
	}

	for _, optionFn := range options {
		optionFn(s)
	}

	return s, nil
}

// Run starts Server
func registerMimeTypes() {
	mimeTypes := [][2]string{
		{".md", "text/x-markdown"},
		{".markdown", "text/x-markdown"},
		{".mdown", "text/x-markdown"},
		{".mkdown", "text/x-markdown"},
		{".mkd", "text/x-markdown"},
		{".mdx", "text/x-markdown"},
		{".conf", "text/plain"},
		{".config", "text/plain"},
		{".cfg", "text/plain"},
		{".ini", "text/plain"},
		{".toml", "text/plain"},
		{".properties", "text/plain"},
		{".gradle.properties", "text/plain"},
		{".maven.properties", "text/plain"},
		{".yml", "text/yaml"},
		{".yaml", "text/yaml"},
		{".json", "application/json"},
		{".jsonld", "application/ld+json"},
		{".json5", "application/json"},
		{".geojson", "application/geo+json"},
		{".xml", "application/xml"},
		{".xsl", "application/xml"},
		{".xslt", "application/xml"},
		{".svg", "image/svg+xml"},
		{".plist", "application/x-plist"},
		{".sh", "text/x-shellscript"},
		{".bash", "text/x-shellscript"},
		{".zsh", "text/x-shellscript"},
		{".fish", "text/x-shellscript"},
		{".ksh", "text/x-shellscript"},
		{".csh", "text/x-shellscript"},
		{".tcsh", "text/x-shellscript"},
		{".ash", "text/x-shellscript"},
		{".ps1", "text/x-powershell"},
		{".psd1", "text/x-powershell"},
		{".psm1", "text/x-powershell"},
		{".bat", "text/x-batch"},
		{".cmd", "text/x-batch"},
		{".sql", "text/x-sql"},
		{".sqlite", "text/x-sql"},
		{".plsql", "text/x-sql"},
		{".tsql", "text/x-sql"},
		{".env", "text/plain"},
		{".env.example", "text/plain"},
		{".env.local", "text/plain"},
		{".env.development", "text/plain"},
		{".env.production", "text/plain"},
		{".editorconfig", "text/plain"},
		{".gitconfig", "text/plain"},
		{".gitignore", "text/plain"},
		{".gitattributes", "text/plain"},
		{".dockerignore", "text/plain"},
		{".dockerfile", "text/x-dockerfile"},
		{".Dockerfile", "text/x-dockerfile"},
		{".py", "text/x-python"},
		{".pyw", "text/x-python"},
		{".pyx", "text/x-python"},
		{".pyi", "text/x-python"},
		{".rb", "text/x-ruby"},
		{".rbw", "text/x-ruby"},
		{".rake", "text/x-ruby"},
		{".gemspec", "text/x-ruby"},
		{".go", "text/x-go"},
		{".rs", "text/x-rust"},
		{".java", "text/x-java"},
		{".class", "application/x-java-applet"},
		{".jar", "application/x-java-archive"},
		{".c", "text/x-csrc"},
		{".cc", "text/x-c++src"},
		{".cpp", "text/x-c++src"},
		{".cxx", "text/x-c++src"},
		{".c++", "text/x-c++src"},
		{".h", "text/x-csrc"},
		{".hh", "text/x-c++src"},
		{".hpp", "text/x-c++src"},
		{".hxx", "text/x-c++src"},
		{".h++", "text/x-c++src"},
		{".hpp", "text/x-c++src"},
		{".hxx", "text/x-c++src"},
		{".h++", "text/x-c++src"},
		{".cs", "text/x-csharp"},
		{".csx", "text/x-csharp"},
		{".csproj", "application/xml"},
		{".vb", "text/x-vbnet"},
		{".vbproj", "application/xml"},
		{".fsx", "text/x-fsharp"},
		{".fsi", "text/x-fsharp"},
		{".fsproj", "application/xml"},
		{".swift", "text/x-swift"},
		{".kt", "text/x-kotlin"},
		{".kts", "text/x-kotlin"},
		{".groovy", "text/x-groovy"},
		{".gradle", "text/x-groovy"},
		{".lua", "text/x-lua"},
		{".pl", "text/x-perl"},
		{".pm", "text/x-perl"},
		{".php", "text/x-php"},
		{".phtml", "text/x-php"},
		{".php3", "text/x-php"},
		{".php4", "text/x-php"},
		{".php5", "text/x-php"},
		{".php7", "text/x-php"},
		{".php8", "text/x-php"},
		{".asp", "text/x-asp"},
		{".aspx", "text/x-asp"},
		{".asmx", "text/x-asp"},
		{".ascx", "text/x-asp"},
		{".master", "text/x-asp"},
		{".asax", "text/x-asp"},
		{".asacx", "text/x-asp"},
		{".handlebars", "text/x-handlebars"},
		{".hbs", "text/x-handlebars"},
		{".js", "text/javascript"},
		{".template", "text/plain"},
		{".jinja", "text/x-jinja"},
		{".jinja2", "text/x-jinja"},
		{".j2", "text/x-jinja"},
		{".makefile", "text/x-makefile"},
		{".Makefile", "text/x-makefile"},
		{".cmake", "text/x-cmake"},
		{".CMakeLists.txt", "text/x-cmake"},
		{".gradle", "text/x-gradle"},
		{".maven", "text/x-maven"},
		{".pom", "text/x-maven"},
		{".npm", "text/plain"},
		{".yarn", "text/plain"},
		{".requirements.txt", "text/plain"},
		{".Gemfile", "text/x-ruby"},
		{".Rakefile", "text/x-ruby"},
		{".Procfile", "text/plain"},
		{".lock", "text/plain"},
		{".log", "text/plain"},
		{".txt", "text/plain"},
		{".text", "text/plain"},
		{".csv", "text/csv"},
		{".tsv", "text/tab-separated-values"},
		{".psv", "text/plain"},
		{".md5", "text/plain"},
		{".sha1", "text/plain"},
		{".sha256", "text/plain"},
		{".sha512", "text/plain"},
		{".checksum", "text/plain"},
		{".gpg", "application/pgp-encrypted"},
		{".asc", "application/pgp-signature"},
		{".sig", "application/pgp-signature"},
		{".key", "application/pgp-keys"},
		{".pub", "text/plain"},
		{".pem", "application/x-pem-file"},
		{".crt", "application/x-x509-ca-cert"},
		{".cer", "application/x-x509-ca-cert"},
		{".der", "application/x-x509-ca-cert"},
		{".p7b", "application/x-pkcs7-certificates"},
		{".p12", "application/x-pkcs12"},
		{".pfx", "application/x-pkcs12"},
		{".jks", "application/x-java-keystore"},
		{".keystore", "application/x-java-keystore"},
		{".csr", "application/pkcs10"},
		{".acme", "text/plain"},
		{".htaccess", "text/plain"},
		{".htpasswd", "text/plain"},
		{".htgroups", "text/plain"},
		{".robots.txt", "text/plain"},
		{".sitemap.xml", "application/xml"},
		{".manifest", "text/cache-manifest"},
		{".webmanifest", "application/manifest+json"},
		{".appcache", "text/cache-manifest"},
		{".mo", "application/x-gettext"},
		{".po", "application/x-gettext"},
		{".pot", "application/x-gettext"},
		{".ts", "application/typescript"},
		{".po", "text/x-po"},
		{".pot", "text/x-pot"},
		{".resx", "application/x-resx"},
		{".strings", "text/plain"},
		{".properties", "text/x-properties"},
		{".gradle", "text/x-gradle"},
		{".bazel", "text/plain"},
		{".buck", "text/plain"},
		{".bazelrc", "text/plain"},
		{".clangformat", "text/plain"},
		{".clang-format", "text/plain"},
		{".prettierrc", "application/json"},
		{".prettierignore", "text/plain"},
		{".eslintrc", "application/json"},
		{".eslintignore", "text/plain"},
		{".stylelintrc", "application/json"},
		{".stylelintignore", "text/plain"},
		{".babelrc", "application/json"},
		{".babelrc.js", "text/javascript"},
		{".eslintrc.json", "application/json"},
		{".eslintrc.yml", "text/yaml"},
		{".eslintrc.yaml", "text/yaml"},
		{".eslintrc.js", "text/javascript"},
		{".browserslistrc", "text/plain"},
		{".npmrc", "text/plain"},
		{".yarnrc", "text/plain"},
		{".nvmrc", "text/plain"},
		{".node-version", "text/plain"},
		{".ruby-version", "text/plain"},
		{".go-version", "text/plain"},
		{".python-version", "text/plain"},
		{".php-version", "text/plain"},
		{".terraform", "text/plain"},
		{".tf", "text/plain"},
		{".tfvars", "text/plain"},
		{".hcl", "text/plain"},
		{".ansible", "text/x-yaml"},
		{".yml.j2", "text/x-jinja"},
		{".yaml.j2", "text/x-jinja"},
		{".graphql", "text/graphql"},
		{".gql", "text/graphql"},
		{".proto", "text/x-protobuf"},
		{".thrift", "text/x-thrift"},
		{".idl", "text/x-idl"},
		{".wsdl", "application/xml"},
		{".wadl", "application/xml"},
		{".raml", "application/raml+yaml"},
		{".openapi", "application/yaml"},
		{".swagger", "application/yaml"},
		{".swagger.json", "application/json"},
		{".asyncapi", "application/yaml"},
		{".asyncapi.json", "application/json"},
		{".hh", "text/x-c++src"},
		{".hpp", "text/x-c++src"},
		{".hxx", "text/x-c++src"},
		{".h++", "text/x-c++src"},
		{".csx", "text/x-csharp"},
		{".csproj", "application/xml"},
		{".vbproj", "application/xml"},
		{".fsx", "text/x-fsharp"},
		{".fsproj", "application/xml"},
		{".vb", "text/x-vbnet"},
		{".vbs", "text/x-vbscript"},
		{".mjs", "text/javascript"},
		{".cjs", "text/javascript"},
		{".tsx", "text/typescript"},
		{".jsx", "text/jsx"},
		{".css", "text/css"},
		{".scss", "text/x-scss"},
		{".sass", "text/x-sass"},
		{".less", "text/x-less"},
		{".styl", "text/x-stylus"},
		{".stylus", "text/x-stylus"},
		{".html", "text/html"},
		{".htm", "text/html"},
		{".xhtml", "application/xhtml+xml"},
		{".vue", "text/x-vue"},
		{".svelte", "text/x-svelte"},
		{".astro", "text/x-astro"},
		{".scala", "text/x-scala"},
		{".t", "text/x-perl"},
		{".vim", "text/x-vim"},
		{".el", "text/x-elisp"},
		{".lisp", "text/x-lisp"},
		{".clj", "text/x-clojure"},
		{".cljs", "text/x-clojure"},
		{".edn", "text/x-clojure"},
		{".ex", "text/x-elixir"},
		{".exs", "text/x-elixir"},
		{".erl", "text/x-erlang"},
		{".hrl", "text/x-erlang"},
		{".ml", "text/x-ocaml"},
		{".mli", "text/x-ocaml"},
		{".fs", "text/x-fsharp"},
		{".fsi", "text/x-fsharp"},
		{".hs", "text/x-haskell"},
		{".lhs", "text/x-haskell"},
		{".r", "text/x-r"},
		{".R", "text/x-r"},
		{".jl", "text/x-julia"},
		{".m", "text/x-matlab"},
		{".mm", "text/x-objc++"},
		{".dart", "text/x-dart"},
		{".pas", "text/x-pascal"},
		{".pp", "text/x-pascal"},
		{".d", "text/x-d"},
		{".asm", "text/x-asm"},
		{".s", "text/x-asm"},
	}
	for _, mt := range mimeTypes {
		_ = mime.AddExtensionType(mt[0], mt[1])
	}
}

func (s *Server) Run() {
	listening := false
	var servers []*http.Server

	if s.profilerEnabled {
		listening = true
		go func() {
			s.logger.Println("Profiled listening at: :6060")
			_ = http.ListenAndServe(":6060", nil)
		}()
	}

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

	var cors func(http.Handler) http.Handler
	if len(s.CorsDomains) > 0 {
		cors = gorillaHandlers.CORS(
			gorillaHandlers.AllowedHeaders([]string{"*"}),
			gorillaHandlers.AllowedOrigins(strings.Split(s.CorsDomains, ",")),
			gorillaHandlers.AllowedMethods([]string{"GET", "HEAD", "POST", "PUT", "DELETE", "OPTIONS"}),
		)
	} else {
		cors = func(h http.Handler) http.Handler {
			return h
		}
	}

	h := handlers.PanicHandler(
		ipFilterHandler(
			handlers.LogHandler(
				LoveHandler(
					s.RedirectHandler(cors(r))),
				handlers.NewLogOptions(s.logger.Printf, "_default_"),
			),
			s.ipFilterOptions,
		),
		nil,
	)

	if !s.TLSListenerOnly {
		listening = true
		s.logger.Printf("starting to listen on: %v\n", s.ListenerString)

		httpSrv := &http.Server{
			Addr:    s.ListenerString,
			Handler: h,
		}
		servers = append(servers, httpSrv)

		go func() {
			if err := httpSrv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
				s.logger.Fatal(err)
			}
		}()
	}

	if s.TLSListenerString != "" {
		listening = true
		s.logger.Printf("starting to listen for TLS on: %v\n", s.TLSListenerString)

		tlsSrv := &http.Server{
			Addr:      s.TLSListenerString,
			Handler:   h,
			TLSConfig: s.tlsConfig,
		}
		servers = append(servers, tlsSrv)

		go func() {
			if err := tlsSrv.ListenAndServeTLS("", ""); err != nil && !errors.Is(err, http.ErrServerClosed) {
				s.logger.Fatal(err)
			}
		}()
	}

	s.logger.Printf("---------------------------")

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
		s.logger.Printf("No listener active.")
	}

	s.logger.Printf("Shutting down...")
	s.purgeCancel()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	for _, srv := range servers {
		if err := srv.Shutdown(ctx); err != nil {
			s.logger.Printf("server shutdown error: %v", err)
		}
	}

	if s.logFile != nil {
		s.logFile.Close()
	}

	s.logger.Printf("Server stopped.")
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
	r.HandleFunc("/({files:.*}).zip", s.zipHandler).Methods("GET")
	r.HandleFunc("/({files:.*}).tar", s.tarHandler).Methods("GET")
	r.HandleFunc("/({files:.*}).tar.gz", s.tarGzHandler).Methods("GET")
	r.HandleFunc("/{token}/{filename}", s.headHandler).Methods("HEAD")
	r.HandleFunc("/{action:(?:download|get|inline)}/{token}/{filename}", s.headHandler).Methods("HEAD")
	r.HandleFunc("/{token}/{filename}", s.previewHandler).MatcherFunc(s.previewMatcher).Methods("GET")

	getHandlerFn := s.getHandler
	if s.rateLimitRequests > 0 {
		getHandlerFn = ratelimit.Request(ratelimit.IP).Rate(s.rateLimitRequests, 60*time.Second).LimitBy(memory.New())(http.HandlerFunc(getHandlerFn)).ServeHTTP
	}

	r.HandleFunc("/{token}/{filename}", getHandlerFn).Methods("GET")
	r.HandleFunc("/{action:(?:download|get|inline)}/{token}/{filename}", getHandlerFn).Methods("GET")
	r.HandleFunc("/{filename}/virustotal", s.virusTotalHandler).Methods("PUT")
	r.HandleFunc("/{filename}/scan", s.scanHandler).Methods("PUT")
	r.HandleFunc("/put/{filename}", s.basicAuthHandler(http.HandlerFunc(s.putHandler))).Methods("PUT")
	r.HandleFunc("/upload/{filename}", s.basicAuthHandler(http.HandlerFunc(s.putHandler))).Methods("PUT")
	r.HandleFunc("/{filename}", s.basicAuthHandler(http.HandlerFunc(s.putHandler))).Methods("PUT")
	r.HandleFunc("/", s.basicAuthHandler(http.HandlerFunc(s.postHandler))).Methods("POST")
	r.HandleFunc("/{token}/{filename}/{deletionToken}", s.deleteHandler).Methods("DELETE")
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
