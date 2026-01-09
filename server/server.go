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

	assetfs "github.com/elazarl/go-bindata-assetfs"
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
func (s *Server) Run() {
	listening := false

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

	_ = mime.AddExtensionType(".md", "text/x-markdown")
	_ = mime.AddExtensionType(".markdown", "text/x-markdown")
	_ = mime.AddExtensionType(".mdown", "text/x-markdown")
	_ = mime.AddExtensionType(".mkdown", "text/x-markdown")
	_ = mime.AddExtensionType(".mkd", "text/x-markdown")
	_ = mime.AddExtensionType(".mdx", "text/x-markdown")
	_ = mime.AddExtensionType(".conf", "text/plain")
	_ = mime.AddExtensionType(".config", "text/plain")
	_ = mime.AddExtensionType(".cfg", "text/plain")
	_ = mime.AddExtensionType(".ini", "text/plain")
	_ = mime.AddExtensionType(".toml", "text/plain")
	_ = mime.AddExtensionType(".properties", "text/plain")
	_ = mime.AddExtensionType(".gradle.properties", "text/plain")
	_ = mime.AddExtensionType(".maven.properties", "text/plain")
	_ = mime.AddExtensionType(".yml", "text/yaml")
	_ = mime.AddExtensionType(".yaml", "text/yaml")
	_ = mime.AddExtensionType(".json", "application/json")
	_ = mime.AddExtensionType(".jsonld", "application/ld+json")
	_ = mime.AddExtensionType(".json5", "application/json")
	_ = mime.AddExtensionType(".geojson", "application/geo+json")
	_ = mime.AddExtensionType(".xml", "application/xml")
	_ = mime.AddExtensionType(".xsl", "application/xml")
	_ = mime.AddExtensionType(".xslt", "application/xml")
	_ = mime.AddExtensionType(".svg", "image/svg+xml")
	_ = mime.AddExtensionType(".plist", "application/x-plist")
	_ = mime.AddExtensionType(".sh", "text/x-shellscript")
	_ = mime.AddExtensionType(".bash", "text/x-shellscript")
	_ = mime.AddExtensionType(".zsh", "text/x-shellscript")
	_ = mime.AddExtensionType(".fish", "text/x-shellscript")
	_ = mime.AddExtensionType(".ksh", "text/x-shellscript")
	_ = mime.AddExtensionType(".csh", "text/x-shellscript")
	_ = mime.AddExtensionType(".tcsh", "text/x-shellscript")
	_ = mime.AddExtensionType(".ash", "text/x-shellscript")
	_ = mime.AddExtensionType(".ps1", "text/x-powershell")
	_ = mime.AddExtensionType(".psd1", "text/x-powershell")
	_ = mime.AddExtensionType(".psm1", "text/x-powershell")
	_ = mime.AddExtensionType(".bat", "text/x-batch")
	_ = mime.AddExtensionType(".cmd", "text/x-batch")
	_ = mime.AddExtensionType(".sql", "text/x-sql")
	_ = mime.AddExtensionType(".sqlite", "text/x-sql")
	_ = mime.AddExtensionType(".plsql", "text/x-sql")
	_ = mime.AddExtensionType(".tsql", "text/x-sql")
	_ = mime.AddExtensionType(".env", "text/plain")
	_ = mime.AddExtensionType(".env.example", "text/plain")
	_ = mime.AddExtensionType(".env.local", "text/plain")
	_ = mime.AddExtensionType(".env.development", "text/plain")
	_ = mime.AddExtensionType(".env.production", "text/plain")
	_ = mime.AddExtensionType(".editorconfig", "text/plain")
	_ = mime.AddExtensionType(".gitconfig", "text/plain")
	_ = mime.AddExtensionType(".gitignore", "text/plain")
	_ = mime.AddExtensionType(".gitattributes", "text/plain")
	_ = mime.AddExtensionType(".dockerignore", "text/plain")
	_ = mime.AddExtensionType(".dockerfile", "text/x-dockerfile")
	_ = mime.AddExtensionType(".Dockerfile", "text/x-dockerfile")
	_ = mime.AddExtensionType(".py", "text/x-python")
	_ = mime.AddExtensionType(".pyw", "text/x-python")
	_ = mime.AddExtensionType(".pyx", "text/x-python")
	_ = mime.AddExtensionType(".pyi", "text/x-python")
	_ = mime.AddExtensionType(".rb", "text/x-ruby")
	_ = mime.AddExtensionType(".rbw", "text/x-ruby")
	_ = mime.AddExtensionType(".rake", "text/x-ruby")
	_ = mime.AddExtensionType(".gemspec", "text/x-ruby")
	_ = mime.AddExtensionType(".go", "text/x-go")
	_ = mime.AddExtensionType(".rs", "text/x-rust")
	_ = mime.AddExtensionType(".java", "text/x-java")
	_ = mime.AddExtensionType(".class", "application/x-java-applet")
	_ = mime.AddExtensionType(".jar", "application/x-java-archive")
	_ = mime.AddExtensionType(".c", "text/x-csrc")
	_ = mime.AddExtensionType(".cc", "text/x-c++src")
	_ = mime.AddExtensionType(".cpp", "text/x-c++src")
	_ = mime.AddExtensionType(".cxx", "text/x-c++src")
	_ = mime.AddExtensionType(".c++", "text/x-c++src")
	_ = mime.AddExtensionType(".h", "text/x-csrc")
	_ = mime.AddExtensionType(".hh", "text/x-c++src")
	_ = mime.AddExtensionType(".hpp", "text/x-c++src")
	_ = mime.AddExtensionType(".hxx", "text/x-c++src")
	_ = mime.AddExtensionType(".h++", "text/x-c++src")
	_ = mime.AddExtensionType(".cs", "text/x-csharp")
	_ = mime.AddExtensionType(".php", "text/x-php")
	_ = mime.AddExtensionType(".php3", "text/x-php")
	_ = mime.AddExtensionType(".php4", "text/x-php")
	_ = mime.AddExtensionType(".php5", "text/x-php")
	_ = mime.AddExtensionType(".php7", "text/x-php")
	_ = mime.AddExtensionType(".php8", "text/x-php")
	_ = mime.AddExtensionType(".phtml", "text/x-php")
	_ = mime.AddExtensionType(".swift", "text/x-swift")
	_ = mime.AddExtensionType(".kt", "text/x-kotlin")
	_ = mime.AddExtensionType(".scala", "text/x-scala")
	_ = mime.AddExtensionType(".groovy", "text/x-groovy")
	_ = mime.AddExtensionType(".gradle", "text/x-gradle")
	_ = mime.AddExtensionType(".pl", "text/x-perl")
	_ = mime.AddExtensionType(".pm", "text/x-perl")
	_ = mime.AddExtensionType(".t", "text/x-perl")
	_ = mime.AddExtensionType(".lua", "text/x-lua")
	_ = mime.AddExtensionType(".vim", "text/x-vim")
	_ = mime.AddExtensionType(".el", "text/x-elisp")
	_ = mime.AddExtensionType(".lisp", "text/x-lisp")
	_ = mime.AddExtensionType(".clj", "text/x-clojure")
	_ = mime.AddExtensionType(".cljs", "text/x-clojure")
	_ = mime.AddExtensionType(".edn", "text/x-clojure")
	_ = mime.AddExtensionType(".ex", "text/x-elixir")
	_ = mime.AddExtensionType(".exs", "text/x-elixir")
	_ = mime.AddExtensionType(".erl", "text/x-erlang")
	_ = mime.AddExtensionType(".hrl", "text/x-erlang")
	_ = mime.AddExtensionType(".ml", "text/x-ocaml")
	_ = mime.AddExtensionType(".mli", "text/x-ocaml")
	_ = mime.AddExtensionType(".fs", "text/x-fsharp")
	_ = mime.AddExtensionType(".fsx", "text/x-fsharp")
	_ = mime.AddExtensionType(".fsi", "text/x-fsharp")
	_ = mime.AddExtensionType(".hs", "text/x-haskell")
	_ = mime.AddExtensionType(".lhs", "text/x-haskell")
	_ = mime.AddExtensionType(".r", "text/x-r")
	_ = mime.AddExtensionType(".R", "text/x-r")
	_ = mime.AddExtensionType(".jl", "text/x-julia")
	_ = mime.AddExtensionType(".m", "text/x-matlab")
	_ = mime.AddExtensionType(".m", "text/x-objc")
	_ = mime.AddExtensionType(".mm", "text/x-objc++")
	_ = mime.AddExtensionType(".dart", "text/x-dart")
	_ = mime.AddExtensionType(".pas", "text/x-pascal")
	_ = mime.AddExtensionType(".pp", "text/x-pascal")
	_ = mime.AddExtensionType(".d", "text/x-d")
	_ = mime.AddExtensionType(".asm", "text/x-asm")
	_ = mime.AddExtensionType(".s", "text/x-asm")
	_ = mime.AddExtensionType(".vb", "text/x-vbnet")
	_ = mime.AddExtensionType(".vbs", "text/x-vbscript")
	_ = mime.AddExtensionType(".js", "text/javascript")
	_ = mime.AddExtensionType(".mjs", "text/javascript")
	_ = mime.AddExtensionType(".cjs", "text/javascript")
	_ = mime.AddExtensionType(".ts", "text/typescript")
	_ = mime.AddExtensionType(".tsx", "text/typescript")
	_ = mime.AddExtensionType(".jsx", "text/jsx")
	_ = mime.AddExtensionType(".css", "text/css")
	_ = mime.AddExtensionType(".scss", "text/x-scss")
	_ = mime.AddExtensionType(".sass", "text/x-sass")
	_ = mime.AddExtensionType(".less", "text/x-less")
	_ = mime.AddExtensionType(".styl", "text/x-stylus")
	_ = mime.AddExtensionType(".stylus", "text/x-stylus")
	_ = mime.AddExtensionType(".html", "text/html")
	_ = mime.AddExtensionType(".htm", "text/html")
	_ = mime.AddExtensionType(".xhtml", "application/xhtml+xml")
	_ = mime.AddExtensionType(".vue", "text/x-vue")
	_ = mime.AddExtensionType(".svelte", "text/x-svelte")
	_ = mime.AddExtensionType(".astro", "text/x-astro")
	_ = mime.AddExtensionType(".jsx", "text/jsx")
	_ = mime.AddExtensionType(".template", "text/plain")
	_ = mime.AddExtensionType(".jinja", "text/x-jinja")
	_ = mime.AddExtensionType(".jinja2", "text/x-jinja")
	_ = mime.AddExtensionType(".j2", "text/x-jinja")
	_ = mime.AddExtensionType(".makefile", "text/x-makefile")
	_ = mime.AddExtensionType(".Makefile", "text/x-makefile")
	_ = mime.AddExtensionType(".cmake", "text/x-cmake")
	_ = mime.AddExtensionType(".CMakeLists.txt", "text/x-cmake")
	_ = mime.AddExtensionType(".gradle", "text/x-gradle")
	_ = mime.AddExtensionType(".maven", "text/x-maven")
	_ = mime.AddExtensionType(".pom", "text/x-maven")
	_ = mime.AddExtensionType(".npm", "text/plain")
	_ = mime.AddExtensionType(".yarn", "text/plain")
	_ = mime.AddExtensionType(".requirements.txt", "text/plain")
	_ = mime.AddExtensionType(".Gemfile", "text/x-ruby")
	_ = mime.AddExtensionType(".Rakefile", "text/x-ruby")
	_ = mime.AddExtensionType(".Procfile", "text/plain")
	_ = mime.AddExtensionType(".lock", "text/plain")
	_ = mime.AddExtensionType(".log", "text/plain")
	_ = mime.AddExtensionType(".txt", "text/plain")
	_ = mime.AddExtensionType(".text", "text/plain")
	_ = mime.AddExtensionType(".csv", "text/csv")
	_ = mime.AddExtensionType(".tsv", "text/tab-separated-values")
	_ = mime.AddExtensionType(".psv", "text/plain")
	_ = mime.AddExtensionType(".md5", "text/plain")
	_ = mime.AddExtensionType(".sha1", "text/plain")
	_ = mime.AddExtensionType(".sha256", "text/plain")
	_ = mime.AddExtensionType(".sha512", "text/plain")
	_ = mime.AddExtensionType(".checksum", "text/plain")
	_ = mime.AddExtensionType(".gpg", "application/pgp-encrypted")
	_ = mime.AddExtensionType(".asc", "application/pgp-signature")
	_ = mime.AddExtensionType(".sig", "application/pgp-signature")
	_ = mime.AddExtensionType(".key", "application/pgp-keys")
	_ = mime.AddExtensionType(".pub", "text/plain")
	_ = mime.AddExtensionType(".pem", "application/x-pem-file")
	_ = mime.AddExtensionType(".crt", "application/x-x509-ca-cert")
	_ = mime.AddExtensionType(".cer", "application/x-x509-ca-cert")
	_ = mime.AddExtensionType(".der", "application/x-x509-ca-cert")
	_ = mime.AddExtensionType(".p7b", "application/x-pkcs7-certificates")
	_ = mime.AddExtensionType(".p12", "application/x-pkcs12")
	_ = mime.AddExtensionType(".pfx", "application/x-pkcs12")
	_ = mime.AddExtensionType(".jks", "application/x-java-keystore")
	_ = mime.AddExtensionType(".keystore", "application/x-java-keystore")
	_ = mime.AddExtensionType(".csr", "application/pkcs10")
	_ = mime.AddExtensionType(".acme", "text/plain")
	_ = mime.AddExtensionType(".htaccess", "text/plain")
	_ = mime.AddExtensionType(".htpasswd", "text/plain")
	_ = mime.AddExtensionType(".htgroups", "text/plain")
	_ = mime.AddExtensionType(".robots.txt", "text/plain")
	_ = mime.AddExtensionType(".sitemap.xml", "application/xml")
	_ = mime.AddExtensionType(".manifest", "text/cache-manifest")
	_ = mime.AddExtensionType(".webmanifest", "application/manifest+json")
	_ = mime.AddExtensionType(".appcache", "text/cache-manifest")
	_ = mime.AddExtensionType(".mo", "application/x-gettext")
	_ = mime.AddExtensionType(".po", "application/x-gettext")
	_ = mime.AddExtensionType(".pot", "application/x-gettext")
	_ = mime.AddExtensionType(".ts", "application/typescript")
	_ = mime.AddExtensionType(".po", "text/x-po")
	_ = mime.AddExtensionType(".pot", "text/x-pot")
	_ = mime.AddExtensionType(".resx", "application/x-resx")
	_ = mime.AddExtensionType(".strings", "text/plain")
	_ = mime.AddExtensionType(".properties", "text/x-properties")
	_ = mime.AddExtensionType(".gradle", "text/x-gradle")
	_ = mime.AddExtensionType(".bazel", "text/plain")
	_ = mime.AddExtensionType(".buck", "text/plain")
	_ = mime.AddExtensionType(".bazelrc", "text/plain")
	_ = mime.AddExtensionType(".clangformat", "text/plain")
	_ = mime.AddExtensionType(".clang-format", "text/plain")
	_ = mime.AddExtensionType(".prettierrc", "application/json")
	_ = mime.AddExtensionType(".prettierignore", "text/plain")
	_ = mime.AddExtensionType(".eslintrc", "application/json")
	_ = mime.AddExtensionType(".eslintignore", "text/plain")
	_ = mime.AddExtensionType(".stylelintrc", "application/json")
	_ = mime.AddExtensionType(".stylelintignore", "text/plain")
	_ = mime.AddExtensionType(".babelrc", "application/json")
	_ = mime.AddExtensionType(".babelrc.js", "text/javascript")
	_ = mime.AddExtensionType(".eslintrc.json", "application/json")
	_ = mime.AddExtensionType(".eslintrc.yml", "text/yaml")
	_ = mime.AddExtensionType(".eslintrc.yaml", "text/yaml")
	_ = mime.AddExtensionType(".eslintrc.js", "text/javascript")
	_ = mime.AddExtensionType(".browserslistrc", "text/plain")
	_ = mime.AddExtensionType(".npmrc", "text/plain")
	_ = mime.AddExtensionType(".yarnrc", "text/plain")
	_ = mime.AddExtensionType(".nvmrc", "text/plain")
	_ = mime.AddExtensionType(".node-version", "text/plain")
	_ = mime.AddExtensionType(".ruby-version", "text/plain")
	_ = mime.AddExtensionType(".go-version", "text/plain")
	_ = mime.AddExtensionType(".python-version", "text/plain")
	_ = mime.AddExtensionType(".php-version", "text/plain")
	_ = mime.AddExtensionType(".terraform", "text/plain")
	_ = mime.AddExtensionType(".tf", "text/plain")
	_ = mime.AddExtensionType(".tfvars", "text/plain")
	_ = mime.AddExtensionType(".hcl", "text/plain")
	_ = mime.AddExtensionType(".ansible", "text/x-yaml")
	_ = mime.AddExtensionType(".yml.j2", "text/x-jinja")
	_ = mime.AddExtensionType(".yaml.j2", "text/x-jinja")
	_ = mime.AddExtensionType(".graphql", "text/graphql")
	_ = mime.AddExtensionType(".gql", "text/graphql")
	_ = mime.AddExtensionType(".proto", "text/x-protobuf")
	_ = mime.AddExtensionType(".thrift", "text/x-thrift")
	_ = mime.AddExtensionType(".idl", "text/x-idl")
	_ = mime.AddExtensionType(".wsdl", "application/xml")
	_ = mime.AddExtensionType(".wadl", "application/xml")
	_ = mime.AddExtensionType(".raml", "application/raml+yaml")
	_ = mime.AddExtensionType(".openapi", "application/yaml")
	_ = mime.AddExtensionType(".swagger", "application/yaml")
	_ = mime.AddExtensionType(".swagger.json", "application/json")
	_ = mime.AddExtensionType(".asyncapi", "application/yaml")
	_ = mime.AddExtensionType(".asyncapi.json", "application/json")

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

		go func() {
			srvr := &http.Server{
				Addr:    s.ListenerString,
				Handler: h,
			}

			if err := srvr.ListenAndServe(); err != nil {
				s.logger.Fatal(err)
			}
		}()
	}

	if s.TLSListenerString != "" {
		listening = true
		s.logger.Printf("starting to listen for TLS on: %v\n", s.TLSListenerString)

		go func() {
			srvr := &http.Server{
				Addr:      s.TLSListenerString,
				Handler:   h,
				TLSConfig: s.tlsConfig,
			}

			if err := srvr.ListenAndServeTLS("", ""); err != nil {
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

	s.purgeCancel()

	if s.logFile != nil {
		s.logFile.Close()
	}

	s.logger.Printf("Server stopped.")
}

func (s *Server) loadTemplatesFromPath() {
	s.htmlTemplatesMutex.Lock()
	s.htmlTemplates, _ = s.htmlTemplates.ParseGlob(filepath.Join(s.webPath, "*.html"))
	s.htmlTemplatesMutex.Unlock()
	s.textTemplatesMutex.Lock()
	s.textTemplates, _ = s.textTemplates.ParseGlob(filepath.Join(s.webPath, "*.txt"))
	s.textTemplatesMutex.Unlock()
}

func (s *Server) createAssetFS() http.FileSystem {
	return &assetfs.AssetFS{
		Asset:    web.Asset,
		AssetDir: web.AssetDir,
		AssetInfo: func(path string) (os.FileInfo, error) {
			return os.Stat(path)
		},
		Prefix: web.Prefix,
	}
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
		s.logger.Fatal(err)
		return false
	}
	return u.Path != r.URL.Path
}
