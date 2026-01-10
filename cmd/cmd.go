package cmd

import (
	"errors"
	"fmt"
	"log"
	"os"
	"regexp"
	"strconv"
	"strings"

	"github.com/morawskidotmy/transfer.ng/server/storage"

	"github.com/fatih/color"
	"github.com/morawskidotmy/transfer.ng/server"
	"github.com/urfave/cli/v2"
	"google.golang.org/api/googleapi"
)

var Version = "0.0.0"

func parseSize(s string) (int64, error) {
	re := regexp.MustCompile(`^(\d+(?:\.\d+)?)\s*([kmgt]?b?)$`)
	matches := re.FindStringSubmatch(strings.ToLower(strings.TrimSpace(s)))
	if matches == nil {
		return 0, fmt.Errorf("invalid size format: %s", s)
	}

	value, err := strconv.ParseFloat(matches[1], 64)
	if err != nil {
		return 0, err
	}

	unit := matches[2]
	multiplier := int64(1)

	switch unit {
	case "kb", "k":
		multiplier = 1024
	case "mb", "m":
		multiplier = 1024 * 1024
	case "gb", "g":
		multiplier = 1024 * 1024 * 1024
	case "tb", "t":
		multiplier = 1024 * 1024 * 1024 * 1024
	}

	return int64(value * float64(multiplier)), nil
}

var helpTemplate = `NAME:
{{.Name}} - {{.Usage}}

DESCRIPTION:
{{.Description}}

USAGE:
{{.Name}} {{if .Flags}}[flags] {{end}}command{{if .Flags}}{{end}} [arguments...]

COMMANDS:
{{range .Commands}}{{join .Names ", "}}{{ "\t" }}{{.Usage}}
{{end}}{{if .Flags}}
FLAGS:
{{range .Flags}}{{.}}
{{end}}{{end}}
VERSION:
` + Version +
	`{{ "\n"}}`

var globalFlags = []cli.Flag{
	&cli.StringFlag{
		Name:    "listener",
		Usage:   "127.0.0.1:8080",
		Value:   "127.0.0.1:8080",
		EnvVars: []string{"LISTENER"},
	},
	// redirect to https?
	// hostnames
	&cli.StringFlag{
		Name:    "profile-listener",
		Usage:   "127.0.0.1:6060",
		Value:   "",
		EnvVars: []string{"PROFILE_LISTENER"},
	},
	&cli.BoolFlag{
		Name:    "force-https",
		Usage:   "",
		EnvVars: []string{"FORCE_HTTPS"},
	},
	&cli.StringFlag{
		Name:    "tls-listener",
		Usage:   "127.0.0.1:8443",
		Value:   "",
		EnvVars: []string{"TLS_LISTENER"},
	},
	&cli.BoolFlag{
		Name:    "tls-listener-only",
		Usage:   "",
		EnvVars: []string{"TLS_LISTENER_ONLY"},
	},
	&cli.StringFlag{
		Name:    "tls-cert-file",
		Value:   "",
		EnvVars: []string{"TLS_CERT_FILE"},
	},
	&cli.StringFlag{
		Name:    "tls-private-key",
		Value:   "",
		EnvVars: []string{"TLS_PRIVATE_KEY"},
	},
	&cli.StringFlag{
		Name:    "temp-path",
		Usage:   "path to temp files",
		Value:   os.TempDir(),
		EnvVars: []string{"TEMP_PATH"},
	},
	&cli.StringFlag{
		Name:    "web-path",
		Usage:   "path to static web files",
		Value:   "",
		EnvVars: []string{"WEB_PATH"},
	},
	&cli.StringFlag{
		Name:    "proxy-path",
		Usage:   "path prefix when service is run behind a proxy",
		Value:   "",
		EnvVars: []string{"PROXY_PATH"},
	},
	&cli.StringFlag{
		Name:    "proxy-port",
		Usage:   "port of the proxy when the service is run behind a proxy",
		Value:   "",
		EnvVars: []string{"PROXY_PORT"},
	},
	&cli.StringFlag{
		Name:    "email-contact",
		Usage:   "email address to link in Contact Us (front end)",
		Value:   "",
		EnvVars: []string{"EMAIL_CONTACT"},
	},
	&cli.StringFlag{
		Name:    "ga-key",
		Usage:   "key for google analytics (front end)",
		Value:   "",
		EnvVars: []string{"GA_KEY"},
	},
	&cli.StringFlag{
		Name:    "uservoice-key",
		Usage:   "key for user voice (front end)",
		Value:   "",
		EnvVars: []string{"USERVOICE_KEY"},
	},
	&cli.StringFlag{
		Name:    "provider",
		Usage:   "s3|gdrive|storj|local",
		Value:   "",
		EnvVars: []string{"PROVIDER"},
	},
	&cli.StringFlag{
		Name:    "s3-endpoint",
		Usage:   "",
		Value:   "",
		EnvVars: []string{"S3_ENDPOINT"},
	},
	&cli.StringFlag{
		Name:    "s3-region",
		Usage:   "",
		Value:   "eu-west-1",
		EnvVars: []string{"S3_REGION"},
	},
	&cli.StringFlag{
		Name:    "aws-access-key",
		Usage:   "",
		Value:   "",
		EnvVars: []string{"AWS_ACCESS_KEY"},
	},
	&cli.StringFlag{
		Name:    "aws-secret-key",
		Usage:   "",
		Value:   "",
		EnvVars: []string{"AWS_SECRET_KEY"},
	},
	&cli.StringFlag{
		Name:    "bucket",
		Usage:   "",
		Value:   "",
		EnvVars: []string{"BUCKET"},
	},
	&cli.BoolFlag{
		Name:    "s3-no-multipart",
		Usage:   "Disables S3 Multipart Puts",
		EnvVars: []string{"S3_NO_MULTIPART"},
	},
	&cli.BoolFlag{
		Name:    "s3-path-style",
		Usage:   "Forces path style URLs, required for Minio.",
		EnvVars: []string{"S3_PATH_STYLE"},
	},
	&cli.StringFlag{
		Name:    "gdrive-client-json-filepath",
		Usage:   "",
		Value:   "",
		EnvVars: []string{"GDRIVE_CLIENT_JSON_FILEPATH"},
	},
	&cli.StringFlag{
		Name:    "gdrive-local-config-path",
		Usage:   "",
		Value:   "",
		EnvVars: []string{"GDRIVE_LOCAL_CONFIG_PATH"},
	},
	&cli.IntFlag{
		Name:    "gdrive-chunk-size",
		Usage:   "",
		Value:   googleapi.DefaultUploadChunkSize / 1024 / 1024,
		EnvVars: []string{"GDRIVE_CHUNK_SIZE"},
	},
	&cli.StringFlag{
		Name:    "storj-access",
		Usage:   "Access for the project",
		Value:   "",
		EnvVars: []string{"STORJ_ACCESS"},
	},
	&cli.StringFlag{
		Name:    "storj-bucket",
		Usage:   "Bucket to use within the project",
		Value:   "",
		EnvVars: []string{"STORJ_BUCKET"},
	},
	&cli.IntFlag{
		Name:    "rate-limit",
		Usage:   "requests per minute",
		Value:   0,
		EnvVars: []string{"RATE_LIMIT"},
	},
	&cli.IntFlag{
		Name:    "purge-days",
		Usage:   "number of days after uploads are purged automatically",
		Value:   0,
		EnvVars: []string{"PURGE_DAYS"},
	},
	&cli.IntFlag{
		Name:    "purge-interval",
		Usage:   "interval in hours to run the automatic purge for",
		Value:   0,
		EnvVars: []string{"PURGE_INTERVAL"},
	},
	&cli.Int64Flag{
		Name:    "max-upload-size",
		Usage:   "max limit for upload, in kilobytes",
		Value:   0,
		EnvVars: []string{"MAX_UPLOAD_SIZE"},
	},
	&cli.StringFlag{
		Name:    "lets-encrypt-hosts",
		Usage:   "host1, host2",
		Value:   "",
		EnvVars: []string{"HOSTS"},
	},
	&cli.StringFlag{
		Name:    "log",
		Usage:   "/var/log/transfersh.log",
		Value:   "",
		EnvVars: []string{"LOG"},
	},
	&cli.StringFlag{
		Name:    "basedir",
		Usage:   "path to storage",
		Value:   "",
		EnvVars: []string{"BASEDIR"},
	},
	&cli.StringFlag{
		Name:    "clamav-host",
		Usage:   "clamav-host",
		Value:   "",
		EnvVars: []string{"CLAMAV_HOST"},
	},
	&cli.BoolFlag{
		Name:    "perform-clamav-prescan",
		Usage:   "perform-clamav-prescan",
		EnvVars: []string{"PERFORM_CLAMAV_PRESCAN"},
	},
	&cli.StringFlag{
		Name:    "virustotal-key",
		Usage:   "virustotal-key",
		Value:   "",
		EnvVars: []string{"VIRUSTOTAL_KEY"},
	},
	&cli.BoolFlag{
		Name:    "profiler",
		Usage:   "enable profiling",
		EnvVars: []string{"PROFILER"},
	},
	&cli.StringFlag{
		Name:    "http-auth-user",
		Usage:   "user for http basic auth",
		Value:   "",
		EnvVars: []string{"HTTP_AUTH_USER"},
	},
	&cli.StringFlag{
		Name:    "http-auth-pass",
		Usage:   "pass for http basic auth",
		Value:   "",
		EnvVars: []string{"HTTP_AUTH_PASS"},
	},
	&cli.StringFlag{
		Name:    "http-auth-htpasswd",
		Usage:   "htpasswd file http basic auth",
		Value:   "",
		EnvVars: []string{"HTTP_AUTH_HTPASSWD"},
	},
	&cli.StringFlag{
		Name:    "http-auth-ip-whitelist",
		Usage:   "comma separated list of ips allowed to upload without being challenged an http auth",
		Value:   "",
		EnvVars: []string{"HTTP_AUTH_IP_WHITELIST"},
	},
	&cli.StringFlag{
		Name:    "ip-whitelist",
		Usage:   "comma separated list of ips allowed to connect to the service",
		Value:   "",
		EnvVars: []string{"IP_WHITELIST"},
	},
	&cli.StringFlag{
		Name:    "ip-blacklist",
		Usage:   "comma separated list of ips not allowed to connect to the service",
		Value:   "",
		EnvVars: []string{"IP_BLACKLIST"},
	},
	&cli.StringFlag{
		Name:    "cors-domains",
		Usage:   "comma separated list of domains allowed for CORS requests",
		Value:   "",
		EnvVars: []string{"CORS_DOMAINS"},
	},
	&cli.BoolFlag{
		Name:    "insecure",
		Usage:   "disable IP filtering and CORS checks (security managed by reverse proxy/firewall)",
		Value:   false,
		EnvVars: []string{"INSECURE"},
	},
	&cli.IntFlag{
		Name:    "random-token-length",
		Usage:   "",
		Value:   10,
		EnvVars: []string{"RANDOM_TOKEN_LENGTH"},
	},
	&cli.StringFlag{
		Name:    "compress-large",
		Usage:   "compress files larger than this size (e.g. 10m, 1g)",
		Value:   "10m",
		EnvVars: []string{"COMPRESS_LARGE"},
	},
}

// Cmd wraps cli.app
type Cmd struct {
	*cli.App
}

func versionCommand(_ *cli.Context) error {
	fmt.Println(color.YellowString("transfer.ng %s: Easy file sharing from the command line", Version))
	return nil
}

func appAction(c *cli.Context, logger *log.Logger) error {
	options := []server.OptionFn{}

	addBasicOptions(c, &options, logger)
	addTLSOptions(c, &options)

	if err := addSecurityOptions(c, &options); err != nil {
		return err
	}

	purgeDays := c.Int("purge-days")
	if err := addStorageProvider(c, &options, logger, purgeDays); err != nil {
		return err
	}

	srvr, err := server.New(options...)
	if err != nil {
		logger.Println(color.RedString("Error starting server: %s", err.Error()))
		return err
	}

	srvr.Run()
	return nil
}

func New() *Cmd {
	logger := log.New(os.Stdout, "[transfer.ng]", log.LstdFlags)

	app := cli.NewApp()
	app.Name = "transfer.ng"
	app.Authors = []*cli.Author{}
	app.Usage = "transfer.ng"
	app.Description = `Easy file sharing from the command line`
	app.Version = Version
	app.Flags = globalFlags
	app.CustomAppHelpTemplate = helpTemplate
	app.Commands = []*cli.Command{
		{
			Name:   "version",
			Action: versionCommand,
		},
	}

	app.Before = func(c *cli.Context) error {
		return nil
	}

	app.Action = func(c *cli.Context) error {
		return appAction(c, logger)
	}

	return &Cmd{
		App: app,
	}
}

func addBasicOptions(c *cli.Context, options *[]server.OptionFn, logger *log.Logger) {
	addStringOption(c, options, "listener", server.Listener)
	addStringOption(c, options, "cors-domains", server.CorsDomains)
	addStringOption(c, options, "profile-listener", server.ProfileListener)
	addStringOption(c, options, "web-path", server.WebPath)
	addStringOption(c, options, "proxy-path", server.ProxyPath)
	addStringOption(c, options, "proxy-port", server.ProxyPort)
	addStringOption(c, options, "email-contact", server.EmailContact)
	addStringOption(c, options, "ga-key", server.GoogleAnalytics)
	addStringOption(c, options, "uservoice-key", server.UserVoice)
	addStringOption(c, options, "temp-path", server.TempPath)
	addStringOption(c, options, "lets-encrypt-hosts", func(v string) server.OptionFn {
		return server.UseLetsEncrypt(strings.Split(v, ","))
	})
	addStringOption(c, options, "virustotal-key", server.VirustotalKey)
	addStringOption(c, options, "clamav-host", server.ClamavHost)

	if v := c.String("log"); v != "" {
		*options = append(*options, server.LogFile(logger, v))
	} else {
		*options = append(*options, server.Logger(logger))
	}

	if c.Bool("perform-clamav-prescan") {
		*options = append(*options, server.PerformClamavPrescan(true))
	}

	if v := c.Int64("max-upload-size"); v > 0 {
		*options = append(*options, server.MaxUploadSize(v))
	}

	if v := c.Int("rate-limit"); v > 0 {
		*options = append(*options, server.RateLimit(v))
	}

	*options = append(*options, server.RandomTokenLength(c.Int("random-token-length")))

	if v := c.String("compress-large"); v != "" {
		if bytes, err := parseSize(v); err == nil {
			*options = append(*options, server.CompressionThreshold(bytes))
		}
	}
}

func addStringOption(c *cli.Context, options *[]server.OptionFn, flag string, fn func(string) server.OptionFn) {
	if v := c.String(flag); v != "" {
		*options = append(*options, fn(v))
	}
}

func addTLSOptions(c *cli.Context, options *[]server.OptionFn) {
	if v := c.String("tls-listener"); v != "" {
		tlsOnly := c.Bool("tls-listener-only")
		*options = append(*options, server.TLSListener(v, tlsOnly))
	}

	if cert := c.String("tls-cert-file"); cert != "" {
		if pk := c.String("tls-private-key"); pk != "" {
			*options = append(*options, server.TLSConfig(cert, pk))
		}
	}

	if c.Bool("profiler") {
		*options = append(*options, server.EnableProfiler())
	}

	if c.Bool("force-https") {
		*options = append(*options, server.ForceHTTPS())
	}
}

func addSecurityOptions(c *cli.Context, options *[]server.OptionFn) error {
	purgeDays := c.Int("purge-days")
	purgeInterval := c.Int("purge-interval")
	if purgeDays > 0 && purgeInterval > 0 {
		*options = append(*options, server.Purge(purgeDays, purgeInterval))
	}

	if httpAuthUser := c.String("http-auth-user"); httpAuthUser != "" {
		if httpAuthPass := c.String("http-auth-pass"); httpAuthPass != "" {
			*options = append(*options, server.HTTPAuthCredentials(httpAuthUser, httpAuthPass))
		}
	}

	if httpAuthHtpasswd := c.String("http-auth-htpasswd"); httpAuthHtpasswd != "" {
		*options = append(*options, server.HTTPAuthHtpasswd(httpAuthHtpasswd))
	}

	if !c.Bool("insecure") {
		if err := addIPFilterOptions(c, options); err != nil {
			return err
		}
	}

	if c.Bool("perform-clamav-prescan") && c.String("clamav-host") == "" {
		return errors.New("clamav-host not set")
	}

	return nil
}

func addIPFilterOptions(c *cli.Context, options *[]server.OptionFn) error {
	if httpAuthIPWhitelist := c.String("http-auth-ip-whitelist"); httpAuthIPWhitelist != "" {
		ipFilterOptions := server.IPFilterOptions{
			AllowedIPs:     strings.Split(httpAuthIPWhitelist, ","),
			BlockByDefault: true,
		}
		*options = append(*options, server.HTTPAUTHFilterOptions(ipFilterOptions))
	}

	applyIPFilter := false
	ipFilterOptions := server.IPFilterOptions{}
	if ipWhitelist := c.String("ip-whitelist"); ipWhitelist != "" {
		applyIPFilter = true
		ipFilterOptions.AllowedIPs = strings.Split(ipWhitelist, ",")
		ipFilterOptions.BlockByDefault = true
	}

	if ipBlacklist := c.String("ip-blacklist"); ipBlacklist != "" {
		applyIPFilter = true
		ipFilterOptions.BlockedIPs = strings.Split(ipBlacklist, ",")
	}

	if applyIPFilter {
		*options = append(*options, server.FilterOptions(ipFilterOptions))
	}

	return nil
}

func addStorageProvider(c *cli.Context, options *[]server.OptionFn, logger *log.Logger, purgeDays int) error {
	provider := c.String("provider")

	switch provider {
	case "s3":
		return addS3Storage(c, options, logger, purgeDays)
	case "gdrive":
		return addGDriveStorage(c, options, logger)
	case "storj":
		return addStorjStorage(c, options, logger, purgeDays)
	case "local":
		return addLocalStorage(c, options, logger)
	default:
		return errors.New("Provider not set or invalid.")
	}
}

func addS3Storage(c *cli.Context, options *[]server.OptionFn, logger *log.Logger, purgeDays int) error {
	accessKey := c.String("aws-access-key")
	secretKey := c.String("aws-secret-key")
	bucket := c.String("bucket")

	if accessKey == "" {
		return errors.New("access-key not set.")
	}
	if secretKey == "" {
		return errors.New("secret-key not set.")
	}
	if bucket == "" {
		return errors.New("bucket not set.")
	}

	store, err := storage.NewS3Storage(c.Context, accessKey, secretKey, bucket, purgeDays,
		c.String("s3-region"), c.String("s3-endpoint"),
		c.Bool("s3-no-multipart"), c.Bool("s3-path-style"), logger)
	if err != nil {
		return err
	}

	*options = append(*options, server.UseStorage(store))
	return nil
}

func addGDriveStorage(c *cli.Context, options *[]server.OptionFn, logger *log.Logger) error {
	chunkSize := c.Int("gdrive-chunk-size") * 1024 * 1024
	clientJSONFilepath := c.String("gdrive-client-json-filepath")
	localConfigPath := c.String("gdrive-local-config-path")
	basedir := c.String("basedir")

	if clientJSONFilepath == "" {
		return errors.New("gdrive-client-json-filepath not set.")
	}
	if localConfigPath == "" {
		return errors.New("gdrive-local-config-path not set.")
	}
	if basedir == "" {
		return errors.New("basedir not set.")
	}

	store, err := storage.NewGDriveStorage(c.Context, clientJSONFilepath, localConfigPath, basedir, chunkSize, logger)
	if err != nil {
		return err
	}

	*options = append(*options, server.UseStorage(store))
	return nil
}

func addStorjStorage(c *cli.Context, options *[]server.OptionFn, logger *log.Logger, purgeDays int) error {
	access := c.String("storj-access")
	bucket := c.String("storj-bucket")

	if access == "" {
		return errors.New("storj-access not set.")
	}
	if bucket == "" {
		return errors.New("storj-bucket not set.")
	}

	store, err := storage.NewStorjStorage(c.Context, access, bucket, purgeDays, logger)
	if err != nil {
		return err
	}

	*options = append(*options, server.UseStorage(store))
	return nil
}

func addLocalStorage(c *cli.Context, options *[]server.OptionFn, logger *log.Logger) error {
	basedir := c.String("basedir")
	if basedir == "" {
		return errors.New("basedir not set.")
	}

	store, err := storage.NewLocalStorage(basedir, logger)
	if err != nil {
		return err
	}

	*options = append(*options, server.UseStorage(store))
	return nil
}
