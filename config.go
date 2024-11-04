package server

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"os"
	"sync"
	"time"

	"github.com/caddyserver/certmagic"
	"github.com/libdns/cloudflare"
	"go.uber.org/zap"
	"golang.org/x/sys/cpu"
)

type EntryPointsConfig map[string]EntryPointConfig

func (cfg EntryPointsConfig) InitDefaults() (err error) {
	for key, value := range cfg {
		err = errors.Join(err, value.InitDefaults())
		cfg[key] = value
	}
	return
}

type EntryPointConfig struct {
	// Host and port to handle as http server.
	Address string `json:"address,omitempty" yaml:"address,omitempty"`

	// HTTP2 defines http/2 server options.
	HTTP2 HTTP2Config `json:"http2,omitempty" yaml:"http2,omitempty"`

	// HTTP3 enables HTTP/3 protocol on the entryPoint. HTTP/3 requires a TCP entryPoint,
	// as HTTP/3 always starts as a TCP connection that then gets upgraded to UDP.
	// In most scenarios, this entryPoint is the same as the one used for TLS traffic.
	HTTP3 *HTTP3Config `json:"http3,omitempty" yaml:"http3,omitempty"`

	Transport TransportConfig `json:"transport,omitempty" yaml:"transport,omitempty"`

	HTTP HTTPConfig `json:"http,omitempty" yaml:"http,omitempty"`
}

func (cfg *EntryPointConfig) InitDefaults() error {
	switch cfg.Address {
	case ":http":
		cfg.Address = ":80"
	case ":https":
		cfg.Address = ":443"
	case "":
		if cfg.HTTP.TLS == nil {
			cfg.Address = ":80"
		} else {
			cfg.Address = ":443"
		}
	}

	cfg.HTTP2.InitDefaults()

	return cfg.HTTP.InitDefaults()
}

type HTTP2Config struct {
	// MaxConcurrentStreams specifies the number of concurrent
	// streams per connection that each client is allowed to initiate.
	// The MaxConcurrentStreams value must be greater than zero, defaults to 250.
	MaxConcurrentStreams uint `json:"maxConcurrentStreams,omitempty" yaml:"maxConcurrentStreams,omitempty"`
}

func (cfg *HTTP2Config) InitDefaults() {
	if cfg.MaxConcurrentStreams == 0 {
		cfg.MaxConcurrentStreams = 250
	}
}

type HTTP3Config struct {
	// AdvertisedPort defines which UDP port to advertise as the HTTP/3 authority.
	// It defaults to the entryPoint's address port. It can be used to override
	// the authority in the alt-svc header.
	AdvertisedPort uint `json:"advertisedPort,omitempty" yaml:"advertisedPort,omitempty"`
}

type TransportConfig struct {
	// ReadTimeout is the maximum duration for reading the entire
	// request, including the body. A zero or negative value means
	// there will be no timeout.
	//
	// Because ReadTimeout does not let Handlers make per-request
	// decisions on each request body's acceptable deadline or
	// upload rate, most users will prefer to use
	// ReadHeaderTimeout. It is valid to use them both.
	ReadTimeout time.Duration `json:"readTimeout,omitempty" yaml:"readTimeout,omitempty"`

	// ReadHeaderTimeout is the amount of time allowed to read
	// request headers. The connection's read deadline is reset
	// after reading the headers and the Handler can decide what
	// is considered too slow for the body. If zero, the value of
	// ReadTimeout is used. If negative, or if zero and ReadTimeout
	// is zero or negative, there is no timeout.
	ReadHeaderTimeout time.Duration `json:"readHeaderTimeout,omitempty" yaml:"readHeaderTimeout,omitempty"`

	// WriteTimeout is the maximum duration before timing out
	// writes of the response. It is reset whenever a new
	// request's header is read. Like ReadTimeout, it does not
	// let Handlers make decisions on a per-request basis.
	// A zero or negative value means there will be no timeout.
	WriteTimeout time.Duration `json:"writeTimeout,omitempty" yaml:"writeTimeout,omitempty"`

	// IdleTimeout is the maximum amount of time to wait for the
	// next request when keep-alives are enabled. If zero, the value
	// of ReadTimeout is used. If negative, or if zero and ReadTimeout
	// is zero or negative, there is no timeout.
	IdleTimeout time.Duration `json:"idleTimeout,omitempty" yaml:"idleTimeout,omitempty"`

	// MaxHeaderBytes controls the maximum number of bytes the
	// server will read parsing the request header's keys and
	// values, including the request line. It does not limit the
	// size of the request body.
	// If zero, http.DefaultMaxHeaderBytes is used.
	MaxHeaderBytes int `json:"maxHeaderBytes,omitempty" yaml:"maxHeaderBytes,omitempty"`
}

type HTTPConfig struct {
	Redirection *RedirectionConfig `json:"redirection,omitempty" yaml:"redirection,omitempty"`
	TLS         *TLSConfig         `json:"tls,omitempty" yaml:"tls,omitempty"`
}

func (cfg *HTTPConfig) InitDefaults() error {
	if cfg.TLS != nil {
		return cfg.TLS.InitDefaults()
	}
	return nil
}

type RedirectionConfig struct {
	EntryPoint struct {
		// To the target element, it can be:
		//   - an entry point name (ex: websecure)
		//   - a port (:443)
		// defaults: :443
		To string `json:"to,omitempty" yaml:"to,omitempty"`

		// Scheme the redirection target scheme, defaults to `https`
		Scheme string `json:"scheme,omitempty" yaml:"scheme,omitempty"`

		// Permanent to apply a permanent redirection
		Permanent bool `json:"permanent,omitempty" yaml:"permanent,omitempty"`
	} `json:"entryPoint,omitempty" yaml:"entryPoint,omitempty"`
}

type TLSConfig struct {
	InsecureSkipVerify bool                `json:"insecureSkipVerify,omitempty" yaml:"insecureSkipVerify,omitempty"`
	Certificates       []CertificateConfig `json:"certificates,omitempty" yaml:"certificates,omitempty"`
	ClientAuth         *ClientAuthConfig   `json:"clientAuth,omitempty" yaml:"clientAuth,omitempty"`
	Acme               *AcmeConfig         `json:"acme,omitempty" yaml:"acme,omitempty"`
}

func (cfg *TLSConfig) InitDefaults() error {
	if cfg.ClientAuth != nil {
		cfg.ClientAuth.InitDefaults()
	}

	if cfg.Acme != nil {
		return cfg.Acme.InitDefaults()
	}
	return nil
}

type CertificateConfig struct {
	CertFile string `json:"certFile,omitempty" yaml:"certFile,omitempty"`
	KeyFile  string `json:"keyFile,omitempty" yaml:"keyFile,omitempty"`
}

func (cfg CertificateConfig) Certificate() (tls.Certificate, error) {
	if cfg.CertFile == "" {
		return tls.Certificate{}, errors.New("CertFile is empty")
	}
	if cfg.KeyFile == "" {
		return tls.Certificate{}, errors.New("KeyFile is empty")
	}
	if info, err := os.Stat(cfg.CertFile); err == nil {
		if info.IsDir() {
			return tls.Certificate{}, errors.New("CertFile is dir")
		}

		if info, err = os.Stat(cfg.KeyFile); err == nil {
			if info.IsDir() {
				return tls.Certificate{}, errors.New("KeyFile is dir")
			}
		}

		return tls.LoadX509KeyPair(cfg.CertFile, cfg.KeyFile)
	}
	return tls.X509KeyPair([]byte(cfg.CertFile), []byte(cfg.KeyFile))
}

type ClientAuthConfig struct {
	ClientAuthType ClientAuthType `json:"clientAuthType,omitempty" yaml:"clientAuthType,omitempty"`
	CaFiles        []string       `json:"caFiles,omitempty" yaml:"caFiles,omitempty"`
}

func (cfg *ClientAuthConfig) InitDefaults() {
	if cfg.ClientAuthType == "" {
		cfg.ClientAuthType = NoClientCert
	}
}

func (cfg *ClientAuthConfig) CertPool() (*x509.CertPool, error) {
	pool := x509.NewCertPool()

	for _, file := range cfg.CaFiles {
		if file == "" {
			continue
		}

		var ca []byte
		if info, err := os.Stat(file); err == nil {
			if info.IsDir() {
				continue
			}
			ca, err = os.ReadFile(file)
			if err != nil {
				return nil, err
			}
		} else {
			ca = []byte(file)
		}

		if ok := pool.AppendCertsFromPEM(ca); !ok {
			return nil, errors.New("could not append Certs from PEM")
		}
	}

	return pool, nil
}

type ClientAuthType string

const (
	NoClientCert               ClientAuthType = "no_client_cert"
	RequestClientCert          ClientAuthType = "request_client_cert"
	RequireAnyClientCert       ClientAuthType = "require_any_client_cert"
	VerifyClientCertIfGiven    ClientAuthType = "verify_client_cert_if_given"
	RequireAndVerifyClientCert ClientAuthType = "require_and_verify_client_cert"
)

func (t ClientAuthType) TLSClientAuth() tls.ClientAuthType {
	switch t {
	case RequestClientCert:
		return tls.RequestClientCert
	case RequireAnyClientCert:
		return tls.RequireAnyClientCert
	case VerifyClientCertIfGiven:
		return tls.VerifyClientCertIfGiven
	case RequireAndVerifyClientCert:
		return tls.RequireAndVerifyClientCert
	default:
		return tls.NoClientCert
	}
}

type AcmeConfig struct {
	// directory to save the certificates, le_certs default
	CacheDir string `json:"cache_dir" yaml:"cache_dir"`

	// User email, mandatory
	Email string `json:"email" yaml:"email"`

	// Use LE production endpoint or staging
	UseProductionEndpoint bool `json:"use_production_endpoint" yaml:"use_production_endpoint"`

	// Domains to obtain certificates
	Domains []string `json:"domains" yaml:"domains"`

	HTTPChallenge *HTTPChallengeConfig `json:"httpChallenge" yaml:"httpChallenge"`

	TLSChallenge bool `json:"tlsChallenge" yaml:"tlsChallenge"`

	DNSChallenge *DNSChallengeConfig `json:"dnsChallenge" yaml:"dnsChallenge"`

	config *certmagic.Config
	mu     sync.RWMutex
}

func (cfg *AcmeConfig) Config(key string, mCfg EntryPointsConfig, logger *zap.Logger) *certmagic.Config {
	cfg.mu.RLock()
	config := cfg.config
	cfg.mu.RUnlock()
	if config != nil {
		return config
	}

	cfg.mu.Lock()
	defer cfg.mu.Unlock()

	logger = logger.Named(key)
	cacheDir := cfg.CacheDir

	cache := certmagic.NewCache(certmagic.CacheOptions{
		GetConfigForCert: func(c certmagic.Certificate) (*certmagic.Config, error) {
			return &certmagic.Config{
				RenewalWindowRatio: 0,
				MustStaple:         false,
				OCSP:               certmagic.OCSPConfig{},
				Storage:            &certmagic.FileStorage{Path: cacheDir},
				Logger:             logger,
			}, nil
		},
		OCSPCheckInterval:  0,
		RenewCheckInterval: 0,
		Capacity:           0,
	})

	cfg.config = certmagic.New(cache, certmagic.Config{
		RenewalWindowRatio: 0,
		MustStaple:         false,
		OCSP:               certmagic.OCSPConfig{},
		Storage:            &certmagic.FileStorage{Path: cacheDir},
		Logger:             logger,
	})

	ca := certmagic.LetsEncryptStagingCA
	if cfg.UseProductionEndpoint {
		ca = certmagic.LetsEncryptProductionCA
	}

	altHTTPPort := 80
	if ep, ok := mCfg[cfg.HTTPChallenge.EntryPoint]; ok {
		altHTTPPort = Port(ep.Address)
	}

	altTLSAlpnPort := 0
	if cfg.TLSChallenge {
		altTLSAlpnPort = Port(mCfg[key].Address)
	}

	myAcme := certmagic.NewACMEIssuer(cfg.config, certmagic.ACMEIssuer{
		CA:                      ca,
		TestCA:                  certmagic.LetsEncryptStagingCA,
		Email:                   cfg.Email,
		Agreed:                  true,
		DisableHTTPChallenge:    cfg.HTTPChallenge == nil,
		DisableTLSALPNChallenge: !cfg.TLSChallenge,
		ListenHost:              "0.0.0.0",
		AltHTTPPort:             altHTTPPort,
		AltTLSALPNPort:          altTLSAlpnPort,
		CertObtainTimeout:       time.Second * 240,
		PreferredChains:         certmagic.ChainPreference{},
		Logger:                  logger,
	})

	if cfg.DNSChallenge != nil && cfg.DNSChallenge.Provider == CloudflareProvider {
		myAcme.DNS01Solver = &certmagic.DNS01Solver{
			DNSManager: certmagic.DNSManager{
				DNSProvider: &cloudflare.Provider{
					APIToken: cfg.DNSChallenge.APIToken,
				},
			},
		}
	}

	cfg.config.Issuers = append(cfg.config.Issuers, myAcme)

	return cfg.config
}

func (cfg *AcmeConfig) InitDefaults() error {
	if cfg.CacheDir == "" {
		cfg.CacheDir = "cache_dir"
	}

	if cfg.Email == "" {
		return errors.New("email could not be empty")
	}

	if len(cfg.Domains) == 0 {
		return errors.New("should be at least 1 domain")
	}

	if cfg.DNSChallenge != nil {
		cfg.DNSChallenge.InitDefaults()

		if cfg.DNSChallenge.APIToken == "" {
			return errors.New("dnsChallenge.apiToken could not be empty")
		}
	}

	if cfg.HTTPChallenge != nil {
		if cfg.HTTPChallenge.EntryPoint == "" {
			return errors.New("httpChallenge.entryPoint could not be empty")
		}
	}

	if cfg.HTTPChallenge == nil && cfg.DNSChallenge == nil {
		cfg.TLSChallenge = true
	}

	return nil
}

type HTTPChallengeConfig struct {
	EntryPoint string `json:"entryPoint" yaml:"entryPoint"`
}

type DNSChallengeConfig struct {
	Provider DNSProviderType   `json:"provider" yaml:"provider"`
	APIToken string            `json:"apiToken" yaml:"apiToken"`
	Metadata map[string]string `json:"metadata" yaml:"metadata"`
}

type DNSProviderType string

const CloudflareProvider DNSProviderType = "cloudflare"

func (cfg *DNSChallengeConfig) InitDefaults() {
	if cfg.Provider == "" {
		cfg.Provider = CloudflareProvider
	}
}

func DefaultTLSConfig() *tls.Config {
	var topCipherSuites []uint16
	var defaultCipherSuitesTLS13 []uint16

	hasGCMAsmAMD64 := cpu.X86.HasAES && cpu.X86.HasPCLMULQDQ
	hasGCMAsmARM64 := cpu.ARM64.HasAES && cpu.ARM64.HasPMULL
	// Keep in sync with crypto/aes/cipher_s390x.go.
	hasGCMAsmS390X := cpu.S390X.HasAES && cpu.S390X.HasAESCBC && cpu.S390X.HasAESCTR && (cpu.S390X.HasGHASH || cpu.S390X.HasAESGCM)

	hasGCMAsm := hasGCMAsmAMD64 || hasGCMAsmARM64 || hasGCMAsmS390X

	if hasGCMAsm {
		// If AES-GCM hardware is provided then priorities AES-GCM
		// cipher suites.
		topCipherSuites = []uint16{
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
			tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
		}
		defaultCipherSuitesTLS13 = []uint16{
			tls.TLS_AES_128_GCM_SHA256,
			tls.TLS_CHACHA20_POLY1305_SHA256,
			tls.TLS_AES_256_GCM_SHA384,
		}
	} else {
		// Without AES-GCM hardware, we put the ChaCha20-Poly1305
		// cipher suites first.
		topCipherSuites = []uint16{
			tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
			tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
		}
		defaultCipherSuitesTLS13 = []uint16{
			tls.TLS_CHACHA20_POLY1305_SHA256,
			tls.TLS_AES_128_GCM_SHA256,
			tls.TLS_AES_256_GCM_SHA384,
		}
	}

	defaultCipherSuites := make([]uint16, 0, 22)
	defaultCipherSuites = append(defaultCipherSuites, topCipherSuites...)
	defaultCipherSuites = append(defaultCipherSuites, defaultCipherSuitesTLS13...)

	return &tls.Config{
		CurvePreferences: []tls.CurveID{
			tls.X25519,
			tls.CurveP256,
			tls.CurveP384,
			tls.CurveP521,
		},
		CipherSuites: defaultCipherSuites,
		MinVersion:   tls.VersionTLS12,
	}
}
