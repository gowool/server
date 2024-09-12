package server

import (
	"crypto/tls"
	"errors"
	"fmt"
	"os"
	"strings"

	"golang.org/x/sys/cpu"
)

type ClientAuthType string

const (
	NoClientCert               ClientAuthType = "no_client_cert"
	RequestClientCert          ClientAuthType = "request_client_cert"
	RequireAnyClientCert       ClientAuthType = "require_any_client_cert"
	VerifyClientCertIfGiven    ClientAuthType = "verify_client_cert_if_given"
	RequireAndVerifyClientCert ClientAuthType = "require_and_verify_client_cert"
)

type ChallengeType string

const (
	HTTP01    ChallengeType = "http-01"
	TLSAlpn01 ChallengeType = "tlsalpn-01"
)

type Config struct {
	// Host and port to handle as http server.
	Address string `json:"address,omitempty" yaml:"address,omitempty"`

	// Redirect when enabled forces all http connections to switch to https.
	Redirect bool `json:"redirect,omitempty" yaml:"redirect,omitempty"`

	// H2C defines http/2 server options.
	H2C H2CConfig `json:"h2c,omitempty" yaml:"h2c,omitempty"`

	// SSL defines https server options.
	SSL *SSLConfig `json:"ssl,omitempty" yaml:"ssl,omitempty"`
}

func (cfg *Config) EnableTLS() bool {
	return cfg.SSL != nil && cfg.SSL.Enable()
}

func (cfg *Config) InitDefaults() error {
	if cfg.Address == "" {
		cfg.Address = "0.0.0.0:80"
	}

	cfg.H2C.InitDefaults()

	if cfg.SSL != nil {
		if err := cfg.SSL.InitDefaults(); err != nil {
			return err
		}
	}

	return cfg.Valid()
}

func (cfg *Config) Valid() error {
	if !strings.Contains(cfg.Address, ":") {
		return errors.New("malformed http server address")
	}

	if cfg.EnableTLS() {
		if err := cfg.SSL.Valid(); err != nil {
			return err
		}
	}

	return nil
}

type H2CConfig struct {
	// MaxConcurrentStreams defaults to 128.
	MaxConcurrentStreams uint `json:"max_concurrent_streams,omitempty" yaml:"max_concurrent_streams,omitempty"`
}

func (cfg *H2CConfig) InitDefaults() {
	if cfg.MaxConcurrentStreams == 0 {
		cfg.MaxConcurrentStreams = 128
	}
}

type SSLConfig struct {
	// Address to listen as HTTPS server, defaults to 0.0.0.0:443.
	Address string `json:"address,omitempty" yaml:"address,omitempty"`

	// Acme configuration
	Acme *AcmeConfig `json:"acme,omitempty" yaml:"acme,omitempty"`

	// Key defined private server key.
	Key string `json:"key,omitempty" yaml:"key,omitempty"`

	// Cert is https certificate.
	Cert string `json:"cert,omitempty" yaml:"cert,omitempty"`

	// RootCA file
	RootCA string `json:"root_ca,omitempty" yaml:"root_ca,omitempty"`

	// AuthType mTLS auth
	AuthType ClientAuthType `json:"auth_type,omitempty" yaml:"auth_type,omitempty"`
}

func (cfg *SSLConfig) InitDefaults() error {
	if cfg.Address == "" {
		cfg.Address = "0.0.0.0:443"
	}

	if cfg.EnableACME() {
		return cfg.Acme.InitDefaults()
	}

	return nil
}

func (cfg *SSLConfig) EnableACME() bool {
	return cfg.Acme != nil
}

func (cfg *SSLConfig) Enable() bool {
	return cfg.EnableACME() || cfg.Key != "" && cfg.Cert != ""
}

func (cfg *SSLConfig) Valid() error {
	if !strings.Contains(cfg.Address, ":") {
		return errors.New("malformed HTTPS server address")
	}

	// the user use they own certificates
	if !cfg.EnableACME() {
		if _, err := os.Stat(cfg.Key); err != nil {
			if os.IsNotExist(err) {
				return fmt.Errorf("HTTPS key file '%s' does not exists", cfg.Key)
			}

			return err
		}

		if _, err := os.Stat(cfg.Cert); err != nil {
			if os.IsNotExist(err) {
				return fmt.Errorf("HTTPS cert file '%s' does not exists", cfg.Cert)
			}

			return err
		}
	}

	// RootCA is optional, but if provided - check it
	if cfg.RootCA != "" {
		if _, err := os.Stat(cfg.RootCA); err != nil {
			if os.IsNotExist(err) {
				return fmt.Errorf("root ca path provided, but path '%s' does not exists", cfg.RootCA)
			}
			return err
		}
	}

	return nil
}

type AcmeConfig struct {
	// directory to save the certificates, le_certs default
	CacheDir string `json:"cache_dir" yaml:"cache_dir"`

	// User email, mandatory
	Email string `json:"email" yaml:"email"`

	// supported values: http-01, tlsalpn-01
	ChallengeType ChallengeType `json:"challenge_type" yaml:"challenge_type"`

	// The alternate port to use for the ACME HTTP challenge
	AltHTTPPort int `json:"alt_http_port" yaml:"alt_http_port"`

	// The alternate port to use for the ACME TLS-ALPN
	AltTLSALPNPort int `json:"alt_tlsalpn_port" yaml:"alt_tlsalpn_port"`

	// Use LE production endpoint or staging
	UseProductionEndpoint bool `json:"use_production_endpoint" yaml:"use_production_endpoint"`

	// Domains to obtain certificates
	Domains []string `json:"domains" yaml:"domains"`
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

	if cfg.ChallengeType == "" {
		cfg.ChallengeType = HTTP01
		if cfg.AltHTTPPort == 0 {
			cfg.AltHTTPPort = 80
		}
	}

	return nil
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
