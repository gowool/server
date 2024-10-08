package server

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"net/http"
	"sync"

	"github.com/mholt/acmez/v2"
	"github.com/quic-go/quic-go/http3"
	"go.uber.org/zap"
	"golang.org/x/net/http2"
)

type HTTPS struct {
	logger  *zap.Logger
	srv     *http.Server
	quicSrv *http3.Server
	cfg     *SSLConfig
}

func NewHTTPS(cfg Config, handler http.Handler, logger *zap.Logger) (*HTTPS, error) {
	std, _ := zap.NewStdLogAt(logger.Named("server"), zap.ErrorLevel)

	tlsConfig := DefaultTLSConfig()

	if cfg.SSL.RootCA != "" {
		pool, err := CreateCertPool(cfg.SSL.RootCA)
		if err != nil {
			return nil, err
		}

		if pool != nil {
			tlsConfig.ClientCAs = pool
			// auth type used only for the CA
			switch cfg.SSL.AuthType {
			case NoClientCert:
				tlsConfig.ClientAuth = tls.NoClientCert
			case RequestClientCert:
				tlsConfig.ClientAuth = tls.RequestClientCert
			case RequireAnyClientCert:
				tlsConfig.ClientAuth = tls.RequireAnyClientCert
			case VerifyClientCertIfGiven:
				tlsConfig.ClientAuth = tls.VerifyClientCertIfGiven
			case RequireAndVerifyClientCert:
				tlsConfig.ClientAuth = tls.RequireAndVerifyClientCert
			default:
				tlsConfig.ClientAuth = tls.NoClientCert
			}
		}
	}

	if cfg.SSL.EnableACME() {
		tlsCfg, err := IssueCertificates(
			cfg.SSL.Acme.CacheDir,
			cfg.SSL.Acme.Email,
			cfg.SSL.Acme.ChallengeType,
			cfg.SSL.Acme.Domains,
			cfg.SSL.Acme.UseProductionEndpoint,
			cfg.SSL.Acme.AltHTTPPort,
			cfg.SSL.Acme.AltTLSALPNPort,
			logger,
		)
		if err != nil {
			return nil, err
		}

		tlsConfig.GetCertificate = tlsCfg.GetCertificate
		tlsConfig.NextProtos = append(tlsConfig.NextProtos, acmez.ACMETLS1Protocol)
	}

	if cfg.SSL.Key != "" && cfg.SSL.Cert != "" {
		var err error
		tlsConfig.Certificates = make([]tls.Certificate, 1)
		tlsConfig.Certificates[0], err = tls.LoadX509KeyPair(cfg.SSL.Cert, cfg.SSL.Key)
		if err != nil {
			return nil, err
		}
	}

	https := &HTTPS{
		logger: logger,
		cfg:    cfg.SSL,
		srv: &http.Server{
			Addr:              cfg.SSL.Address,
			ErrorLog:          std,
			TLSConfig:         tlsConfig,
			ReadHeaderTimeout: cfg.ReadHeaderTimeout,
			ReadTimeout:       cfg.ReadTimeout,
			WriteTimeout:      cfg.WriteTimeout,
			IdleTimeout:       cfg.IdleTimeout,
			MaxHeaderBytes:    cfg.MaxHeaderBytes,
			Handler:           handler,
		},
	}

	if cfg.SSL.H3 {
		https.quicSrv = &http3.Server{
			TLSConfig:      tlsConfig,
			Handler:        handler,
			IdleTimeout:    cfg.IdleTimeout,
			MaxHeaderBytes: cfg.MaxHeaderBytes,
		}

		https.srv.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if err := https.quicSrv.SetQUICHeaders(w.Header()); err != nil {
				logger.Error("set quic headers", zap.Error(err))
			}
			handler.ServeHTTP(w, r)
		})
	}

	if err := http2.ConfigureServer(https.srv, &http2.Server{
		MaxConcurrentStreams: uint32(cfg.H2C.MaxConcurrentStreams),
	}); err != nil {
		return nil, err
	}

	return https, nil
}

func (s *HTTPS) Start() error {
	lst, err := net.Listen("tcp", s.cfg.Address)
	if err != nil {
		return err
	}

	var udpConn *net.UDPConn
	if s.quicSrv != nil {
		udpAddr, err := net.ResolveUDPAddr("udp", s.cfg.Address)
		if err != nil {
			return err
		}
		udpConn, err = net.ListenUDP("udp", udpAddr)
		if err != nil {
			return err
		}
		defer func() {
			_ = udpConn.Close()
		}()
	}

	s.logger.Info("https server start", zap.String("address", s.cfg.Address))

	chErr := make(chan error, 2)

	var wg sync.WaitGroup

	wg.Add(1)
	go func() {
		defer wg.Done()
		chErr <- s.srv.ServeTLS(lst, s.cfg.Cert, s.cfg.Key)
	}()

	if s.quicSrv != nil {
		wg.Add(1)
		go func() {
			defer wg.Done()
			chErr <- s.quicSrv.Serve(udpConn)
		}()
	}

	go func() {
		wg.Wait()
		close(chErr)
	}()

	for err1 := range chErr {
		if err1 != nil && !errors.Is(err1, http.ErrServerClosed) {
			err = errors.Join(err, err1)
		}
	}
	return err
}

func (s *HTTPS) Stop(ctx context.Context) error {
	s.logger.Info("https server stop", zap.String("address", s.cfg.Address))

	chErr := make(chan error, 2)

	var wg sync.WaitGroup

	wg.Add(1)
	go func() {
		defer wg.Done()
		chErr <- s.srv.Shutdown(ctx)
	}()

	if s.quicSrv != nil {
		wg.Add(1)
		go func() {
			defer wg.Done()
			chErr <- s.quicSrv.Close()
		}()
	}

	go func() {
		wg.Wait()
		close(chErr)
	}()

	var err error

	for {
		select {
		case <-ctx.Done():
			return nil
		case err1, ok := <-chErr:
			if !ok {
				if err != nil {
					s.logger.Error("https shutdown", zap.Error(err))
				}
				return err
			}
			if err1 != nil && !errors.Is(err1, http.ErrServerClosed) {
				err = errors.Join(err, err1)
			}
		}
	}
}
