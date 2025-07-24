package server

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"

	"github.com/caddyserver/certmagic"
	"github.com/quic-go/quic-go/http3"
	"go.uber.org/zap"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/h2c"
)

type EntryPoint struct {
	logger *zap.Logger
	http2  *http.Server
	http3  *http3.Server
	cancel context.CancelFunc
}

func NewEntryPoint(name string, cfg EntryPointsConfig, handler http.Handler, logger *zap.Logger) (*EntryPoint, error) {
	if err := cfg.setDefaults(); err != nil {
		return nil, err
	}

	l := logger.Named(name)
	std, _ := zap.NewStdLogAt(l.Named("std"), logger.Level())

	epCfg, ok := cfg[name]
	if !ok {
		return nil, fmt.Errorf("entry point config `%s` not found", name)
	}

	if epCfg.HTTP.Redirection != nil {
		handler = redirectionHandler(epCfg.HTTP.Redirection, cfg)
	}

	tlsCfg := epCfg.HTTP.TLS
	if tlsCfg == nil {
		for key, value := range cfg {
			if key == name || value.HTTP.TLS == nil || value.HTTP.TLS.Acme == nil {
				continue
			}

			if value.HTTP.TLS.Acme.HTTPChallenge == nil || value.HTTP.TLS.Acme.HTTPChallenge.EntryPoint != name {
				continue
			}

			config := value.HTTP.TLS.Acme.Config(key, cfg, logger)
			handler = config.Issuers[len(config.Issuers)-1].(*certmagic.ACMEIssuer).HTTPChallengeHandler(handler)
			break
		}
	}

	h2s := &http2.Server{MaxConcurrentStreams: uint32(epCfg.HTTP2.MaxConcurrentStreams)}
	h2Handler := h2c.NewHandler(handler, h2s)

	transport := epCfg.Transport

	ctx, cancel := context.WithCancel(context.Background())

	ep := &EntryPoint{
		logger: l,
		cancel: cancel,
		http2: &http.Server{
			Addr:              epCfg.Address,
			ErrorLog:          std,
			ReadHeaderTimeout: transport.ReadHeaderTimeout,
			ReadTimeout:       transport.ReadTimeout,
			WriteTimeout:      transport.WriteTimeout,
			IdleTimeout:       transport.IdleTimeout,
			MaxHeaderBytes:    transport.MaxHeaderBytes,
			Handler:           h2Handler,
			BaseContext: func(net.Listener) context.Context {
				return ctx
			},
		},
	}

	if tlsCfg == nil {
		return ep, nil
	}

	var err error

	ep.http2.TLSConfig = DefaultTLSConfig()
	ep.http2.TLSConfig.InsecureSkipVerify = tlsCfg.InsecureSkipVerify
	ep.http2.TLSConfig.Certificates = make([]tls.Certificate, len(tlsCfg.Certificates))
	for i, cert := range tlsCfg.Certificates {
		if ep.http2.TLSConfig.Certificates[i], err = cert.Certificate(); err != nil {
			return nil, err
		}
	}

	if tlsCfg.ClientAuth != nil {
		ep.http2.TLSConfig.ClientAuth = tlsCfg.ClientAuth.ClientAuthType.TLSClientAuth()
		if ep.http2.TLSConfig.ClientCAs, err = tlsCfg.ClientAuth.CertPool(); err != nil {
			return nil, err
		}
	}

	if tlsCfg.Acme != nil {
		config := tlsCfg.Acme.Config(name, cfg, l)

		for i := 0; i < len(tlsCfg.Acme.Domains); i++ {
			if err = config.ObtainCertAsync(context.Background(), tlsCfg.Acme.Domains[i]); err != nil {
				return nil, err
			}
		}

		if err = config.ManageSync(context.Background(), tlsCfg.Acme.Domains); err != nil {
			return nil, err
		}

		acmeTLSCfg := config.TLSConfig()
		ep.http2.TLSConfig.GetCertificate = acmeTLSCfg.GetCertificate
		ep.http2.TLSConfig.NextProtos = append(ep.http2.TLSConfig.NextProtos, acmeTLSCfg.NextProtos...)
	}

	if epCfg.HTTP3 != nil {
		addr := ""
		port := int(epCfg.HTTP3.AdvertisedPort)
		if port == 0 {
			port = Port(epCfg.Address)
		}
		if index := strings.Index(epCfg.Address, ":"); index > 0 {
			addr = epCfg.Address[:index]
		}

		ep.http3 = &http3.Server{
			TLSConfig:      http3.ConfigureTLSConfig(ep.http2.TLSConfig),
			Addr:           fmt.Sprintf("%s:%d", addr, port),
			Port:           port,
			Handler:        handler,
			IdleTimeout:    transport.IdleTimeout,
			MaxHeaderBytes: transport.MaxHeaderBytes,
		}

		ep.http2.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.ProtoMajor < 3 {
				if err := ep.http3.SetQUICHeaders(w.Header()); err != nil {
					ep.logger.Error("set quic headers", zap.Error(err))
				}
			}
			h2Handler.ServeHTTP(w, r)
		})
	}

	return ep, nil
}

func (ep *EntryPoint) Start() error {
	chErr := make(chan error, 2)

	var wg sync.WaitGroup

	wg.Add(1)
	go func(srv *http.Server, logger *zap.Logger) {
		defer wg.Done()

		logger.Info("start http entry point", zap.String("address", srv.Addr))

		if srv.TLSConfig == nil {
			chErr <- srv.ListenAndServe()
		} else {
			chErr <- srv.ListenAndServeTLS("", "")
		}
	}(ep.http2, ep.logger)

	if ep.http3 != nil {
		wg.Add(1)
		go func(srv *http3.Server, logger *zap.Logger) {
			defer wg.Done()

			logger.Info("start http3 entry point", zap.String("address", srv.Addr))

			chErr <- srv.ListenAndServe()
		}(ep.http3, ep.logger)
	}

	go func() {
		wg.Wait()
		close(chErr)
	}()

	var err error
	for err1 := range chErr {
		if err1 != nil && !errors.Is(err1, http.ErrServerClosed) {
			err = errors.Join(err, err1)
		}
	}
	return err
}

func (ep *EntryPoint) Stop(ctx context.Context) error {
	chErr := make(chan error, 2)

	var wg sync.WaitGroup

	if ep.http3 != nil {
		wg.Add(1)
		go func(srv *http3.Server, logger *zap.Logger) {
			defer wg.Done()

			logger.Info("stop http3 entry point", zap.String("address", srv.Addr))

			chErr <- srv.Close()
		}(ep.http3, ep.logger)
	}

	wg.Add(1)
	go func(srv *http.Server, logger *zap.Logger) {
		defer wg.Done()

		logger.Info("stop http entry point", zap.String("address", srv.Addr))

		chErr <- srv.Shutdown(ctx)
	}(ep.http2, ep.logger)

	go func() {
		wg.Wait()
		close(chErr)
	}()

	ep.cancel()

	var err error

	for {
		select {
		case <-ctx.Done():
			return nil
		case err1, ok := <-chErr:
			if !ok {
				if err != nil {
					ep.logger.Error("entry point shutdown", zap.Error(err))
				}
				return err
			}
			if err1 != nil && !errors.Is(err1, http.ErrServerClosed) {
				err = errors.Join(err, err1)
			}
		}
	}
}

func redirectionHandler(cfg *RedirectionConfig, mCfg EntryPointsConfig) http.Handler {
	scheme := "https"
	if cfg.EntryPoint.Scheme != "" {
		scheme = cfg.EntryPoint.Scheme
	}

	toPort := 443
	if cfg.EntryPoint.To != "" {
		if to, ok := mCfg[cfg.EntryPoint.To]; ok {
			toPort = Port(to.Address)
		} else {
			toPort = Port(cfg.EntryPoint.To)
		}
	}

	status := http.StatusTemporaryRedirect
	if cfg.EntryPoint.Permanent {
		status = http.StatusPermanentRedirect
	}

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Add("Strict-Transport-Security", "max-age=31536000; includeSubDomains; preload")
		target := &url.URL{
			Scheme:   scheme,
			Host:     tlsAddr(r.Host, false, toPort),
			Path:     r.URL.Path,
			RawQuery: r.URL.RawQuery,
		}

		http.Redirect(w, r, target.String(), status)
	})
}
