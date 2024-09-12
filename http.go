package server

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/url"
	"time"

	"go.uber.org/zap"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/h2c"
)

type HTTP struct {
	logger  *zap.Logger
	srv     *http.Server
	address string
}

func NewHTTP(cfg Config, handler http.Handler, logger *zap.Logger) *HTTP {
	if cfg.Redirect && cfg.EnableTLS() {
		handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Add("Strict-Transport-Security", "max-age=31536000; includeSubDomains; preload")
			target := &url.URL{
				Scheme:   "https",
				Host:     tlsAddr(r.Host, false, Port(cfg.SSL.Address)),
				Path:     r.URL.Path,
				RawQuery: r.URL.RawQuery,
			}

			http.Redirect(w, r, target.String(), http.StatusPermanentRedirect)
		})
	}

	std, _ := zap.NewStdLogAt(logger.Named("server"), zap.ErrorLevel)

	return &HTTP{
		logger:  logger,
		address: cfg.Address,
		srv: &http.Server{
			ReadHeaderTimeout: time.Minute,
			ReadTimeout:       time.Minute,
			WriteTimeout:      time.Minute,
			ErrorLog:          std,
			Handler: h2c.NewHandler(handler, &http2.Server{
				MaxConcurrentStreams:         uint32(cfg.H2C.MaxConcurrentStreams),
				PermitProhibitedCipherSuites: false,
			}),
		},
	}
}

func (s *HTTP) Start() error {
	lst, err := net.Listen("tcp", s.address)
	if err != nil {
		return err
	}

	s.logger.Info("http server start", zap.String("address", s.address))

	if err = s.srv.Serve(lst); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}

	return nil
}

func (s *HTTP) Stop(ctx context.Context) error {
	s.logger.Info("http server stop", zap.String("address", s.address))

	if err := s.srv.Shutdown(ctx); err != nil && !errors.Is(err, http.ErrServerClosed) {
		s.logger.Error("http shutdown", zap.Error(err))
		return err
	}
	return nil
}
