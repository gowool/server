package server

import (
	"context"
	"errors"
	"net/http"
	"slices"
	"sync"

	"go.uber.org/zap"
)

type server interface {
	Start() error
	Stop(context.Context) error
}

type Server struct {
	servers []server
	logger  *zap.Logger
	wg      sync.WaitGroup
	mu      sync.Mutex
	chErr   chan error
}

func NewServer(cfg Config, handler http.Handler, logger *zap.Logger) (*Server, error) {
	servers := make([]server, 0, 2)
	servers = append(servers, NewHTTP(cfg, handler, logger))

	if cfg.EnableTLS() {
		https, err := NewHTTPS(cfg, handler, logger)
		if err != nil {
			return nil, err
		}
		servers = append(servers, https)
	}

	return &Server{
		logger:  logger,
		servers: slices.Clip(servers),
		chErr:   make(chan error, len(servers)),
	}, nil
}

func (s *Server) Start(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	for _, srv := range s.servers {
		select {
		case <-ctx.Done():
			return nil
		default:
			s.wg.Add(1)

			go func(srv server) { s.chErr <- srv.Start() }(srv)
		}
	}

	return nil
}

func (s *Server) Stop(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	for _, srv := range s.servers {
		s.wg.Add(1)

		go func(ctx context.Context, srv server) { s.chErr <- srv.Stop(ctx) }(ctx, srv)
	}

	done := make(chan struct{}, 1)
	defer close(done)

	go func() {
		s.wg.Wait()

		done <- struct{}{}
	}()

	var err error
	for {
		select {
		case <-ctx.Done():
			return nil
		case e := <-s.chErr:
			err = errors.Join(err, e)
			s.wg.Done()
		case <-done:
			if err != nil {
				s.logger.Error("error on stop http server", zap.Error(err))
			}
			return err
		}
	}
}
