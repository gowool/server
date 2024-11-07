package server

import (
	"context"
	"errors"
	"net/http"
	"sync"

	"go.uber.org/zap"
)

type entryPoint interface {
	Start() error
	Stop(context.Context) error
}

type Server struct {
	entryPoints []entryPoint
	logger      *zap.Logger
	wg          sync.WaitGroup
	mu          sync.Mutex
	chErr       chan error
}

func NewServer(cfg EntryPointsConfig, handler http.Handler, logger *zap.Logger) (*Server, error) {
	if err := cfg.setDefaults(); err != nil {
		return nil, err
	}

	entryPoints := make([]entryPoint, 0, len(cfg))
	for name := range cfg {
		ep, err := NewEntryPoint(name, cfg, handler, logger)
		if err != nil {
			return nil, err
		}
		entryPoints = append(entryPoints, ep)
	}

	return &Server{
		logger:      logger,
		entryPoints: entryPoints,
		chErr:       make(chan error, len(entryPoints)),
	}, nil
}

func (s *Server) Start(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	for _, ep := range s.entryPoints {
		select {
		case <-ctx.Done():
			return nil
		default:
			s.wg.Add(1)

			go func(ep entryPoint) { s.chErr <- ep.Start() }(ep)
		}
	}

	return nil
}

func (s *Server) Stop(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	for _, ep := range s.entryPoints {
		s.wg.Add(1)

		go func(ctx context.Context, ep entryPoint) { s.chErr <- ep.Stop(ctx) }(ctx, ep)
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
				s.logger.Error("stop server", zap.Error(err))
			}
			return err
		}
	}
}
