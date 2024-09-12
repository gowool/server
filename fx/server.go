package fx

import (
	"net/http"

	"go.uber.org/fx"
	"go.uber.org/zap"

	"github.com/gowool/server"
)

type ServerParams struct {
	fx.In
	Lifecycle fx.Lifecycle
	Config    server.Config
	Handler   http.Handler
	Logger    *zap.Logger
}

func NewServer(params ServerParams) (*server.Server, error) {
	srv, err := server.NewServer(params.Config, params.Handler, params.Logger)
	if err != nil {
		return nil, err
	}

	params.Lifecycle.Append(fx.StartStopHook(srv.Start, srv.Stop))

	return srv, nil
}
