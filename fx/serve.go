package fx

import (
	"go.uber.org/fx"

	"github.com/gowool/server"
)

func Serve(srv *server.Server, lc fx.Lifecycle) {
	lc.Append(fx.StartStopHook(srv.Start, srv.Stop))
}
