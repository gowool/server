package fx

import (
	"go.uber.org/fx"

	"github.com/gowool/server"
)

var OptionHTTPServer = fx.Provide(server.NewServer)
