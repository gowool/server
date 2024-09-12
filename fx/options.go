package fx

import "go.uber.org/fx"

var OptionHTTPServer = fx.Provide(NewServer)
