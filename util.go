package server

import (
	"fmt"
	"strconv"
	"strings"
)

func Port(address string) int {
	if index := strings.Index(address, ":"); index >= 0 {
		address = address[index+1:]
	}
	if port, err := strconv.Atoi(address); err == nil {
		return port
	}
	return 0
}

func tlsAddr(host string, forcePort bool, sslPort int) string {
	// remove current forcePort first
	host = strings.Split(host, ":")[0]

	if forcePort || sslPort != 443 {
		host = fmt.Sprintf("%s:%v", host, sslPort)
	}

	return host
}
