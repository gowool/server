package server

import (
	"crypto/x509"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
)

func Port(address string) int {
	parts := strings.Split(address, ":")
	switch len(parts) {
	case 2:
		if port, err := strconv.Atoi(parts[1]); err == nil {
			return port
		}
	}
	return 0
}

func CreateCertPool(rootCa string) (*x509.CertPool, error) {
	rootCAs, err := x509.SystemCertPool()
	if err != nil {
		return nil, nil
	}
	if rootCAs == nil {
		rootCAs = x509.NewCertPool()
	}

	CA, err := os.ReadFile(rootCa)
	if err != nil {
		return nil, err
	}

	// should append our CA cert
	ok := rootCAs.AppendCertsFromPEM(CA)
	if !ok {
		return nil, errors.New("could not append Certs from PEM")
	}

	return rootCAs, nil
}

func tlsAddr(host string, forcePort bool, sslPort int) string {
	// remove current forcePort first
	host = strings.Split(host, ":")[0]

	if forcePort || sslPort != 443 {
		host = fmt.Sprintf("%s:%v", host, sslPort)
	}

	return host
}
