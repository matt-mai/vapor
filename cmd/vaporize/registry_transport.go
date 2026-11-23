package main

import (
	"errors"
	"net/http"

	"github.com/google/go-containerregistry/pkg/v1/remote"
)

var registryTransport = remote.DefaultTransport

type registryHTTPS struct{ upstream http.RoundTripper }

func (transport registryHTTPS) RoundTrip(request *http.Request) (*http.Response, error) {
	// The registry client makes its own HTTP clients for pings and authentication.
	if request.URL.Scheme != "https" {
		return nil, errors.New("registry requests require HTTPS")
	}
	return transport.upstream.RoundTrip(request)
}
