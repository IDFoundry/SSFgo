package main

import (
	"net/http"
	"net/http/httptest"
)

// lazyClient returns an HTTP client that trusts the certificate of a test
// server created after the client is needed.
func lazyClient(server func() *httptest.Server) *http.Client {
	return &http.Client{Transport: roundTripper(func(r *http.Request) (*http.Response, error) {
		return server().Client().Transport.RoundTrip(r)
	})}
}

type roundTripper func(*http.Request) (*http.Response, error)

func (f roundTripper) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }
