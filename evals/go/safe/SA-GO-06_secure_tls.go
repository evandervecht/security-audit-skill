package main

// SA-GO-06: Proper TLS configuration with certificate validation
import (
	"crypto/tls"
	"net/http"
)

func createClient() *http.Client {
	return &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				MinVersion: tls.VersionTLS12,
			},
		},
	}
}
