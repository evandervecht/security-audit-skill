package main

// SA-GO-06: TLS certificate verification disabled
import (
	"crypto/tls"
	"net/http"
)

func createClient() *http.Client {
	return &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
			},
		},
	}
}
