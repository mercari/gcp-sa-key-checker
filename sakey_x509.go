package main

import (
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
)

type ServiceAccountCerts map[string]*x509.Certificate

func getServiceAccountKeyCerts(sa string) (ServiceAccountCerts, error) {
	resp, err := http.Get("https://www.googleapis.com/service_accounts/v1/metadata/x509/" + sa)
	if err != nil {
		return nil, fmt.Errorf("error making request: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return nil, fmt.Errorf("error: service account not found. Does it exist and is it enabled?")
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("error: unexpected status code: %v. Check", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("error reading response body: %v", err)
	}

	var keys map[string]string
	err = json.Unmarshal(body, &keys)
	if err != nil {
		return nil, fmt.Errorf("error unmarshaling JSON: %v", err)
	}

	certs := map[string]*x509.Certificate{}
	for keyId, v := range keys {
		block, rest := pem.Decode([]byte(v))
		if block == nil {
			return nil, fmt.Errorf("error decoding PEM block")
		}
		if len(rest) > 0 {
			return nil, fmt.Errorf("error: Extra data after PEM block")
		}

		if block.Type != "CERTIFICATE" {
			return nil, fmt.Errorf("error: Unexpected PEM block type: %v. Expected CERTIFICATE", block.Type)
		}
		if len(block.Headers) > 0 {
			return nil, fmt.Errorf("error: unexpected headers in PEM block %v", block.Headers)
		}

		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("error parsing certificate: %v", err)
		}

		certs[keyId] = cert
	}

	return certs, nil
}
