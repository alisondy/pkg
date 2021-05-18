/*
Copyright 2021 The Flux authors

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package cert

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net/http"

	corev1 "k8s.io/api/core/v1"
)

const (
	ClientCert = "certFile"
	ClientKey  = "keyFile"
	CACert     = "caFile"
)

// TlsConfigFromSecret returns a tls config created from the content of the secret.
// If the secret does not contain either a client cert and key or ca cert an
// error will be returned. If the secret contains only the cert or key an error
// will be returned.
func TlsConfigFromSecret(certSecret *corev1.Secret) (*tls.Config, error) {
	validSecret := false
	tlsConfig := &tls.Config{}

	clientCert, clientCertOk := certSecret.Data[ClientCert]
	clientKey, clientKeyOk := certSecret.Data[ClientKey]
	if clientCertOk && !clientKeyOk {
		return nil, errors.New("client certificate found, but no key")
	}
	if !clientCertOk && clientKeyOk {
		return nil, errors.New("client key found, but no certificate")
	}
	if clientCertOk && clientKeyOk {
		validSecret = true
		cert, err := tls.X509KeyPair(clientCert, clientKey)
		if err != nil {
			return nil, err
		}
		tlsConfig.Certificates = append(tlsConfig.Certificates, cert)
	}

	if caCert, ok := certSecret.Data[CACert]; ok {
		validSecret = true
		syscerts, err := x509.SystemCertPool()
		if err != nil {
			return nil, err
		}
		syscerts.AppendCertsFromPEM(caCert)
		tlsConfig.RootCAs = syscerts
	}

	if !validSecret {
		return nil, errors.New("no ca or client cert found in secret")
	}

	return tlsConfig, nil
}

// TransportFromSecret returns a http transport with a tls config created from the content of the secret.
// If the secret does not contain either a client cert and key or ca cert an
// error will be returned. If the secret contains only the cert or key an error
// will be returned.
func TransportFromSecret(certSecret *corev1.Secret) (*http.Transport, error) {
	tlsConfig, err := TlsConfigFromSecret(certSecret)
	if err != nil {
		return nil, err
	}
	return &http.Transport{TLSClientConfig: tlsConfig}, nil
}
