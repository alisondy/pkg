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
	"testing"

	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
)

func TestCert_TlsConfigAll(t *testing.T) {
	secret := &corev1.Secret{
		Data: map[string][]byte{
			CACert:     ExampleCA,
			ClientCert: ExampleCert,
			ClientKey:  ExampleKey,
		},
	}
	tlsConfig, err := TlsConfigFromSecret(secret)
	require.NoError(t, err)
	cert, err := tls.X509KeyPair(ExampleCert, ExampleKey)
	require.NoError(t, err)
	require.Equal(t, tlsConfig.Certificates[0], cert)
}

func TestCert_TlsConfigNone(t *testing.T) {
	secret := &corev1.Secret{
		Data: map[string][]byte{},
	}
	tlsConfig, err := TlsConfigFromSecret(secret)
	require.EqualError(t, err, "no ca or client cert found in secret")
	require.Nil(t, tlsConfig)
}

func TestCert_TlsConfigOnlyCa(t *testing.T) {
	secret := &corev1.Secret{
		Data: map[string][]byte{
			CACert: ExampleCA,
		},
	}
	tlsConfig, err := TlsConfigFromSecret(secret)
	require.NoError(t, err)
	require.NotNil(t, tlsConfig)
}

func TestCert_TlsConfigOnlyClient(t *testing.T) {
	secret := &corev1.Secret{
		Data: map[string][]byte{
			ClientCert: ExampleCert,
			ClientKey:  ExampleKey,
		},
	}
	tlsConfig, err := TlsConfigFromSecret(secret)
	require.NoError(t, err)
	require.NotNil(t, tlsConfig)
}

func TestCert_TlsConfigMissingKey(t *testing.T) {
	secret := &corev1.Secret{
		Data: map[string][]byte{
			CACert:     ExampleCA,
			ClientCert: ExampleCert,
		},
	}
	tlsConfig, err := TlsConfigFromSecret(secret)
	require.EqualError(t, err, "client certificate found, but no key")
	require.Nil(t, tlsConfig)
}

func TestCert_TlsConfigMissingCert(t *testing.T) {
	secret := &corev1.Secret{
		Data: map[string][]byte{
			CACert:    ExampleCA,
			ClientKey: ExampleKey,
		},
	}
	tlsConfig, err := TlsConfigFromSecret(secret)
	require.EqualError(t, err, "client key found, but no certificate")
	require.Nil(t, tlsConfig)
}

func TestCert_Transport(t *testing.T) {
	secret := &corev1.Secret{
		Data: map[string][]byte{
			CACert:     ExampleCA,
			ClientCert: ExampleCert,
			ClientKey:  ExampleKey,
		},
	}
	transport, err := TransportFromSecret(secret)
	require.NoError(t, err)
	require.NotNil(t, transport.TLSClientConfig)
}
