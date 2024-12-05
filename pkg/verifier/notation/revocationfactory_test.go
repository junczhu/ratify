// Copyright The Ratify Authors.
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at

// http://www.apache.org/licenses/LICENSE-2.0

// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package notation

import (
	"context"
	"crypto/x509"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestCRLNewFetcher(t *testing.T) {
	httpClient := &http.Client{}
	cacheRoot := "/tmp/cache"

	t.Run("successful fetcher creation", func(t *testing.T) {
		fetcher, err := NewFetcher(httpClient, cacheRoot)
		assert.NoError(t, err)
		assert.NotNil(t, fetcher)
	})

	t.Run("error in creating HTTP fetcher", func(t *testing.T) {
		// Simulate error by passing nil httpClient
		fetcher, err := NewFetcher(nil, cacheRoot)
		assert.Error(t, err)
		assert.Nil(t, fetcher)
	})
}
func TestSupportCRL(t *testing.T) {
	t.Run("certificate with CRL distribution points", func(t *testing.T) {
		cert := &x509.Certificate{
			CRLDistributionPoints: []string{"http://example.com/crl"},
		}
		assert.True(t, SupportCRL(cert))
	})

	t.Run("certificate without CRL distribution points", func(t *testing.T) {
		cert := &x509.Certificate{}
		assert.False(t, SupportCRL(cert))
	})

	t.Run("nil certificate", func(t *testing.T) {
		assert.False(t, SupportCRL(nil))
	})
}
func TestCacheCRL(t *testing.T) {
	ctx := context.Background()
	httpClient := &http.Client{}
	cacheRoot := "/tmp/cache"
	fetcher, _ := NewFetcher(httpClient, cacheRoot)

	t.Run("nil fetcher", func(t *testing.T) {
		certs := []*x509.Certificate{
			{
				CRLDistributionPoints: []string{"http://example.com/crl"},
			},
		}
		CacheCRL(ctx, certs, nil)
		// Check logs if necessary
	})

	t.Run("certificate without CRL distribution points", func(t *testing.T) {
		certs := []*x509.Certificate{
			{},
		}
		CacheCRL(ctx, certs, fetcher)
		// Check logs if necessary
	})

	t.Run("valid certificates with CRL distribution points", func(t *testing.T) {
		certs := []*x509.Certificate{
			{
				CRLDistributionPoints: []string{"http://example.com/crl1"},
			},
			{
				CRLDistributionPoints: []string{"http://example.com/crl2"},
			},
		}
		CacheCRL(ctx, certs, fetcher)
		// Check logs if necessary
	})
}
