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
	"sync"

	"github.com/notaryproject/notation-core-go/revocation"
	corecrl "github.com/notaryproject/notation-core-go/revocation/crl"
	"github.com/notaryproject/notation-go/dir"
	"github.com/notaryproject/notation-go/verifier/crl"
	"github.com/sirupsen/logrus"
)

type RevocationFactory interface {
	// NewFetcher returns a new fetcher instance
	NewFetcher() (corecrl.Fetcher, error)

	// NewValidator returns a new validator instance
	NewValidator(revocation.Options) (revocation.Validator, error)
}

// NewFetcher returns a new fetcher instance
func NewFetcher(httpClient *http.Client, cacheRoot string) (corecrl.Fetcher, error) {
	crlFetcher, err := corecrl.NewHTTPFetcher(httpClient)
	if err != nil {
		return nil, err
	}
	crlFetcher.Cache, err = newFileCache(cacheRoot)
	if err != nil {
		return nil, err
	}
	return crlFetcher, nil
}

// SupportCRL checks if the certificate supports CRL
func SupportCRL(cert *x509.Certificate) bool {
	return cert != nil && len(cert.CRLDistributionPoints) > 0
}

// cacheCRL caches the Certificate Revocation Lists (CRLs) for the given certificates using the provided CRL fetcher.
// It logs a warning if fetching the CRL fails but does not return an error to ensure the process is not blocked.
func CacheCRL(ctx context.Context, certs []*x509.Certificate, crlFetcher corecrl.Fetcher) {
	logger := logrus.WithContext(ctx)

	var wg sync.WaitGroup
	for _, cert := range certs {
		// check if the certificate supports CRL
		if !SupportCRL(cert) {
			continue
		}
		for _, crlURL := range cert.CRLDistributionPoints {
			wg.Add(1)
			go func(url string) {
				defer wg.Done()
				if _, err := crlFetcher.Fetch(ctx, url); err != nil {
					// Log error but do not return. Ensure unblock on CRL download failure
					logger.Infof("failed to download CRL from %s: %v", url, err)
				}
			}(crlURL)
		}
	}
	wg.Wait()
}

// newFileCache returns a new file cache instance
func newFileCache(root string) (*crl.FileCache, error) {
	cacheRoot, err := dir.CacheFS().SysPath(root)
	if err != nil {
		return nil, err
	}
	return crl.NewFileCache(cacheRoot)
}
