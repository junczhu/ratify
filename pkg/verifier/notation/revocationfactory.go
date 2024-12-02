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

// RevocationFactory is an interface that defines methods for creating instances
// related to revocation. It provides methods to create a new fetcher and a new
// validator.
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
func CacheCRL(ctx context.Context, certs []*x509.Certificate, fetcher corecrl.Fetcher) {
	logger := logrus.WithContext(ctx)
	if fetcher == nil {
		logger.Warn("CRL fetcher is nil")
		return
	}
	var wg sync.WaitGroup
	for _, cert := range certs {
		cacheCertificateCRL(ctx, cert, fetcher, &wg, logger)
	}
	wg.Wait()
}

func cacheCertificateCRL(ctx context.Context, cert *x509.Certificate, crlFetcher corecrl.Fetcher, wg *sync.WaitGroup, logger *logrus.Entry) {
	if !SupportCRL(cert) {
		return
	}
	for _, crlURL := range cert.CRLDistributionPoints {
		crlURL := crlURL // capture loop variable
		wg.Add(1)
		go fetchCRL(ctx, cert, crlURL, crlFetcher, wg, logger)
	}
}

func fetchCRL(ctx context.Context, cert *x509.Certificate, url string, crlFetcher corecrl.Fetcher, wg *sync.WaitGroup, logger *logrus.Entry) {
	defer wg.Done()
	if _, err := crlFetcher.Fetch(ctx, url); err != nil {
		logger.Infof("failed to download CRL from %s for certificate %s : %v", url, cert.Subject.CommonName, err)
	}
}

// newFileCache returns a new file cache instance
func newFileCache(root string) (*crl.FileCache, error) {
	cacheRoot, err := dir.CacheFS().SysPath(root)
	if err != nil {
		return nil, err
	}
	return crl.NewFileCache(cacheRoot)
}
