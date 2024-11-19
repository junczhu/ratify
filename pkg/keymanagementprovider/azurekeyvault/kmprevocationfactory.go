/*
Copyright The Ratify Authors.
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

package azurekeyvault

import (
	"crypto/x509"

	"github.com/notaryproject/notation-core-go/revocation"
	corecrl "github.com/notaryproject/notation-core-go/revocation/crl"
	nv "github.com/ratify-project/ratify/pkg/verifier/notation"
)

type RevocationFactoryImpl struct {
	EnableCache bool
	Fetcher     corecrl.Fetcher
}

// NewRevocationFactoryImpl returns a new NewRevocationFactoryImpl instance
func NewRevocationFactoryImpl() nv.RevocationFactory {
	// Enable cache by default
	return &RevocationFactoryImpl{EnableCache: true}
}

func (f *RevocationFactoryImpl) NewFetcher() (corecrl.Fetcher, error) {
	if f.Fetcher != nil {
		return f.Fetcher, nil
	}
	fetcher, err := nv.NewRevocationFactoryImpl().NewFetcher()
	if err != nil {
		return nil, err
	}
	f.Fetcher = fetcher
	if !f.EnableCache {
		if httpFetcher, ok := f.Fetcher.(*corecrl.HTTPFetcher); ok {
			httpFetcher.Cache = nil
		}
	}
	return f.Fetcher, nil
}

// NewValidator is not used by Azure Key Vault case. Not implemented.
func (f *RevocationFactoryImpl) NewValidator(_ revocation.Options) (revocation.Validator, error) {
	return nil, nil
}

// IsSupported checks if the certificate supports CRL
func IsSupported(cert *x509.Certificate) bool {
	return cert != nil && len(cert.CRLDistributionPoints) > 0
}
