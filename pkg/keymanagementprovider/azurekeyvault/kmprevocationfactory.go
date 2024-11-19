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
	"github.com/notaryproject/notation-core-go/revocation"
	corecrl "github.com/notaryproject/notation-core-go/revocation/crl"
	nv "github.com/ratify-project/ratify/pkg/verifier/notation"
)

type RevocationFactoryImpl struct {
	EnableCache bool
	Fetcher     corecrl.Fetcher
}

// NewRevocationFactoryImpl returns a new NewRevocationFactoryImpl instance. Enable cache by default.
func NewRevocationFactoryImpl() nv.RevocationFactory {
	return &RevocationFactoryImpl{EnableCache: true}
}

// NewFetcher creates a new instance of a Fetcher if it doesn't already exist.
// If a Fetcher instance is already present, it returns the existing instance.
// The method also configures the cache for the Fetcher.
// Returns an instance of corecrl.Fetcher or an error if the Fetcher creation fails.
func (f *RevocationFactoryImpl) NewFetcher() (corecrl.Fetcher, error) {
	if f.Fetcher != nil {
		return f.Fetcher, nil
	}
	fetcher, err := f.createFetcher()
	if err != nil {
		return nil, err
	}
	f.Fetcher = fetcher
	f.configureCache()
	return fetcher, nil
}

// NewValidator is not used by Azure Key Vault case. Not implemented.
func (f *RevocationFactoryImpl) NewValidator(_ revocation.Options) (revocation.Validator, error) {
	return nil, nil
}

// createFetcher creates a new Fetcher instance using the NewRevocationFactoryImpl method
// from the nv package. It returns a Fetcher and an error if the creation fails.
func (f *RevocationFactoryImpl) createFetcher() (corecrl.Fetcher, error) {
	return nv.NewRevocationFactoryImpl().NewFetcher()
}

// configureCache disables the cache for the HTTPFetcher if caching is not enabled.
// If the EnableCache field is set to false, this method sets the Cache field of the
// HTTPFetcher to nil, effectively disabling caching for HTTP fetch operations.
func (f *RevocationFactoryImpl) configureCache() {
	if !f.EnableCache {
		if httpFetcher, ok := f.Fetcher.(*corecrl.HTTPFetcher); ok {
			httpFetcher.Cache = nil
		}
	}
}
