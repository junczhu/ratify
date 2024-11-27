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
	"net/http"
	"sync"

	"github.com/notaryproject/notation-core-go/revocation"
	corecrl "github.com/notaryproject/notation-core-go/revocation/crl"
	nv "github.com/ratify-project/ratify/pkg/verifier/notation"
)

type CRLHandler struct {
	EnableCache bool
	Fetcher     corecrl.Fetcher
	httpClient  *http.Client
}

var fetcherOnce sync.Once

// NewCRLHandler returns a new NewCRLHandler instance. Enable cache by default.
func NewCRLHandler() nv.RevocationFactory {
	return &CRLHandler{EnableCache: true, httpClient: &http.Client{}}
}

// NewFetcher creates a new instance of a Fetcher if it doesn't already exist.
// If a Fetcher instance is already present, it returns the existing instance.
// The method also configures the cache for the Fetcher.
// Returns an instance of corecrl.Fetcher or an error if the Fetcher creation fails.
func (h *CRLHandler) NewFetcher() (corecrl.Fetcher, error) {
	var err error
	fetcherOnce.Do(func() {
		if h.Fetcher == nil {
			h.Fetcher, err = h.createFetcher()
			if err == nil {
				h.configureCache()
			}
		}
	})
	if err != nil {
		return nil, err
	}
	return h.Fetcher, nil
}

// NewValidator is not used by Azure Key Vault case. Not implemented.
func (h *CRLHandler) NewValidator(_ revocation.Options) (revocation.Validator, error) {
	return nil, nil
}

// createFetcher creates a new Fetcher instance using the NewRevocationFactoryImpl method
// from the nv package. It returns a Fetcher or an error if the creation fails.
func (h *CRLHandler) createFetcher() (corecrl.Fetcher, error) {
	return nv.NewFetcher(h.httpClient, "")
}

// configureCache disables the cache for the HTTPFetcher if caching is not enabled.
// If the EnableCache field is set to false, this method sets the Cache field of the
// HTTPFetcher to nil, effectively disabling caching for HTTP fetch operations.
func (h *CRLHandler) configureCache() {
	if !h.EnableCache {
		if httpFetcher, ok := h.Fetcher.(*corecrl.HTTPFetcher); ok {
			httpFetcher.Cache = nil
		}
	}
}
