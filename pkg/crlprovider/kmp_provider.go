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

package crlprovider

import (
	"net/http"
	"time"

	corecrl "github.com/notaryproject/notation-core-go/revocation/crl"
	"github.com/notaryproject/notation-go/verifier/crl"
)

type KMPCRLProvider struct {
	timeout time.Duration
}

// NewCRLFetcher creates a new CRLFetcher with the given paramters.
func (p *KMPCRLProvider) NewCRLFetcher(opts CRLFetcherOptions) (corecrl.Fetcher, error) {
	return corecrl.NewHTTPFetcher(&http.Client{Timeout: p.timeout})
}

// NewCacheCRL caches the CRL using the provided cache provider.
func (p *KMPCRLProvider) NewCRLCache(opts CRLCacheOptions) (corecrl.Cache, error) {
	return crl.NewFileCache(opts.cacheRoot)
}
