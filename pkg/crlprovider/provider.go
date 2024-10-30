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

	corecrl "github.com/notaryproject/notation-core-go/revocation/crl"
)

type CRLFetcherOptions struct {
	useCache          bool
	httpClient        *http.Client
	DiscardCacheError bool // default is false
}

type CRLCacheOptions struct {
	cacheRoot string
}

// CRLProvider defines the interface for managing CRL operations.
type CRLProvider interface {
	// NewCRLFetcher creates a new CRLFetcher with the given paramters.
	NewCRLFetcher(opts CRLFetcherOptions) (*corecrl.Fetcher, error)

	// CacheCRL caches the CRL using the provided cache provider.
	NewCRLCache(opts CRLCacheOptions) (*corecrl.Cache, error)
}
