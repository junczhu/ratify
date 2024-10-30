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

package cache

import (
	corecrl "github.com/notaryproject/notation-core-go/revocation/crl"
)

// CRLCacheProvider defines the interface for a CRL cache provider.
type CRLCacheProvider interface {
	// Get returns the CRL bundle associated with the given URI, if available.
	Get(uri string) (*corecrl.Bundle, error)

	// Set caches the given CRL bundle for the specified URI.
	Set(uri string, bundle *corecrl.Bundle) error

	// Delete removes the CRL bundle associated with the given URI.
	Delete(uri string) error

	// Refresh updates the CRL bundle for the specified URI.
	Refresh(uri string) (*corecrl.Bundle, error)

	// ListURIs lists all URIs currently cached.
	ListURIs() ([]string, error)
}
