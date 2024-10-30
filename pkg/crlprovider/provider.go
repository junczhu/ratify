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

import "crypto/x509"

// CRLManager defines the interface for managing CRL operations.
type CRLManager interface {
	// FetchCRL retrieves the CRL from a given URI.
	FetchCRL(uri string) (*x509.RevocationList, error)

	// ValidateCRL validates the CRL to ensure it is correctly formatted and not expired.
	ValidateCRL(crl *x509.RevocationList) error

	// CacheCRL caches the CRL using the provided cache provider.
	CacheCRL(uri string, crl *x509.RevocationList) error

	// LoadCRLFromCache loads the CRL from cache if available.
	LoadCRLFromCache(uri string) (*x509.RevocationList, error)

	// MonitorCRLRefresh sets up the refresh schedule for the CRLs.
	MonitorCRLRefresh() error
}
