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

	nv "github.com/ratify-project/ratify/pkg/verifier/notation"
)

type RevocationFactoryImpl struct{}

// NewRevocationFactoryImpl returns a new NewRevocationFactoryImpl instance
func NewRevocationFactoryImpl() nv.RevocationFactory {
	return nv.NewRevocationFactoryImpl()
}

// IsSupported checks if the certificate supports CRL
func IsSupported(cert *x509.Certificate) bool {
	return cert != nil && len(cert.CRLDistributionPoints) > 0
}
