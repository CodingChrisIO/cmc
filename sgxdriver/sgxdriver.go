// Copyright (c) 2021 Fraunhofer AISEC
// Fraunhofer-Gesellschaft zur Foerderung der angewandten Forschung e.V.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package sgxdriver

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"

	ar "github.com/Fraunhofer-AISEC/cmc/attestationreport"
	est "github.com/Fraunhofer-AISEC/cmc/est/estclient"
	"github.com/Fraunhofer-AISEC/cmc/internal"
	"github.com/edgelesssys/ego/enclave"
	"github.com/sirupsen/logrus"

	_ "github.com/mattn/go-sqlite3"
)

var log = logrus.WithField("service", "sgxdriver")

const (
	// TODO: use environment variables or specify the paths inside the config file
	PCK_CACHE_DB_PATH = "/opt/intel/sgx-dcap-pccs/pckcache.db"
)

// Sgx is a structure required for implementing the Measure method
// of the attestation report Measurer interface
type Sgx struct {
	sgxCertChain     []*x509.Certificate
	signingCertChain []*x509.Certificate
	priv             crypto.PrivateKey
}

// Init initializes the SGX driver with the specifified configuration
func (sgx *Sgx) Init(c *ar.DriverConfig) error {

	// Initial checks
	if sgx == nil {
		return errors.New("internal error: SNP object is nil")
	}

	// Create storage folder for storage of internal data if not existing
	if c.StoragePath != "" {
		if _, err := os.Stat(c.StoragePath); err != nil {
			if err := os.MkdirAll(c.StoragePath, 0755); err != nil {
				return fmt.Errorf("failed to create directory for internal data '%v': %w",
					c.StoragePath, err)
			}
		}
	}

	// Create new private key for signing
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return fmt.Errorf("failed to generate private key: %w", err)
	}
	sgx.priv = priv

	// Create IK CSR and fetch new certificate including its chain from EST server
	sgx.signingCertChain, err = getSigningCertChain(priv, c.Serializer, c.Metadata,
		c.ServerAddr)
	if err != nil {
		return fmt.Errorf("failed to get signing cert chain: %w", err)
	}

	// Fetch SGX certificate chain
	sgx.sgxCertChain, err = getSgxCertChain()
	if err != nil {
		return fmt.Errorf("failed to get SGX cert chain: %w", err)
	}
	log.Traceln("sgxCertChain: ", sgx.sgxCertChain)

	return nil
}

// Measure implements the attestation reports generic Measure interface to be called
// as a plugin during attestation report generation
func (sgx *Sgx) Measure(nonce []byte) (ar.Measurement, error) {

	if sgx == nil {
		return ar.SgxMeasurement{}, errors.New("internal error: SGX object is nil")
	}

	data, err := enclave.GetRemoteReport(nonce)
	if err != nil {
		return ar.SgxMeasurement{}, fmt.Errorf("failed to get SGX Measurement: %w", err)
	}

	measurement := ar.SgxMeasurement{
		Type:   "SGX Measurement",
		Report: data[16:],
		Certs:  internal.WriteCertsDer(sgx.sgxCertChain),
	}

	return measurement, nil
}

// Lock implements the locking method for the attestation report signer interface
func (sgx *Sgx) Lock() error {
	// No locking mechanism required for software key
	return nil
}

// Lock implements the unlocking method for the attestation report signer interface
func (sgx *Sgx) Unlock() error {
	// No unlocking mechanism required for software key
	return nil
}

// GetSigningKeys returns the TLS private and public key as a generic crypto interface
func (sgx *Sgx) GetSigningKeys() (crypto.PrivateKey, crypto.PublicKey, error) {
	if sgx == nil {
		return nil, nil, errors.New("internal error: SW object is nil")
	}
	return sgx.priv, &sgx.priv.(*ecdsa.PrivateKey).PublicKey, nil
}

func (sgx *Sgx) GetCertChain() ([]*x509.Certificate, error) {
	if sgx == nil {
		return nil, errors.New("internal error: SW object is nil")
	}
	log.Tracef("Returning %v certificates", len(sgx.signingCertChain))
	return sgx.signingCertChain, nil
}

func getSigningCertChain(priv crypto.PrivateKey, s ar.Serializer, metadata [][]byte,
	addr string,
) ([]*x509.Certificate, error) {

	csr, err := ar.CreateCsr(priv, s, metadata)
	if err != nil {
		return nil, fmt.Errorf("failed to create CSRs: %w", err)
	}

	// Get CA certificates and enroll newly created CSR
	// TODO provision EST server certificate with a different mechanism,
	// otherwise this step has to happen in a secure environment. Allow
	// different CAs for metadata and the EST server authentication
	log.Warn("Creating new EST client without server authentication")
	client := est.NewClient(nil)

	log.Info("Retrieving CA certs")
	caCerts, err := client.CaCerts(addr)
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve certs: %w", err)
	}
	log.Debug("Received certs:")
	for _, c := range caCerts {
		log.Debugf("\t%v", c.Subject.CommonName)
	}
	if len(caCerts) == 0 {
		return nil, fmt.Errorf("no certs provided")
	}

	log.Warn("Setting retrieved cert for future authentication")
	err = client.SetCAs([]*x509.Certificate{caCerts[len(caCerts)-1]})
	if err != nil {
		return nil, fmt.Errorf("failed to set EST CA: %w", err)
	}

	cert, err := client.SimpleEnroll(addr, csr)
	if err != nil {
		return nil, fmt.Errorf("failed to enroll cert: %w", err)
	}

	return append([]*x509.Certificate{cert}, caCerts...), nil
}

// PCK Certificate Chain + TCB Signing Cert
func getSgxCertChain() ([]*x509.Certificate, error) {
	certificates := []*x509.Certificate{}

	// Parameters
	// TODO: Should be defined in config
	encrypted_ppid := "330c6134e27d3441edffca24b5b050f84fb6799a1d0b4db8d1a199081d2a26f449d47b303fe93c33ac92cbbe9d1d3faec8132672577d328b8c6b3f1b424a73f1a9543bc4074368d35dc8549aa90483900b669a935b432fac409d88083749fceee762ba96b716020cd4c7413590ef418e88f18e419342f5f60dc6cdc9424317f4637088b6d7d826ad60590dc3b4ce7258fec8e399dbde0e2b92ff9c4e585c85f8d64a43be38edddadf473e0016e5072a284c315923b419f2b22c5a5acf83e0aeca3842aaa45cb49afa8499d9b42f0bd71141818e0883093d9e82ec5263765448a87a8c09bbb3d3a1e2d498502eeab84bf22f795c3a08ad4856b198f69d990ddcfd766dc992608d8af39e3e4cd4e711ce937dc13501a75b2a71829987e815652c2dfeec6bdc693aebb9626f4c55828fd1b82fcccad7863d2cfa778aee99577b301a2caac5844d3dea085c08d413798344e4d86d15515d21cea2fa9698deef67a3d19f7d8ab01d85c6e12a3d76996535716395b5a168ecd75a3eee63f32389ebb15"
	cpusvn := "07080000000000000000000000000000"
	pceid := "0000"
	pcesvn := "0f00"
	fmspc := "00706a100000"

	tcbInfoUrl := fmt.Sprintf("https://api.trustedservices.intel.com/sgx/certification/v4/tcb?fmspc=%s", fmspc)
	apiUrl := fmt.Sprintf("https://api.trustedservices.intel.com/sgx/certification/v4/pckcert?encrypted_ppid=%s&cpusvn=%s&pceid=%s&pcesvn=%s", encrypted_ppid, cpusvn, pceid, pcesvn)

	// 1. GET PCK Certificate and Certificte Chain
	req, err := http.NewRequest("GET", apiUrl, nil)
	if err != nil {
		return certificates, fmt.Errorf("error creating request: %v", err)

	}

	// Perform the request (ego has no access to root certificates in enclave, untrusted)
	tlsConfig := &tls.Config{InsecureSkipVerify: true}
	client := http.Client{Transport: &http.Transport{TLSClientConfig: tlsConfig}}
	resp, err := client.Do(req)
	if err != nil {
		return certificates, fmt.Errorf("error performing request: %v", err)
	}

	// Extract and print TCB-Info-Issuer-Chain from the header
	sgxPckIssuerChain := resp.Header.Get("SGX-PCK-Certificate-Issuer-Chain")

	// Decode URL-encoded string
	decoded, err := url.QueryUnescape(sgxPckIssuerChain)
	if err != nil {
		return certificates, fmt.Errorf("error decoding URL-encoded string: %v", err)
	}

	// Split the PEM certificates
	certs := strings.SplitAfter(decoded, "-----END CERTIFICATE-----\n")
	for _, certPEM := range certs {
		if certPEM != "" {

			// Decode the PEM block
			block, _ := pem.Decode([]byte(certPEM))
			if block == nil {
				return certificates, fmt.Errorf("error decoding PCK cert chain PEM block")
			}

			// Parse the certificate
			cert, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				return certificates, fmt.Errorf("error parsing certificate: %v", err)
			}

			certificates = append(certificates, cert)
		}
	}

	// Read the response body
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return certificates, fmt.Errorf("error reading response body: %v", err)
	}

	// Decode the PEM block
	block, _ := pem.Decode([]byte(body))
	if block == nil {
		return certificates, fmt.Errorf("error decoding PCK cert PEM block")
	}

	// Parse the certificate
	pckCert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return certificates, fmt.Errorf("error parsing certificate: %v", err)

	}
	certificates = append(certificates, pckCert)
	resp.Body.Close()

	// 2. GET TCB Signing Certificate
	req, err = http.NewRequest("GET", tcbInfoUrl, nil)
	if err != nil {
		return certificates, fmt.Errorf("error creating request: %v", err)
	}

	// Perform the request
	resp, err = client.Do(req)
	if err != nil {
		return certificates, fmt.Errorf("error performing request: %v", err)
	}

	// Extract and print TCB-Info-Issuer-Chain from the header
	tcbInfoIssuerChain := resp.Header.Get("TCB-Info-Issuer-Chain")

	// Decode URL-encoded string
	decoded, err = url.QueryUnescape(tcbInfoIssuerChain)
	if err != nil {
		return certificates, fmt.Errorf("error decoding URL-encoded string: %v", err)
	}

	// Split the PEM certificates
	certs = strings.SplitAfter(decoded, "-----END CERTIFICATE-----\n")
	certPEM := certs[0]
	if certPEM != "" {
		// Decode the PEM block
		block, _ := pem.Decode([]byte(certPEM))
		if block == nil {
			return certificates, fmt.Errorf("error decoding TCB Signing Cert PEM block")
		}

		// Parse the certificate
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return certificates, fmt.Errorf("error parsing certificate: %v", err)
		}

		certificates = append(certificates, cert)
	}

	resp.Body.Close()

	return certificates, nil
}
