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

package attestationreport

import (
	"crypto/x509"
	"fmt"
	"math/big"
	"strings"
	"time"

	"github.com/Fraunhofer-AISEC/cmc/internal"
)

// VerificationResult represents the results of all steps taken during
// the validation of an attestation report.
type VerificationResult struct {
	Type            string              `json:"type"`
	Success         bool                `json:"raSuccessful"`
	ErrorCode       ErrorCode           `json:"errorCode,omitempty"` // Set in case of global errors
	Prover          string              `json:"prover,omitempty"`    // Name of the proving device the report was created for
	Created         string              `json:"created,omitempty"`   // Timestamp the attestation verification was completed
	SwCertLevel     int                 `json:"swCertLevel"`         // Overall certification level for the software stack
	FreshnessCheck  Result              `json:"freshnessCheck"`      // Result for comparison of the expected nonce to the one provided in the attestation report
	Measurements    []MeasurementResult `json:"measurements"`
	ReportSignature []SignatureResult   `json:"reportSignatureCheck"` // Result for validation of the overall report signature
	MetadataResult
	PolicySuccess bool `json:"policySuccess,omitempty"` // Result of custom policy validation (if utilized)
}

type MetadataResult struct {
	CompDescResult *CompDescResult  `json:"companyValidation,omitempty"`
	RtmResult      ManifestResult   `json:"rtmValidation"`
	OsResult       ManifestResult   `json:"osValidation"`
	AppResults     []ManifestResult `json:"appValidation,omitempty"`
	DevDescResult  DevDescResult    `json:"deviceDescValidation"`
}

// CompDescResult represents the results of the validation of the
// Company Description and its mapping to the used device certificate.
type CompDescResult struct {
	MetaInfo
	CompCertLevel  int               `json:"compCertLevel"`       // Certification level for the company operating the device
	Summary        Result            `json:"result"`              // Summarizing value illustrating whether any issues were detected during validation of the Company Description
	SignatureCheck []SignatureResult `json:"signatureValidation"` // Results for validation of the Description Signatures and the used certificates
	ValidityCheck  Result            `json:"validityCheck"`       // Result from checking the validity of the description
}

// ManifestResult represents the results of the validation of a
// manifest provided in the Attestation Report.
type ManifestResult struct {
	MetaInfo
	Summary        Result            `json:"result"`
	SignatureCheck []SignatureResult `json:"signatureValidation"`
	ValidityCheck  Result            `json:"validityCheck"`
	Details        any               `json:"details,omitempty"`
}

// DevDescResult represents the results of the validation of the
// Device Description in the Attestation Report.
type DevDescResult struct {
	MetaInfo
	Description         string            `json:"description"`
	Location            string            `json:"location"`
	Summary             Result            `json:"result"`
	CorrectRtm          Result            `json:"correctRtm"`
	CorrectOs           Result            `json:"correctOs"`
	CorrectApps         []Result          `json:"correctApps"`
	RtmOsCompatibility  Result            `json:"rtmOsCompatibility"`
	OsAppsCompatibility []Result          `json:"osAppCompatibility"`
	SignatureCheck      []SignatureResult `json:"signatureValidation"`
}

type MeasurementResult struct {
	Type      string          `json:"type"`
	Summary   Result          `json:"summary"`
	Freshness Result          `json:"freshness"`
	Signature SignatureResult `json:"signature"`
	Artifacts []DigestResult  `json:"artifacts"`
	TpmResult *TpmResult      `json:"tpmResult,omitempty"`
	SnpResult *SnpResult      `json:"snpResult,omitempty"`
	SgxResult *SgxResult      `json:"sgxResult,omitempty"`
	TdxResult *TdxResult      `json:"tdxResult,omitempty"`
	SwResult  *SwResult       `json:"swResult,omitempty"`
}

type TpmResult struct {
	PcrMatch         []PcrResult `json:"pcrMatch"`
	AggPcrQuoteMatch Result      `json:"aggPcrQuoteMatch"`
}

type SnpResult struct {
	VersionMatch Result       `json:"reportVersionMatch"`
	FwCheck      VersionCheck `json:"fwCheck"`
	TcbCheck     TcbCheck     `json:"tcbCheck"`
	PolicyCheck  PolicyCheck  `json:"policyCheck"`
}

type SgxResult struct {
	VersionMatch       Result             `json:"reportVersionMatch"`
	TcbInfoCheck       TcbLevelResult     `json:"tcbInfoCheck"`
	QeIdentityCheck    TcbLevelResult     `json:"qeIdentityCheck"`
	SgxAttributesCheck SgxAttributesCheck `json:"sgxAttributesCheck"`
}

type TdxResult struct {
	VersionMatch        Result            `json:"reportVersionMatch"`
	TcbInfoCheck        TcbLevelResult    `json:"tcbInfoCheck"`
	QeIdentityCheck     TcbLevelResult    `json:"qeIdentityCheck"`
	TdAttributesCheck   TdAttributesCheck `json:"tdAttributesCheck"`
	SeamAttributesCheck AttributesCheck   `json:"seamAttributesCheck"`
	XfamCheck           AttributesCheck   `json:"xfamCheck"`
}

type SwResult struct {
	MeasName string `json:"measurementName"`    // Name associated with the measurement used for validation
	VerName  string `json:"referenceValueName"` // Name of the reference value information used for validation
}

// PcrResult represents the results for the recalculation of a specific PCR.
type PcrResult struct {
	Pcr        int    `json:"pcr"`                  // Number for the PCR which was validated
	Calculated string `json:"calculated,omitempty"` // PCR Digest that was recalculated
	Measured   string `json:"measured,omitempty"`   // PCR Digest from the measurement
	Success    bool   `json:"success"`
}

// DigestResult represents a generic result for a digest that was processed
// during attestation
type DigestResult struct {
	Pcr         *int       `json:"pcr,omitempty"`         // Number for the PCR if present (TPM)
	Name        string     `json:"name,omitempty"`        // Name of the software artifact
	Digest      string     `json:"digest"`                // Digest that was processed
	Description string     `json:"description,omitempty"` // Optional description
	Success     bool       `json:"success"`               // Indicates whether match was found
	Type        string     `json:"type,omitempty"`        // On fail, indicates whether digest is reference or measurement
	EventData   *EventData `json:"eventdata,omitempty"`   // data that was included from bioseventlog
}

type VersionCheck struct {
	Success  bool  `json:"success"`
	Claimed  []int `json:"claimed"`
	Measured []int `json:"measured"`
}

type BooleanMatch struct {
	Success  bool `json:"success"`
	Claimed  bool `json:"claimed"`
	Measured bool `json:"measured"`
}

type TcbCheck struct {
	Summary Result       `json:"result"`
	Bl      VersionCheck `json:"bl"`
	Tee     VersionCheck `json:"tee"`
	Snp     VersionCheck `json:"snp"`
	Ucode   VersionCheck `json:"ucode"`
}

type PolicyCheck struct {
	Summary      Result       `json:"result"`
	Abi          VersionCheck `json:"abi"`
	Smt          BooleanMatch `json:"smt"`
	Migration    BooleanMatch `json:"migration"`
	Debug        BooleanMatch `json:"debug"`
	SingleSocket BooleanMatch `json:"singleSocket"`
}

type AttributesCheck struct {
	Success  bool    `json:"success"`
	Claimed  HexByte `json:"claimed"`
	Measured HexByte `json:"measured"`
}

type TcbLevelResult struct {
	Summary        Result    `json:"success"`
	MrSigner       Result    `json:"mrsigner"`
	IsvProdId      Result    `json:"isvProdId"`
	MiscSelect     Result    `json:"miscSelect"`
	Attributes     Result    `json:"attributes"`
	TcbLevelStatus string    `json:"status"`
	TcbLevelDate   time.Time `json:"date"`
}

type SgxAttributesCheck struct {
	Initted      BooleanMatch `json:"initted"`
	Debug        BooleanMatch `json:"debug"`
	Mode64Bit    BooleanMatch `json:"mode64Bit"`
	ProvisionKey BooleanMatch `json:"provisionKey"`
	EInitToken   BooleanMatch `json:"eInitToken"`
	Kss          BooleanMatch `json:"kss"`
	Legacy       BooleanMatch `json:"legacy"`
	Avx          BooleanMatch `json:"avx"`
}

type TdAttributesCheck struct {
	Debug         BooleanMatch `json:"debug"`
	SeptVEDisable BooleanMatch `json:"septVEDisable"`
	Pks           BooleanMatch `json:"pks"`
	Kl            BooleanMatch `json:"kl"`
}

// SignatureResults represents the results for validation of
// a provided signature and the used certificates.
type SignatureResult struct {
	SignCheck       Result                `json:"signatureVerification"` // Result from checking the signature has been calculated with this certificate
	CertChainCheck  Result                `json:"certChainValidation"`   // Result from validatint the certification chain back to a shared root of trust
	ExtensionsCheck []Result              `json:"extensionsCheck,omitempty"`
	ValidatedCerts  [][]X509CertExtracted `json:"validatedCerts"` //Stripped information from validated x509 cert chain(s) for additional checks from the policies module
}

// X509CertExtracted represents a x509 certificate with attributes
// in a human-readable way and prepared for (un)marshaling JSON objects.
// It is based on the type Certificate from the crypto/x509 package.
type X509CertExtracted struct {
	Version            int      `json:"version"`
	SerialNumber       *big.Int `json:"serialNumber"`
	Issuer             X509Name `json:"issuer"`
	Subject            X509Name `json:"subject"`
	Validity           Validity `json:"validity"`
	KeyUsage           []string `json:"keyUsage"`
	SignatureAlgorithm string   `json:"signatureAlgorithm"`
	PublicKeyAlgorithm string   `json:"publicKeyAlgorithm"`
	PublicKey          string   `json:"publicKey"`

	// Extensions contains raw X.509 extensions extracted during parsing.
	Extensions []PkixExtension `json:"pkixExtensions"`

	ExtKeyUsage        []string `json:"extKeyUsage,omitempty"`        // Sequence of extended key usages.
	UnknownExtKeyUsage []string `json:"unknownExtKeyUsage,omitempty"` // Encountered extended key usages unknown to this package.

	BasicConstraintsValid bool `json:"basicConstraintsValid"` // BasicConstraintsValid indicates whether IsCA, MaxPathLen, and MaxPathLenZero are valid.
	IsCA                  bool `json:"isCA,omitempty"`

	// MaxPathLen and MaxPathLenZero indicate the presence and
	// value of the BasicConstraints' "pathLenConstraint".
	//
	// A positive non-zero MaxPathLen means that the field was specified,
	// -1 means it was unset, and MaxPathLenZero being true means that the field was
	// explicitly set to zero. The case of MaxPathLen==0 with MaxPathLenZero==false
	// should be treated equivalent to -1 (unset).
	MaxPathLen int `json:"maxPathLen,omitempty"`
	// MaxPathLenZero indicates that BasicConstraintsValid==true
	// and MaxPathLen==0 should be interpreted as an actual
	// maximum path length of zero. Otherwise, that combination is
	// interpreted as MaxPathLen not being set.
	MaxPathLenZero bool `json:"maxPathLenZero,omitempty"`

	SubjectKeyId   []byte `json:"subjectKeyId"`
	AuthorityKeyId []byte `json:"authorityKeyId"`

	// Subject Alternate Name values.
	DNSNames       []string `json:"dnsNames,omitempty"`
	EmailAddresses []string `json:"emailAddresses,omitempty"`
	IPAddresses    []string `json:"ipAddresses,omitempty"`
	URIs           []string `json:"uris,omitempty"`
}

// X509Name represents an X.509 distinguished name. This only includes the common
// elements of a DN. Note that the structure is not a complete representation of
// the X.509 structure.
type X509Name struct {
	Country            []string `json:"country,omitempty"`
	Organization       []string `json:"organization,omitempty"`
	OrganizationalUnit []string `json:"organizationalUnit,omitempty"`
	Locality           []string `json:"locality,omitempty"`
	Province           []string `json:"province,omitempty"`
	StreetAddress      []string `json:"streetAddress,omitempty"`
	PostalCode         []string `json:"postalCode,omitempty"`
	SerialNumber       string   `json:"serialNumber,omitempty"`
	CommonName         string   `json:"commonName,omitempty"`
}

// PkixExtension represents extensions of a x509 certificate.
type PkixExtension struct {
	Id       string `json:"id"`
	Critical bool   `json:"critical"`
	Value    []byte `json:"value"`
}

// keyUsageName is used for translating the internal representation of allowed
// key usage in an x509 certificate to a string array.
var keyUsageName = [...]string{
	x509.KeyUsageDigitalSignature:  "Digital Signature",
	x509.KeyUsageContentCommitment: "Content Commitment",
	x509.KeyUsageKeyEncipherment:   "Key Encipherment",
	x509.KeyUsageDataEncipherment:  "Data Encipherment",
	x509.KeyUsageKeyAgreement:      "Key Agreement",
	x509.KeyUsageCertSign:          "Cert Sign",
	x509.KeyUsageCRLSign:           "CRL Sign",
	x509.KeyUsageEncipherOnly:      "Encipher Only",
	x509.KeyUsageDecipherOnly:      "Decipher Only",
}

// KeyUsageToString translates the internal representation of allowed key usage
// in an x509 certificate to a string array.
func KeyUsageToString(usage x509.KeyUsage) []string {
	res := []string{}
	for i := 0; i < len(keyUsageName); i++ {
		if ((1 << i) & usage) != 0 {
			res = append(res, keyUsageName[1<<i])
		}
	}
	return res
}

// extkeyUsageName is used for translating the internal representation of allowed
// extended key usage in an x509 certificate to a string array.
var extkeyUsageName = [...]string{
	x509.ExtKeyUsageAny:                            "Any",
	x509.ExtKeyUsageServerAuth:                     "Server Auth",
	x509.ExtKeyUsageClientAuth:                     "Client Auth",
	x509.ExtKeyUsageCodeSigning:                    "Code Signing",
	x509.ExtKeyUsageEmailProtection:                "Email Protection",
	x509.ExtKeyUsageIPSECEndSystem:                 "IPsec Endsystem",
	x509.ExtKeyUsageIPSECTunnel:                    "IPsec Tunnel",
	x509.ExtKeyUsageIPSECUser:                      "IPsec User",
	x509.ExtKeyUsageTimeStamping:                   "Time Stamping",
	x509.ExtKeyUsageOCSPSigning:                    "OCSP Signing",
	x509.ExtKeyUsageMicrosoftServerGatedCrypto:     "Microsoft Server Gated Crypto",
	x509.ExtKeyUsageNetscapeServerGatedCrypto:      "Netscape Server Gated Crypto",
	x509.ExtKeyUsageMicrosoftCommercialCodeSigning: "Microsoft Commercial Code Signing",
	x509.ExtKeyUsageMicrosoftKernelCodeSigning:     "Microsoft Kernel Code Signing",
}

// ExtKeyUsageToString translates the internal representation of allowed extended
// key usage in an x509 certificate to a string array.
func ExtKeyUsageToString(usage []x509.ExtKeyUsage) []string {
	res := []string{}
	for i := 0; i < len(usage); i++ {
		res = append(res, extkeyUsageName[usage[i]])
	}
	return res
}

// TokenResult is a helper struct for the validation of JWS or COSE tokens focussing
// on the validation of the provided signatures.
type TokenResult struct {
	Summary        Result            `json:"result"`
	SignatureCheck []SignatureResult `json:"signatureValidation"`
}

type ErrorCode int

const (
	NotSet ErrorCode = iota
	CaFingerprint
	CRLCheckRoot
	CRLCheckPCK
	CRLCheckSigningCert
	DecodeCertChain
	UnknownSerialization
	DownloadRootCRL
	DownloadPCKCRL
	EvidenceLength
	EvidenceType
	Expired
	ExtractPubKey
	Internal
	InvalidCertificationLevel
	JWSNoSignatures
	JWSSignatureOrder
	JWSPayload
	MeasurementNoMatch
	MeasurementTypeNotSupported
	NotPresent
	NotYetValid
	OidLength
	OidNotPresent
	OidTag
	Parse
	ParseAR
	ParseX5C
	ParseCA
	ParseCAFingerprint
	ParseCert
	ParseTcbInfo
	ParseJSON
	ParseOSManifest
	ParseEvidence
	ParseExtensions
	ParseQEIdentity
	ParseRTMManifest
	ParseTime
	PolicyEngineNotImplemented
	RefValTypeNotSupported
	SetupSystemCA
	SgxFmpcMismatch
	SgxPceidMismatch
	SignatureLength
	DetailsNotPresent
	RefValMultiple
	RefValNotPresent
	RefValType
	RefValNoMatch
	TcbInfoExpired
	TcbLevelUnsupported
	TcbLevelRevoked
	UnsupportedAlgorithm
	VerifyAR
	VerifyCertChain
	VerifyPCKChain
	VerifyOSManifest
	VerifyPolicies
	VerifyQEIdentityErr
	VerifyRTMManifest
	VerifySignature
	VerifyTCBChain
	VerifyTcbInfo
	ExtensionsCheck
)

type Result struct {
	Success         bool      `json:"success"`
	Got             string    `json:"got,omitempty"`
	Expected        string    `json:"expected,omitempty"`
	ExpectedOneOf   []string  `json:"expectedOneOf,omitempty"`   // Required for compatibility
	ExpectedBetween []string  `json:"expectedBetween,omitempty"` // Required for validity
	ErrorCode       ErrorCode `json:"errorCode,omitempty"`
}

// ExtractX509Infos extracts relevant attributes from cert and transform some attribute
// into a more human-readable form by translating enums to a string representations.
func ExtractX509Infos(cert *x509.Certificate) X509CertExtracted {
	certExtracted := X509CertExtracted{}

	certExtracted.Version = cert.Version
	certExtracted.SerialNumber = cert.SerialNumber

	certExtracted.Issuer = X509Name{
		Country:            cert.Issuer.Country,
		Organization:       cert.Issuer.Organization,
		OrganizationalUnit: cert.Issuer.OrganizationalUnit,
		Locality:           cert.Issuer.Locality,
		Province:           cert.Issuer.Province,
		StreetAddress:      cert.Issuer.StreetAddress,
		PostalCode:         cert.Issuer.PostalCode,
		SerialNumber:       cert.Issuer.SerialNumber,
		CommonName:         cert.Issuer.CommonName,
	}

	certExtracted.Subject = X509Name{
		Country:            cert.Subject.Country,
		Organization:       cert.Subject.Organization,
		OrganizationalUnit: cert.Subject.OrganizationalUnit,
		Locality:           cert.Subject.Locality,
		Province:           cert.Subject.Province,
		StreetAddress:      cert.Subject.StreetAddress,
		PostalCode:         cert.Subject.PostalCode,
		SerialNumber:       cert.Subject.SerialNumber,
		CommonName:         cert.Subject.CommonName,
	}

	certExtracted.Validity = Validity{
		NotBefore: cert.NotBefore.String(),
		NotAfter:  cert.NotAfter.String(),
	}

	certExtracted.KeyUsage = KeyUsageToString(cert.KeyUsage)
	certExtracted.SignatureAlgorithm = cert.SignatureAlgorithm.String()
	certExtracted.PublicKeyAlgorithm = cert.PublicKeyAlgorithm.String()

	pk, err := internal.WritePublicKeyPem(cert.PublicKey)
	if err != nil {
		log.Warnf("failed to marshal PKIX public key")
	} else {
		certExtracted.PublicKey = string(pk)
	}

	for _, ext := range cert.Extensions {
		ext_extracted := PkixExtension{
			Id:       ext.Id.String(),
			Critical: ext.Critical,
			Value:    ext.Value,
		}
		certExtracted.Extensions = append(certExtracted.Extensions, ext_extracted)
	}
	certExtracted.ExtKeyUsage = ExtKeyUsageToString(cert.ExtKeyUsage)

	for _, keyusage := range cert.UnknownExtKeyUsage {
		certExtracted.UnknownExtKeyUsage = append(certExtracted.UnknownExtKeyUsage, keyusage.String())
	}

	certExtracted.BasicConstraintsValid = cert.BasicConstraintsValid
	certExtracted.IsCA = cert.IsCA
	certExtracted.MaxPathLen = cert.MaxPathLen
	certExtracted.MaxPathLenZero = cert.MaxPathLenZero

	certExtracted.SubjectKeyId = cert.SubjectKeyId
	certExtracted.AuthorityKeyId = cert.AuthorityKeyId

	certExtracted.DNSNames = cert.DNSNames
	certExtracted.EmailAddresses = cert.EmailAddresses
	for _, uri := range cert.URIs {
		certExtracted.URIs = append(certExtracted.URIs, uri.String())
	}
	for _, ip := range cert.IPAddresses {
		certExtracted.IPAddresses = append(certExtracted.IPAddresses, ip.String())
	}

	return certExtracted
}

func (e ErrorCode) String() string {
	switch e {
	case NotSet:
		return fmt.Sprintf("%v (Error code not set)", int(e))
	case CaFingerprint:
		return fmt.Sprintf("%v (CA fingerprint error)", int(e))
	case CRLCheckRoot:
		return fmt.Sprintf("%v (CRL check root error)", int(e))
	case CRLCheckPCK:
		return fmt.Sprintf("%v (CRL check PCK error)", int(e))
	case CRLCheckSigningCert:
		return fmt.Sprintf("%v (CRL check signing certificate error)", int(e))
	case DecodeCertChain:
		return fmt.Sprintf("%v (Decode certificate chain error)", int(e))
	case UnknownSerialization:
		return fmt.Sprintf("%v (Unknown serialization error)", int(e))
	case DownloadRootCRL:
		return fmt.Sprintf("%v (Download root CRL error)", int(e))
	case DownloadPCKCRL:
		return fmt.Sprintf("%v (Download PCK CRL error)", int(e))
	case EvidenceLength:
		return fmt.Sprintf("%v (Evidence length error)", int(e))
	case EvidenceType:
		return fmt.Sprintf("%v (Evidence type error)", int(e))
	case Expired:
		return fmt.Sprintf("%v (Validity Expired error)", int(e))
	case ExtractPubKey:
		return fmt.Sprintf("%v (Extract public key error)", int(e))
	case Internal:
		return fmt.Sprintf("%v (Internal error)", int(e))
	case InvalidCertificationLevel:
		return fmt.Sprintf("%v (Invalid certification level error)", int(e))
	case JWSNoSignatures:
		return fmt.Sprintf("%v (JWS no signatures error)", int(e))
	case JWSSignatureOrder:
		return fmt.Sprintf("%v (JWS signature order error)", int(e))
	case JWSPayload:
		return fmt.Sprintf("%v (JWS payload error)", int(e))
	case MeasurementNoMatch:
		return fmt.Sprintf("%v (Measurement no match error)", int(e))
	case MeasurementTypeNotSupported:
		return fmt.Sprintf("%v (Measurement type not supported error)", int(e))
	case NotPresent:
		return fmt.Sprintf("%v (Not present error)", int(e))
	case NotYetValid:
		return fmt.Sprintf("%v (Not yet valid error)", int(e))
	case OidLength:
		return fmt.Sprintf("%v (OID length error)", int(e))
	case OidNotPresent:
		return fmt.Sprintf("%v (OID not present error)", int(e))
	case OidTag:
		return fmt.Sprintf("%v (OID tag error)", int(e))
	case Parse:
		return fmt.Sprintf("%v (Parse error)", int(e))
	case ParseAR:
		return fmt.Sprintf("%v (Parse AR error)", int(e))
	case ParseX5C:
		return fmt.Sprintf("%v (Parse X5C error)", int(e))
	case ParseCA:
		return fmt.Sprintf("%v (Parse CA error)", int(e))
	case ParseCAFingerprint:
		return fmt.Sprintf("%v (Parse CA fingerprint error)", int(e))
	case ParseCert:
		return fmt.Sprintf("%v (Parse certificate error)", int(e))
	case ParseTcbInfo:
		return fmt.Sprintf("%v (Parse TCB info error)", int(e))
	case ParseJSON:
		return fmt.Sprintf("%v (Parse JSON error)", int(e))
	case ParseOSManifest:
		return fmt.Sprintf("%v (Parse OS manifest error)", int(e))
	case ParseEvidence:
		return fmt.Sprintf("%v (Parse evidence error)", int(e))
	case ParseExtensions:
		return fmt.Sprintf("%v (Parse extensions error)", int(e))
	case ParseQEIdentity:
		return fmt.Sprintf("%v (Parse QE identity error)", int(e))
	case ParseRTMManifest:
		return fmt.Sprintf("%v (Parse RTM manifest error)", int(e))
	case ParseTime:
		return fmt.Sprintf("%v (Parse time error)", int(e))
	case PolicyEngineNotImplemented:
		return fmt.Sprintf("%v (Policy engine not implemented error)", int(e))
	case RefValTypeNotSupported:
		return fmt.Sprintf("%v (Reference value type not supported error)", int(e))
	case SetupSystemCA:
		return fmt.Sprintf("%v (Setup system CA error)", int(e))
	case SgxFmpcMismatch:
		return fmt.Sprintf("%v (SGX FMPC mismatch error)", int(e))
	case SgxPceidMismatch:
		return fmt.Sprintf("%v (SGX PCEID mismatch error)", int(e))
	case SignatureLength:
		return fmt.Sprintf("%v (Signature length error)", int(e))
	case DetailsNotPresent:
		return fmt.Sprintf("%v (Details not present error)", int(e))
	case RefValMultiple:
		return fmt.Sprintf("%v (Reference value multiple error)", int(e))
	case RefValNotPresent:
		return fmt.Sprintf("%v (Reference value not present error)", int(e))
	case RefValType:
		return fmt.Sprintf("%v (Reference value type error)", int(e))
	case RefValNoMatch:
		return fmt.Sprintf("%v (Reference value no match error)", int(e))
	case TcbInfoExpired:
		return fmt.Sprintf("%v (TCB info expired error)", int(e))
	case TcbLevelUnsupported:
		return fmt.Sprintf("%v (TCB level unsupported error)", int(e))
	case TcbLevelRevoked:
		return fmt.Sprintf("%v (TCB level revoked error)", int(e))
	case UnsupportedAlgorithm:
		return fmt.Sprintf("%v (Unsupported algorithm error)", int(e))
	case VerifyAR:
		return fmt.Sprintf("%v (Verify AR error)", int(e))
	case VerifyCertChain:
		return fmt.Sprintf("%v (Verify certificate chain error)", int(e))
	case VerifyPCKChain:
		return fmt.Sprintf("%v (Verify PCK chain error)", int(e))
	case VerifyOSManifest:
		return fmt.Sprintf("%v (Verify OS manifest error)", int(e))
	case VerifyPolicies:
		return fmt.Sprintf("%v (Verify policies error)", int(e))
	case VerifyQEIdentityErr:
		return fmt.Sprintf("%v (Verify QE identity error)", int(e))
	case VerifyRTMManifest:
		return fmt.Sprintf("%v (Verify RTM manifest error)", int(e))
	case VerifySignature:
		return fmt.Sprintf("%v (Verify signature error)", int(e))
	case VerifyTCBChain:
		return fmt.Sprintf("%v (Verify TCB chain error)", int(e))
	case VerifyTcbInfo:
		return fmt.Sprintf("%v (Verify TCB info error)", int(e))
	case ExtensionsCheck:
		return fmt.Sprintf("%v (Extensions check error)", int(e))
	default:
		return fmt.Sprintf("Unknown error code: %v", int(e))
	}
}

func (r *Result) SetErr(e ErrorCode) {
	r.Success = false
	r.ErrorCode = e
}

func (r *Result) PrintErr(format string, args ...interface{}) {
	if r.Success {
		return
	}
	if r.ErrorCode == NotSet {
		log.Warnf("%v failed", fmt.Sprintf(format, args...))
	} else {
		log.Warnf("%v failed with error code %v", fmt.Sprintf(format, args...), r.ErrorCode)
	}
	if r.Expected != "" {
		log.Warnf("\tExpected: %v", r.Expected)
		log.Warnf("\tGot     : %v", r.Got)
	}
	if len(r.ExpectedBetween) == 2 {
		log.Warnf("\tExpected: %v - %v", r.ExpectedBetween[0], r.ExpectedBetween[1])
		log.Warnf("\tGot     : %v", r.Got)
	}
	if len(r.ExpectedOneOf) > 0 {
		log.Warnf("\tExpected: %v", strings.Join(r.ExpectedOneOf, ","))
		log.Warnf("\tGot     : %v", r.Got)
	}
}

func (r *SignatureResult) PrintErr(format string, args ...interface{}) {
	r.SignCheck.PrintErr("%v signature check", fmt.Sprintf(format, args...))
	r.CertChainCheck.PrintErr("%v cert chain check", fmt.Sprintf(format, args...))
	for _, e := range r.ExtensionsCheck {
		e.PrintErr("%v extension check", fmt.Sprintf(format, args...))
	}
}

func (r *VerificationResult) PrintErr() {

	if !r.Success {

		if r.ErrorCode == NotSet {
			log.Warn("Verification failed")
		} else {
			log.Warnf("Verification failed with error code: %v", r.ErrorCode)
		}

		r.FreshnessCheck.PrintErr("Report freshness check")

		for _, m := range r.Measurements {
			m.Summary.PrintErr("%v", m.Type)
			m.Freshness.PrintErr("Measurement freshness check")
			m.Signature.PrintErr("Measurement")
			for _, a := range m.Artifacts {
				if !a.Success {
					details := ""
					if a.Pcr != nil {
						details = "PCR%v"
					}
					log.Warnf("%v Measurement %v: %v verification failed", details, a.Name, a.Digest)
				}
			}
			if m.TpmResult != nil {
				m.TpmResult.AggPcrQuoteMatch.PrintErr("Aggregated PCR verification")
				for _, p := range m.TpmResult.PcrMatch {
					if !p.Success {
						log.Warnf("PCR%v calculated: %v, measured: %v", p.Pcr, p.Calculated,
							p.Measured)
					}
				}
			}
			if m.SnpResult != nil {
				m.SnpResult.VersionMatch.PrintErr("Version match")
				// TODO
				log.Warnf("Detailed SNP evaluation not yet implemented")
			}
			if m.SgxResult != nil {
				m.SgxResult.VersionMatch.PrintErr("Version match")
				// TODO
				log.Warnf("Detailed SNP evaluation not yet implemented")
			}
			if m.TdxResult != nil {
				m.TdxResult.VersionMatch.PrintErr("Version match")
				// TODO
				log.Warnf("Detailed SNP evaluation not yet implemented")
			}
		}

		for _, s := range r.ReportSignature {
			s.PrintErr("Report")
		}

		if r.CompDescResult != nil {
			r.CompDescResult.Summary.PrintErr("Company description check")
			for _, s := range r.CompDescResult.SignatureCheck {
				s.PrintErr("Company Description")
			}
			r.CompDescResult.ValidityCheck.PrintErr("Company description validity check")
		}

		r.OsResult.Summary.PrintErr("OS Manifest check")
		for _, s := range r.OsResult.SignatureCheck {
			s.PrintErr("OS Manifest")
		}
		r.OsResult.ValidityCheck.PrintErr("OS Manifest validity check")

		r.RtmResult.Summary.PrintErr("RTM Manifest check")
		for _, s := range r.RtmResult.SignatureCheck {
			s.PrintErr("RTM Manifest")
		}
		r.RtmResult.ValidityCheck.PrintErr("RTM Manifest validity check")

		for _, a := range r.AppResults {
			a.Summary.PrintErr("App Manifest %v check", a.Name)
			for _, s := range a.SignatureCheck {
				s.PrintErr("App Manifest %v", a.Name)
			}
			a.ValidityCheck.PrintErr("App Manifest %v validity check", a.Name)
		}

		r.DevDescResult.Summary.PrintErr("Device Description check")
		for _, s := range r.DevDescResult.SignatureCheck {
			s.PrintErr("Device Description")
		}
		r.DevDescResult.CorrectRtm.PrintErr("Correct RTM check")
		r.DevDescResult.CorrectOs.PrintErr("Correct OS check")
		for _, a := range r.DevDescResult.CorrectApps {
			a.PrintErr("Correct App check")
		}
		r.DevDescResult.RtmOsCompatibility.PrintErr("RTM OS compatibility")
		for _, a := range r.DevDescResult.OsAppsCompatibility {
			a.PrintErr("OS App compatibiltiy check")
		}

		if !r.PolicySuccess {
			log.Warnf("Custom policy validation failed")
		}
	}
}
