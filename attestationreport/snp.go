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
	"bytes"
	"crypto/ecdsa"
	"crypto/sha512"
	"crypto/x509"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"math/big"

	log "github.com/sirupsen/logrus"
)

type snpreport struct {
	// Table 24 @ https://www.amd.com/system/files/TechDocs/56860.pdf
	Status     uint32
	ReportSize uint32
	Reserved0  [24]byte
	// Table 21 @ https://www.amd.com/system/files/TechDocs/56860.pdf
	Version         uint32
	GuestSvn        uint32
	Policy          uint64
	FamilyId        [16]byte
	ImageId         [16]byte
	Vmpl            uint32
	SignatureAlgo   uint32
	CurrentTcb      uint64 // platform_version
	PlatformInfo    uint64
	AuthorKeyEn     uint32
	Reserved1       uint32
	ReportData      [64]byte
	Measurement     [48]byte
	HostData        [32]byte
	IdKeyDigest     [48]byte
	AuthorKeyDigest [48]byte
	ReportId        [32]byte
	ReportIdMa      [32]byte
	ReportedTcb     uint64
	Reserved2       [24]byte
	ChipId          [64]byte
	//Reserved3 [192]byte
	CommittedTcb   uint64
	CurrentBuild   uint8
	CurrentMinor   uint8
	CurrentMajor   uint8
	Reserved3a     uint8
	CommittedBuild uint8
	CommittedMinor uint8
	CommittedMajor uint8
	Reserved3b     uint8
	LaunchTcb      uint64
	Reserved3c     [168]byte
	// Table 23 @ https://www.amd.com/system/files/TechDocs/56860.pdf
	SignatureR [72]byte
	SignatureS [72]byte
	Reserved4  [368]byte
}

const (
	ecdsa384_with_sha384 = 1
)

const (
	header_offset    = 0x20
	signature_offset = 0x2A0
)

func verifySnpMeasurements(snpM *SnpMeasurement, nonce []byte, verifications []Verification) (*SnpMeasurementResult, bool) {
	result := &SnpMeasurementResult{}
	ok := true

	// If the attestationreport does contain neither SNP measurements, nor SNP verifications
	// there is nothing to to
	if snpM == nil && len(verifications) == 0 {
		return nil, true
	}

	// If the attestationreport contains SNP verifications, but no SNP measurement, the
	// attestation must fail
	if snpM == nil {
		for _, v := range verifications {
			msg := fmt.Sprintf("SNP Measurement not present. Cannot verify SNP verification (hash: %v)", v.Sha384)
			result.VerificationsCheck.setFalseMulti(&msg)
		}
		result.Summary.Success = false
		return result, false
	}

	if len(verifications) == 0 {
		msg := "Could not find SNP verification"
		result.Summary.setFalse(&msg)
		return result, false
	} else if len(verifications) > 1 {
		msg := fmt.Sprintf("Report contains %v verifications. Currently, only 1 SNP verification is supported", len(verifications))
		result.Summary.setFalse(&msg)
		return result, false
	}
	snpVerification := verifications[0]

	if snpVerification.Type != "SNP Verification" {
		msg := fmt.Sprintf("SNP Verification invalid type %v", snpVerification.Type)
		result.Summary.setFalse(&msg)
		return result, false
	}
	if snpVerification.Snp == nil {
		msg := "SNP Verification does not contain policy"
		result.Summary.setFalse(&msg)
		return result, false
	}

	// Extract the SNP attestation report data structure
	s, err := DecodeSnpReport(snpM.Report)
	if err != nil {
		msg := fmt.Sprintf("Failed to decode SNP report: %v", err)
		result.Summary.setFalse(&msg)
		return result, false
	}

	// Compare Nonce for Freshness (called Report Data in the SNP Attestation Report Structure)
	nonce64 := make([]byte, 64)
	copy(nonce64, nonce)
	if cmp := bytes.Compare(s.ReportData[:], nonce64); cmp != 0 {
		msg := fmt.Sprintf("Nonces mismatch: Supplied Nonce = %v, Nonce in SNP Report = %v)", hex.EncodeToString(nonce), hex.EncodeToString(s.ReportData[:]))
		result.Freshness.setFalse(&msg)
		ok = false
	} else {
		result.Freshness.Success = true
	}

	// Verify Signature, created with SNP VCEK private key
	sig, ret := verifySnpSignature(snpM.Report, s, snpM.Certs)
	if !ret {
		ok = false
	}
	result.Signature = sig

	// Compare Measurements
	v, err := hex.DecodeString(snpVerification.Sha384)
	if err != nil {
		msg := fmt.Sprintf("Failed to decode SNP Verification: %v", err)
		result.Summary.setFalse(&msg)
		ok = false
	}
	if cmp := bytes.Compare(s.Measurement[:], v); cmp != 0 {
		msg := fmt.Sprintf("SNP Measurement mismatch: Supplied measurement = %v, SNP report measurement = %v", snpVerification.Sha384, hex.EncodeToString(s.Measurement[:]))
		result.MeasurementMatch.setFalse(&msg)
		ok = false
	} else {
		result.MeasurementMatch.Success = true
		// As we previously checked, that the attestation report contains exactly one
		// SNP verification, we can set this here:
		result.VerificationsCheck.Success = true
	}

	// Compare SNP parameters
	result.VersionMatch, ret = verifySnpVersion(s, snpVerification.Snp.Version)
	if !ret {
		ok = false
	}
	result.PolicyCheck, ret = verifySnpPolicy(s, snpVerification.Snp.Policy)
	if !ret {
		ok = false
	}
	result.FwCheck, ret = verifySnpFw(s, snpVerification.Snp.Fw)
	if !ret {
		ok = false
	}
	result.TcbCheck, ret = verifySnpTcb(s, snpVerification.Snp.Tcb)
	if !ret {
		ok = false
	}

	result.Summary.Success = ok

	return result, ok
}

func DecodeSnpReport(report []byte) (snpreport, error) {
	var s snpreport
	b := bytes.NewBuffer(report)
	err := binary.Read(b, binary.LittleEndian, &s)
	if err != nil {
		return snpreport{}, fmt.Errorf("failed to decode SNP report: %w", err)
	}
	return s, nil
}

func verifySnpVersion(s snpreport, version uint32) (Result, bool) {
	r := Result{}
	ok := s.Version == version
	if !ok {
		msg := fmt.Sprintf("SNP report version mismatch: Report = %v, supplied = %v", s.Version, version)
		r.setFalse(&msg)
	} else {
		r.Success = true
	}
	return r, ok
}

func verifySnpPolicy(s snpreport, v SnpPolicy) (PolicyCheck, bool) {

	abiMajor := uint8(s.Policy & 0xFF)
	abiMinor := uint8((s.Policy >> 8) & 0xFF)
	smt := (s.Policy & (1 << 16)) != 0
	migration := (s.Policy & (1 << 18)) != 0
	debug := (s.Policy & (1 << 19)) != 0
	singleSocket := (s.Policy & (1 << 20)) != 0

	// Convert to int, as json.Marshal otherwise interprets the values as strings
	r := PolicyCheck{
		Abi: VersionCheck{
			Success:  checkMinVersion([]uint8{abiMajor, abiMinor}, []uint8{v.AbiMajor, v.AbiMinor}),
			Claimed:  []int{int(v.AbiMajor), int(v.AbiMinor)},
			Measured: []int{int(abiMajor), int(abiMinor)},
		},
		Smt: BooleanMatch{
			Success:  smt == v.Smt,
			Claimed:  v.Smt,
			Measured: smt,
		},
		Migration: BooleanMatch{
			Success:  migration == v.Migration,
			Claimed:  v.Migration,
			Measured: migration,
		},
		Debug: BooleanMatch{
			Success:  debug == v.Debug,
			Claimed:  v.Debug,
			Measured: debug,
		},
		SingleSocket: BooleanMatch{
			Success:  singleSocket == v.SingleSocket,
			Claimed:  v.SingleSocket,
			Measured: singleSocket,
		},
	}
	ok := r.Abi.Success &&
		r.Smt.Success &&
		r.Migration.Success &&
		r.Debug.Success &&
		r.SingleSocket.Success
	if !ok {
		log.Tracef("SNP policies do not match: Abi: %v, Smt: %v, Migration: %v, Debug: %v, SingleSocket: %v",
			r.Abi.Success, r.Smt.Success, r.Migration.Success, r.Debug.Success, r.SingleSocket.Success)
	}
	r.Summary.Success = ok

	return r, ok
}

func verifySnpFw(s snpreport, v SnpFw) (VersionCheck, bool) {

	build := min([]uint8{s.CurrentBuild, s.CommittedBuild})
	major := min([]uint8{s.CurrentMajor, s.CommittedMajor})
	minor := min([]uint8{s.CurrentMinor, s.CommittedMinor})

	ok := checkMinVersion([]uint8{major, minor, build}, []uint8{v.Major, v.Minor, v.Build})
	if !ok {
		log.Tracef("SNP FW version check failed. Expected: %v.%v.%v, got %v.%v.%v",
			v.Major, v.Minor, v.Build, major, minor, build)
	}

	// Convert to int, as json.Marshal otherwise interprets the values as strings
	r := VersionCheck{
		Success:  ok,
		Claimed:  []int{int(v.Major), int(v.Minor), int(v.Build)},
		Measured: []int{int(major), int(minor), int(build)},
	}
	return r, ok
}

func verifySnpTcb(s snpreport, v SnpTcb) (TcbCheck, bool) {

	currBl := uint8(s.CurrentTcb & 0xFF)
	commBl := uint8(s.CommittedTcb & 0xFF)
	launBl := uint8(s.LaunchTcb & 0xFF)
	repoBl := uint8(s.ReportedTcb & 0xFF)
	currTee := uint8((s.CurrentTcb >> 8) & 0xFF)
	commTee := uint8((s.CommittedTcb >> 8) & 0xFF)
	launTee := uint8((s.LaunchTcb >> 8) & 0xFF)
	repoTee := uint8((s.ReportedTcb >> 8) & 0xFF)
	currSnp := uint8((s.CurrentTcb >> 48) & 0xFF)
	commSnp := uint8((s.CommittedTcb >> 48) & 0xFF)
	launSnp := uint8((s.LaunchTcb >> 48) & 0xFF)
	repoSnp := uint8((s.ReportedTcb >> 48) & 0xFF)
	currUcode := uint8((s.CurrentTcb >> 56) & 0xFF)
	commUcode := uint8((s.CommittedTcb >> 56) & 0xFF)
	launUcode := uint8((s.LaunchTcb >> 56) & 0xFF)
	repoUcode := uint8((s.ReportedTcb >> 56) & 0xFF)

	bl := min([]uint8{currBl, commBl, launBl, repoBl})
	tee := min([]uint8{currTee, commTee, launTee, repoTee})
	snp := min([]uint8{currSnp, commSnp, launSnp, repoSnp})
	ucode := min([]uint8{currUcode, commUcode, launUcode, repoUcode})

	// Convert to int, as json.Marshal otherwise interprets the values as strings
	r := TcbCheck{
		Bl: VersionCheck{
			Success:  bl >= v.Bl,
			Claimed:  []int{int(v.Bl)},
			Measured: []int{int(bl)},
		},
		Tee: VersionCheck{
			Success:  tee >= v.Tee,
			Claimed:  []int{int(v.Tee)},
			Measured: []int{int(tee)},
		},
		Snp: VersionCheck{
			Success:  snp >= v.Snp,
			Claimed:  []int{int(v.Snp)},
			Measured: []int{int(snp)},
		},
		Ucode: VersionCheck{
			Success:  ucode >= v.Ucode,
			Claimed:  []int{int(v.Ucode)},
			Measured: []int{int(ucode)},
		},
	}
	ok := r.Bl.Success && r.Tee.Success && r.Snp.Success && r.Ucode.Success
	if !ok {
		log.Tracef("SNP TCB check failed: BL: %v, TEE: %v, SNP: %v, UCODE: %v",
			r.Bl.Success, r.Tee.Success, r.Snp.Success, r.Ucode.Success)
	}
	r.Summary.Success = ok

	return r, ok
}

func verifySnpSignature(reportRaw []byte, report snpreport, certs CertChain) (SignatureResult, bool) {
	result := SignatureResult{}

	if len(reportRaw) < (header_offset + signature_offset) {
		msg := "Internal Error: Report buffer too small"
		result.Signature.setFalse(&msg)
		return result, false
	}

	// Strip the header and the signature from the report and hash for signature verification
	// Table 21, 23 @ https://www.amd.com/system/files/TechDocs/56860.pdf
	digest := sha512.Sum384(reportRaw[0x20 : 0x20+0x2A0])

	// Golang SetBytes expects BigEndian byte array, but SNP values are little endian
	rRaw := report.SignatureR[:]
	for i := 0; i < len(rRaw)/2; i++ {
		rRaw[i], rRaw[len(rRaw)-i-1] = rRaw[len(rRaw)-i-1], rRaw[i]
	}
	sRaw := report.SignatureS[:]
	for i := 0; i < len(sRaw)/2; i++ {
		sRaw[i], sRaw[len(sRaw)-i-1] = sRaw[len(sRaw)-i-1], sRaw[i]
	}

	// Convert r, s to Big Int
	r := new(big.Int)
	r.SetBytes(rRaw)
	s := new(big.Int)
	s.SetBytes(sRaw)

	// Load the VCEK certificate
	c, err := loadCert(certs.Leaf)
	if err != nil {
		msg := fmt.Sprintf("Failed to load certificate: %v", err)
		result.Signature.setFalse(&msg)
		return result, false
	}
	result.Name = c.Subject.CommonName
	result.Organization = c.Subject.Organization
	result.SubjectKeyId = hex.EncodeToString(c.SubjectKeyId)
	result.AuthorityKeyId = hex.EncodeToString(c.AuthorityKeyId)

	// Examine SNP x509 extensions
	extensionResult, ok := verifySnpExtensions(c, &report)
	result.ExtensionsCheck = &extensionResult
	if !ok {
		return result, false
	}

	// Check that the algorithm is supported
	if report.SignatureAlgo != ecdsa384_with_sha384 {
		msg := fmt.Sprintf("Siganture Algorithm %v not supported", report.SignatureAlgo)
		result.Signature.setFalse(&msg)
		return result, false
	}

	// Extract the public key from the certificate
	pub, ok := c.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		msg := "Failed to extract ECDSA public key from certificate"
		result.Signature.setFalse(&msg)
		return result, false
	}

	// Verify ECDSA Signature represented by r and s
	ok = ecdsa.Verify(pub, digest[:], r, s)
	if !ok {
		msg := "Failed to verify SNP report signature"
		result.Signature.setFalse(&msg)
		return result, false
	}
	log.Trace("Successfully verified SNP report signature")

	// Verify the SNP certificate chain
	err = verifyCertChain(&certs)
	if err != nil {
		msg := fmt.Sprintf("Failed to verify certificate chain: %v", err)
		result.CertCheck.setFalse(&msg)
		return result, false
	} else {
		result.CertCheck.Success = true
	}

	result.Signature.Success = true

	return result, true
}

func verifySnpExtensions(cert *x509.Certificate, report *snpreport) (ResultMulti, bool) {
	result := ResultMulti{}
	ok := true
	tcb := report.CurrentTcb

	if err := checkExtensionUint8(cert, "1.3.6.1.4.1.3704.1.3.1", uint8(tcb)); err != nil {
		msg := fmt.Sprintf("SEV BL Extension Check failed: %v", err)
		result.setFalseMulti(&msg)
		ok = false
	}

	if err := checkExtensionUint8(cert, "1.3.6.1.4.1.3704.1.3.2", uint8(tcb>>8)); err != nil {
		msg := fmt.Sprintf("SEV TEE Extension Check failed: %v", err)
		result.setFalseMulti(&msg)
		ok = false
	}

	if err := checkExtensionUint8(cert, "1.3.6.1.4.1.3704.1.3.3", uint8(tcb>>48)); err != nil {
		msg := fmt.Sprintf("SEV SNP Extension Check failed: %v", err)
		result.setFalseMulti(&msg)
		ok = false
	}

	if err := checkExtensionUint8(cert, "1.3.6.1.4.1.3704.1.3.8", uint8(tcb>>56)); err != nil {
		msg := fmt.Sprintf("SEV UCODE Extension Check failed: %v", err)
		result.setFalseMulti(&msg)
		ok = false
	}

	if err := checkExtensionBuf(cert, "1.3.6.1.4.1.3704.1.4", report.ChipId[:]); err != nil {
		msg := fmt.Sprintf("Chip ID Extension Check failed: %v", err)
		result.setFalseMulti(&msg)
		ok = false
	}

	result.Success = ok

	return result, ok
}

func min(v []uint8) uint8 {
	if len(v) == 0 {
		return 0
	}
	min := v[0]
	for _, v := range v {
		if v < min {
			min = v
		}
	}
	return min
}

func checkMinVersion(version []uint8, ref []uint8) bool {
	if len(version) != len(ref) {
		log.Warn("Internal Error: Version arrays differ in length")
		return false
	}
	for i := range version {
		if version[i] > ref[i] {
			return true
		} else if version[i] < ref[i] {
			return false
		}
	}
	return true
}
