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

package attestedtls

import (
	"crypto/tls"
	"fmt"

	"github.com/sirupsen/logrus"
)

var id = "0000"

var log = logrus.WithField("service", "atls")

func attestDialer(conn *tls.Conn, chbindings []byte, cc CmcConfig) error {

	//optional: attest Client
	if cc.Attest == Attest_Mutual || cc.Attest == Attest_Client {
		log.Debug("Attesting the Client")
		// Obtain attestation report from local cmcd
		resp, err := cc.CmcApi.obtainAR(cc, chbindings)
		if err != nil {
			return fmt.Errorf("could not obtain dialer AR: %w", err)
		}

		// Send created attestation report to listener
		log.Tracef("Sending attestation report length %v to listener", len(resp))

		err = Write(append([]byte{byte(cc.Attest)}, resp...), conn)
		if err != nil {
			return fmt.Errorf("failed to send AR: %w", err)
		}
		log.Trace("Sent AR")
	} else {
		//if not sending attestation report, send the attestation mode
		err := Write([]byte{byte(cc.Attest)}, conn)
		if err != nil {
			return fmt.Errorf("failed to send skip client Attestation: %w", err)
		}
		log.Debug("Skipping client-side attestation")
	}

	readvalue, err := readValue(conn, cc.Attest, true)
	if err != nil {
		return err
	}

	//optional: Wait for attestation report from Server
	if cc.Attest == Attest_Mutual || cc.Attest == Attest_Server {
		report := readvalue
		// Verify AR from listener with own channel bindings
		log.Trace("Verifying attestation report from listener")
		err = cc.CmcApi.verifyAR(chbindings, report, cc)
		if err != nil {
			return err
		}
	} else {
		log.Debug("Skipping client-side verification")
	}

	log.Trace("Attestation successful")

	return nil
}

func attestListener(conn *tls.Conn, chbindings []byte, cc CmcConfig) error {
	// optional: attest server
	if cc.Attest == Attest_Mutual || cc.Attest == Attest_Server {
		// Obtain own attestation report from local cmcd
		log.Trace("Attesting the Server")
		resp, err := cc.CmcApi.obtainAR(cc, chbindings)
		if err != nil {
			return fmt.Errorf("could not obtain AR of Listener : %w", err)
		}

		// Send own attestation report to dialer
		log.Trace("Sending own attestation report")
		err = Write(append([]byte{byte(cc.Attest)}, resp...), conn)
		if err != nil {
			return fmt.Errorf("failed to send AR: %w", err)
		}
	} else {
		//if not sending attestation report, send the attestation mode
		err := Write([]byte{byte(cc.Attest)}, conn)
		if err != nil {
			return fmt.Errorf("failed to send skip client Attestation: %w", err)
		}
		log.Debug("Skipping server-side attestation")
	}

	report, err := readValue(conn, cc.Attest, false)
	if err != nil {
		return err
	}

	// optional: Wait for attestation report from client
	if cc.Attest == Attest_Mutual || cc.Attest == Attest_Client {
		// Verify AR from dialer with own channel bindings
		log.Trace("Verifying attestation report from dialer...")
		err = cc.CmcApi.verifyAR(chbindings, report, cc)
		if err != nil {
			return err
		}
	} else {
		log.Debug("Skipping server-side verification")
	}

	log.Trace("Attestation successful")

	return nil
}

func readValue(conn *tls.Conn, selection AttestSelect, dialer bool) ([]byte, error) {
	readvalue, err := Read(conn)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	selectionStr, errS1 := selectionString(byte(selection))
	if errS1 != nil {
		return nil, errS1
	}

	// the first byte should always be the attestation mode
	if readvalue[0] == byte(selection) {
		log.Debugf("Matching attestation mode: [%v]", selectionStr)
	} else {
		reportByte := readvalue[0]
		reportStr, errS1 := selectionString(reportByte)
		if errS1 != nil {
			return nil, errS1
		}
		return nil, fmt.Errorf("mismatching attestation mode, local set to: [%v], while remote is set to: [%v]", selectionStr, reportStr)
	}

	return readvalue[1:], nil
}

func selectionString(selection byte) (string, error) {
	switch selection {
	case 0:
		return "mutual", nil
	case 1:
		return "client", nil
	case 2:
		return "server", nil
	case 3:
		return "none", nil
	default:
		return "", fmt.Errorf("unknown attestation mode")
	}
}
