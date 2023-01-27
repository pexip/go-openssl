// Copyright (C) 2017. See AUTHORS.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package openssl

import (
	"bytes"
	"math/big"
	"testing"
	"time"
)

func TestCertGenerate(t *testing.T) {
	key, err := GenerateRSAKey(768)
	if err != nil {
		t.Fatal(err)
	}
	info := &CertificateInfo{
		Serial:       big.NewInt(int64(1)),
		Issued:       0,
		Expires:      24 * time.Hour,
		Country:      "US",
		Organization: "Test",
		CommonName:   "localhost",
	}
	cert, err := NewCertificate(info, key)
	if err != nil {
		t.Fatal(err)
	}
	if err := cert.Sign(key, EVP_SHA256); err != nil {
		t.Fatal(err)
	}
}

func TestCAGenerate(t *testing.T) {
	cakey, err := GenerateRSAKey(768)
	if err != nil {
		t.Fatal(err)
	}
	info := &CertificateInfo{
		Serial:       big.NewInt(int64(1)),
		Issued:       0,
		Expires:      24 * time.Hour,
		Country:      "US",
		Organization: "Test CA",
		CommonName:   "CA",
	}
	ca, err := NewCertificate(info, cakey)
	if err != nil {
		t.Fatal(err)
	}
	if err := ca.AddExtensions(map[NID]string{
		NID_basic_constraints:      "critical,CA:TRUE",
		NID_key_usage:              "critical,keyCertSign,cRLSign",
		NID_subject_key_identifier: "hash",
		NID_netscape_cert_type:     "sslCA",
	}); err != nil {
		t.Fatal(err)
	}
	if err := ca.Sign(cakey, EVP_SHA256); err != nil {
		t.Fatal(err)
	}
	key, err := GenerateRSAKey(768)
	if err != nil {
		t.Fatal(err)
	}
	info = &CertificateInfo{
		Serial:       big.NewInt(int64(1)),
		Issued:       0,
		Expires:      24 * time.Hour,
		Country:      "US",
		Organization: "Test",
		CommonName:   "localhost",
	}
	cert, err := NewCertificate(info, key)
	if err != nil {
		t.Fatal(err)
	}
	if err := cert.AddExtensions(map[NID]string{
		NID_basic_constraints: "critical,CA:FALSE",
		NID_key_usage:         "keyEncipherment",
		NID_ext_key_usage:     "serverAuth",
	}); err != nil {
		t.Fatal(err)
	}
	if err := cert.SetIssuer(ca); err != nil {
		t.Fatal(err)
	}
	if err := cert.Sign(cakey, EVP_SHA256); err != nil {
		t.Fatal(err)
	}
}

func TestCertGetNameEntry(t *testing.T) {
	key, err := GenerateRSAKey(768)
	if err != nil {
		t.Fatal(err)
	}
	info := &CertificateInfo{
		Serial:       big.NewInt(int64(1)),
		Issued:       0,
		Expires:      24 * time.Hour,
		Country:      "US",
		Organization: "Test",
		CommonName:   "localhost",
	}
	cert, err := NewCertificate(info, key)
	if err != nil {
		t.Fatal(err)
	}
	name, err := cert.GetSubjectName()
	if err != nil {
		t.Fatal(err)
	}
	entry, ok := name.GetEntry(NID_commonName)
	if !ok {
		t.Fatal("no common name")
	}
	if entry != "localhost" {
		t.Fatalf("expected localhost; got %q", entry)
	}
	entry, ok = name.GetEntry(NID_localityName)
	if ok {
		t.Fatal("did not expect a locality name")
	}
	if entry != "" {
		t.Fatalf("entry should be empty; got %q", entry)
	}
}

func TestCertVersion(t *testing.T) {
	key, err := GenerateRSAKey(768)
	if err != nil {
		t.Fatal(err)
	}
	info := &CertificateInfo{
		Serial:       big.NewInt(int64(1)),
		Issued:       0,
		Expires:      24 * time.Hour,
		Country:      "US",
		Organization: "Test",
		CommonName:   "localhost",
	}
	cert, err := NewCertificate(info, key)
	if err != nil {
		t.Fatal(err)
	}
	if err := cert.SetVersion(X509_V3); err != nil {
		t.Fatal(err)
	}
	if vers := cert.GetVersion(); vers != X509_V3 {
		t.Fatalf("bad version: %d", vers)
	}
}

func TestCertGetFingerprint(t *testing.T) {
	cert, err := LoadCertificateFromPEM(certBytes)
	if err != nil {
		t.Fatal(err)
	}
	fingerprint, err := cert.ComputeFingerprint(EVP_SHA256)
	if err != nil {
		t.Fatal(err)
	}
	expected := []byte{0xB6, 0x7B, 0xF8, 0x11, 0x69, 0x86, 0x40, 0x4C, 0x17, 0x87, 0x70, 0x98, 0xA2, 0x99, 0x2A, 0x30, 0xB7, 0x7D, 0x0B, 0x6F, 0x3B, 0x5F, 0x53, 0x13, 0x40, 0xAF, 0xA2, 0x78, 0x04, 0x95, 0x5A, 0x69}
	if !bytes.Equal(fingerprint, expected) {
		t.Fatal("Invalid fingerprint")
	}
}
