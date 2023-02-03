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

/*
#include <openssl/ssl.h>
#include <openssl/conf.h>
#include <openssl/x509v3.h>
*/
import "C"

import (
	"errors"
	"fmt"
	"net"
	"unsafe"
)

var (
	ErrHostValidation    = errors.New("host validation error")
	ErrHostInvalidInput  = errors.New("invalid hostname input")
	ErrHostInternalError = errors.New("host internal error")
)

type CheckFlags int

const (
	AlwaysCheckSubject    CheckFlags = C.X509_CHECK_FLAG_ALWAYS_CHECK_SUBJECT
	NoWildcards           CheckFlags = C.X509_CHECK_FLAG_NO_WILDCARDS
	NoPartialWildcards    CheckFlags = C.X509_CHECK_FLAG_NO_PARTIAL_WILDCARDS
	MultiLabelWildcards   CheckFlags = C.X509_CHECK_FLAG_MULTI_LABEL_WILDCARDS
	SingleLabelSubdomains CheckFlags = C.X509_CHECK_FLAG_SINGLE_LABEL_SUBDOMAINS
	NeverCheckSubject     CheckFlags = C.X509_CHECK_FLAG_NEVER_CHECK_SUBJECT
)

func getErrorFromReturn(rc int, fn string) error {
	switch rc {
	case 1:
		return nil
	case 0:
		return ErrHostValidation
	case -1:
		return ErrHostInternalError
	case -2:
		return ErrHostInvalidInput
	}
	panic(fmt.Sprintf("Unknown %s return value: %d", fn, rc))
}

// CheckHost checks that the X509 certificate is signed for the provided
// host name. See http://www.openssl.org/docs/crypto/X509_check_host.html for
// more. Note that CheckHost does not check the IP field. See VerifyHostname.
// Specifically returns ErrHostValidation if the Certificate didn't match but
// there was no internal error.
func (c *Certificate) CheckHost(host string, flags CheckFlags) error {
	chost := C.CString(host)
	defer C.free(unsafe.Pointer(chost))

	return getErrorFromReturn(
		int(C.X509_check_host(c.x, chost, C.size_t(len(host)), C.uint(flags), nil)),
		"X509_check_host",
	)
}

// CheckEmail checks that the X509 certificate is signed for the provided
// email address. See http://www.openssl.org/docs/crypto/X509_check_host.html
// for more.
// Specifically returns ErrHostValidation if the Certificate didn't match but
// there was no internal error.
func (c *Certificate) CheckEmail(email string, flags CheckFlags) error {
	cemail := C.CString(email)
	defer C.free(unsafe.Pointer(cemail))

	return getErrorFromReturn(
		int(C.X509_check_email(c.x, cemail, C.size_t(len(email)), C.uint(flags))),
		"X509_check_email",
	)
}

// CheckIP checks that the X509 certificate is signed for the provided
// IP address. See http://www.openssl.org/docs/crypto/X509_check_host.html
// for more.
// Specifically returns ErrHostValidation if the Certificate didn't match but
// there was no internal error.
func (c *Certificate) CheckIP(ip net.IP, flags CheckFlags) error {
	// X509_check_ip will fail to validate the 16-byte representation of an IPv4
	// address, so convert to the 4-byte representation.
	if ip4 := ip.To4(); ip4 != nil {
		ip = ip4
	}

	cip := unsafe.Pointer(&ip[0])
	return getErrorFromReturn(
		int(C.X509_check_ip(c.x, (*C.uchar)(cip), C.size_t(len(ip)), C.uint(flags))),
		"X509_check_ip",
	)
}

// VerifyHostname is a combination of CheckHost and CheckIP. If the provided
// hostname looks like an IP address, it will be checked as an IP address,
// otherwise it will be checked as a hostname.
// Specifically returns ErrHostValidation if the Certificate didn't match but
// there was no internal error.
func (c *Certificate) VerifyHostname(host string) error {
	var ip net.IP
	if len(host) >= 3 && host[0] == '[' && host[len(host)-1] == ']' {
		ip = net.ParseIP(host[1 : len(host)-1])
	} else {
		ip = net.ParseIP(host)
	}
	if ip != nil {
		return c.CheckIP(ip, 0)
	}
	return c.CheckHost(host, 0)
}
