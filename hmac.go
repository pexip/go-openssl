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

// #include <openssl/core_names.h>
// #include <openssl/evp.h>
import "C"

import (
	"runtime"
	"unsafe"
)

type evpMac struct {
	mac *C.EVP_MAC
}

func getMACByName(algorithm string, allowNonFIPS bool) (*evpMac, error) {
	if DigestRequiresLegacyProvider(algorithm) {
		return nil, ErrLegacyDigest
	}

	// Create HMAC context/MAC
	libCtx := &LibraryContext{}
	if allowNonFIPS {
		var err error
		libCtx, err = GetNonFIPSCtx(false)
		if err != nil {
			return nil, err
		}
	}
	hmacStr := C.CString(C.OSSL_MAC_NAME_HMAC)
	defer C.free(unsafe.Pointer(hmacStr))
	osslMac := C.EVP_MAC_fetch(libCtx.ctx, hmacStr, nil)
	if osslMac == nil {
		return nil, errorFromErrorQueue()
	}
	mac := &evpMac{osslMac}
	runtime.SetFinalizer(mac, func(m *evpMac) {
		if m.mac != nil {
			C.EVP_MAC_free(m.mac)
			m.mac = nil
		}
	})
	return mac, nil
}

func (m *evpMac) GetName() string {
	return C.GoString(C.EVP_MAC_get0_name(m.mac))
}

func algorithmToParams(algorithm string) (*Param, error) {
	paramBld, err := NewParamBld()
	if err != nil {
		return nil, err
	}
	if err = paramBld.PushString(C.OSSL_ALG_PARAM_DIGEST, algorithm); err != nil {
		return nil, err
	}
	params, err := paramBld.ToParam()
	if err != nil {
		return nil, err
	}
	return params, nil
}

type HMAC struct {
	ctx      *C.EVP_MAC_CTX
	mac      *evpMac
	params   *Param
	key      []byte
	finished bool
}

func NewHMAC(algorithm string, key []byte, allowNonFIPS bool) (*HMAC, error) {
	mac, err := getMACByName(algorithm, allowNonFIPS)
	if err != nil {
		return nil, err
	}
	ctx := C.EVP_MAC_CTX_new(mac.mac)
	if ctx == nil {
		return nil, errorFromErrorQueue()
	}
	params, err := algorithmToParams(algorithm)
	if err != nil {
		return nil, err
	}
	hmac := &HMAC{ctx, mac, params, key, false}
	runtime.SetFinalizer(hmac, func(h *HMAC) { h.Close() })
	if err = hmac.Reset(); err != nil {
		return nil, err
	}
	return hmac, nil
}

// Reset initialises (and therefore resets) the HMAC job
func (h *HMAC) Reset() error {
	if int(C.EVP_MAC_init(
		h.ctx, (*C.uchar)(unsafe.Pointer(&h.key[0])), C.size_t(len(h.key)), h.params.param,
	)) != 1 {
		return errorFromErrorQueue()
	}
	return nil
}

func (h *HMAC) Close() {
	if h.ctx != nil {
		C.EVP_MAC_CTX_free(h.ctx)
		h.ctx = nil
	}
}

// Update updates an HMAC job
func (h *HMAC) Update(data []byte) error {
	if h.finished {
		return ErrDigestFinalised
	}
	if len(data) == 0 {
		return nil
	}
	if int(C.EVP_MAC_update(
		h.ctx, (*C.uchar)(unsafe.Pointer(&data[0])), C.size_t(len(data)),
	)) != 1 {
		return errorFromErrorQueue()
	}
	return nil
}

// Write writes data to be HMACed and returns number of bytes written
func (h *HMAC) Write(data []byte) (n int, err error) {
	if len(data) == 0 {
		return 0, nil
	}
	if err = h.Update(data); err != nil {
		return 0, err
	}
	return len(data), nil
}

// Final finalises the HMAC job and returns the digest sum
func (h *HMAC) Final() ([]byte, error) {
	h.finished = true
	var finalWritten C.size_t
	if int(C.EVP_MAC_final(
		h.ctx, nil, &finalWritten, C.EVP_MAX_MD_SIZE),
	) != 1 {
		return nil, errorFromErrorQueue()
	}

	result := make([]byte, finalWritten)
	if int(C.EVP_MAC_final(
		h.ctx, (*C.uchar)(unsafe.Pointer(&result[0])), &finalWritten, finalWritten),
	) != 1 {
		return nil, errorFromErrorQueue()
	}
	return result, nil
}
