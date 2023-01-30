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

// #include "shim.h"
import "C"

import (
	"errors"
	"runtime"
	"unsafe"
)

type DH struct {
	dh *C.EVP_PKEY
}

// LoadDHParametersFromPEM loads the Diffie-Hellman parameters from
// a PEM-encoded block.
func LoadDHParametersFromPEM(pem_block []byte) (*DH, error) {
	if len(pem_block) == 0 {
		return nil, errors.New("empty pem block")
	}

	bio := C.BIO_new_mem_buf(unsafe.Pointer(&pem_block[0]), C.int(len(pem_block)))
	if bio == nil {
		return nil, errors.New("failed creating bio")
	}
	defer C.BIO_free(bio)

	var data *C.uchar
	dataLength := C.long(0)

	cDhParam := C.CString("DH PARAMETERS")
	defer C.free(unsafe.Pointer(cDhParam))

	if int(C.PEM_bytes_read_bio(
		&data, &dataLength, nil, cDhParam, bio, nil, nil,
	)) != 1 {
		return nil, errorFromErrorQueue()
	}

	// take a copy of data pointer because d2i_KeyParams manipulates the data pointer
	p := data
	params := C.d2i_KeyParams(C.EVP_PKEY_DH, nil, &p, dataLength)
	cfile := C.CString("LoadDHParametersFromPEM")
	defer C.free(unsafe.Pointer(cfile))
	C.CRYPTO_free(unsafe.Pointer(data), cfile, 0)
	if params == nil {
		return nil, errorFromErrorQueue()
	}

	dhparams := &DH{dh: params}
	runtime.SetFinalizer(dhparams, func(dhparams *DH) {
		C.EVP_PKEY_free(dhparams.dh)
	})
	return dhparams, nil
}

// SetDHParameters sets the DH group (DH parameters) used to
// negotiate an ephemeral DH key during handshaking.
func (c *Ctx) SetDHParameters(dh *DH) error {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	if int(C.SSL_CTX_set0_tmp_dh_pkey(c.ctx, dh.dh)) != 1 {
		return errorFromErrorQueue()
	}
	return nil
}
