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

// #include <string.h>
// #include <openssl/evp.h>
// #include <openssl/core_names.h>
import "C"

import (
	"errors"
	"fmt"
	"unsafe"
)

var ErrCipherInvalidBlockSize = errors.New("invalid block size")

type AuthenticatedCipherJob interface {
	// ExtraData add extra data that
	// pass in any extra data that was added during encryption with the
	// encryption context's ExtraData()
	ExtraData([]byte) error
}
type AuthenticatedEncryptionCipherJob interface {
	AuthenticatedCipherJob
	EncryptionCipherJob

	// ExtraData data passed in to ExtraData() is part of the final output; it is
	// not encrypted itself, but is part of the authenticated data. when
	// decrypting or authenticating, pass back with the decryption
	// context's ExtraData()
	ExtraData([]byte) error

	// GetTag gets the authentication tag after finalising the encryption
	GetTag() ([]byte, error)
}

type AuthenticatedDecryptionCipherCtx interface {
	AuthenticatedCipherJob
	DecryptionCipherJob

	// ExtraData pass in any extra authenticated data that was added during encryption
	ExtraData([]byte) error

	// SetTag sets the expected authentication tag to be checked when finalising the decryption
	SetTag([]byte) error
}

type authEncryptionCipherJob struct {
	*encryptionCipherJob
}

type authDecryptionCipherJob struct {
	*decryptionCipherJob
}

func getGCMCipher(blocksize int) (*Cipher, error) {
	cipher, err := GetCipherByName(fmt.Sprintf("aes-%d-gcm", blocksize), false)
	if err != nil {
		return nil, ErrCipherInvalidBlockSize
	}
	return cipher, nil
}

func NewGCMEncryptionCipherJob(blocksize int, key, iv []byte) (AuthenticatedEncryptionCipherJob, error) {
	cipher, err := getGCMCipher(blocksize)
	if err != nil {
		return nil, err
	}
	job, err := newEncryptionCipherJob(cipher, key, iv, true)
	if err != nil {
		return nil, err
	}
	return &authEncryptionCipherJob{job}, nil
}

func NewGCMDecryptionCipherCtx(blocksize int, key, iv []byte) (AuthenticatedDecryptionCipherCtx, error) {
	cipher, err := getGCMCipher(blocksize)
	if err != nil {
		return nil, err
	}
	job, err := newDecryptionCipherJob(cipher, key, iv, true)
	if err != nil {
		return nil, err
	}
	return &authDecryptionCipherJob{job}, nil
}

func (ctx *authEncryptionCipherJob) GetTag() ([]byte, error) {
	tag := make([]byte, GCMTagLen)
	pBld, err := NewParamBld()
	if err != nil {
		return nil, err
	}
	if err = pBld.PushOctetString(C.OSSL_CIPHER_PARAM_AEAD_TAG, tag); err != nil {
		return nil, err
	}
	params, err := pBld.ToParam()
	if err != nil {
		return nil, err
	}
	if err := ctx.cipherJob.ctx.getParams(params); err != nil {
		return nil, err
	}
	// memcpy because ParamBld "helpfully" allocates a new buffer, see
	// https://github.com/openssl/openssl/blob/323c47532ea7fc79d5e28a0fa58ea0cc4d5196b8/crypto/param_build.c#L357-L362
	// And we can't use PushOctetPtr because the GCM implementation calls OSSL_PARAM_set_octet_string which willfully
	// ignores octet pointers! See
	// https://github.com/openssl/openssl/blob/323c47532ea7fc79d5e28a0fa58ea0cc4d5196b8/providers/implementations/ciphers/ciphercommon_gcm.c#L205-L219
	C.memcpy(
		unsafe.Pointer(&tag[0]),
		unsafe.Pointer(params.param.data),
		C.size_t(len(tag)),
	)
	return tag, nil
}

func (ctx *authDecryptionCipherJob) SetTag(tag []byte) error {
	pBld, err := NewParamBld()
	if err != nil {
		return err
	}
	if err = pBld.PushOctetString(C.OSSL_CIPHER_PARAM_AEAD_TAG, tag); err != nil {
		return err
	}
	params, err := pBld.ToParam()
	if err != nil {
		return err
	}
	return ctx.cipherJob.ctx.setParams(params)
}
