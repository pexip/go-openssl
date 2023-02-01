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
	"errors"
	"fmt"
	"runtime"
	"strings"
	"unsafe"
)

const (
	GCMTagLen = 16
)

var (
	ErrUnknownCipher    = errors.New("unknown cipher")
	ErrLegacyCipher     = errors.New("legacy cipher requested")
	ErrNullCipher       = errors.New("null cipher")
	ErrInvalidKeyLength = errors.New("invalid key length")
	ErrInvalidIVLength  = errors.New("invalid IV length")
	ErrCipherFinalised  = errors.New("cipher job already finalised")
	legacyCipher        = map[string]bool{"rc4": true}
)

func CipherRequiresLegacyProvider(algorithm string) bool {
	_, exists := legacyCipher[strings.ToLower(algorithm)]
	return exists
}

type CipherCtx interface {
	Cipher() *Cipher
	BlockSize() int
	KeySize() int
	IVSize() int
}

type Cipher struct {
	name string
	ptr  *C.EVP_CIPHER
}

func (c *Cipher) Nid() NID {
	return NID(C.EVP_CIPHER_get_nid(c.ptr))
}

func (c *Cipher) ShortName() (string, error) {
	return Nid2ShortName(c.Nid())
}

func (c *Cipher) BlockSize() int {
	return int(C.EVP_CIPHER_get_block_size(c.ptr))
}

func (c *Cipher) KeySize() int {
	return int(C.EVP_CIPHER_get_key_length(c.ptr))
}

func (c *Cipher) IVSize() int {
	return int(C.EVP_CIPHER_get_iv_length(c.ptr))
}
func (c *Cipher) getFlags() C.ulong {
	return C.EVP_CIPHER_get_flags(c.ptr)
}

func Nid2ShortName(nid NID) (string, error) {
	sn := C.OBJ_nid2sn(C.int(nid))
	if sn == nil {
		return "", fmt.Errorf("NID %d not found", nid)
	}
	return C.GoString(sn), nil
}

// GetCipherByName returns the Cipher with the name or nil and an error if the
// cipher was not found.
func GetCipherByName(algorithm string, allowNonFIPS bool) (*Cipher, error) {
	isLegacyCipher := CipherRequiresLegacyProvider(algorithm)
	if isLegacyCipher && !allowNonFIPS {
		return nil, ErrLegacyCipher
	}
	libCtx := &LibraryContext{}
	if allowNonFIPS {
		var err error
		libCtx, err = GetNonFIPSCtx(isLegacyCipher)
		if err != nil {
			return nil, err
		}
	}
	cipherName := C.CString(algorithm)
	defer C.free(unsafe.Pointer(cipherName))

	cipher := C.EVP_CIPHER_fetch(libCtx.ctx, cipherName, nil)
	if cipher == nil {
		return nil, ErrUnknownCipher
	}
	return &Cipher{algorithm, cipher}, nil
}

func GetCipherByNid(nid NID) (*Cipher, error) {
	sn, err := Nid2ShortName(nid)
	if err != nil {
		return nil, err
	}
	return GetCipherByName(sn, false)
}

type cipherCtx struct {
	ctx *C.EVP_CIPHER_CTX
}

func newCipherCtx() (*cipherCtx, error) {
	cctx := C.EVP_CIPHER_CTX_new()
	if cctx == nil {
		return nil, errorFromErrorQueue()
	}
	ctx := &cipherCtx{cctx}
	runtime.SetFinalizer(ctx, func(c *cipherCtx) {
		if c.ctx != nil {
			C.EVP_CIPHER_CTX_free(c.ctx)
			c.ctx = nil
		}
	})
	return ctx, nil
}

func (ctx *cipherCtx) Cipher() *Cipher {
	cipherPtr := C.EVP_CIPHER_CTX_get0_cipher(ctx.ctx)
	name := C.EVP_CIPHER_get0_name(cipherPtr)
	cipher := &Cipher{name: C.GoString(name), ptr: cipherPtr}
	return cipher
}

func (ctx *cipherCtx) BlockSize() int {
	return int(C.EVP_CIPHER_CTX_get_block_size(ctx.ctx))
}

func (ctx *cipherCtx) KeySize() int {
	return int(C.EVP_CIPHER_CTX_get_key_length(ctx.ctx))
}

func (ctx *cipherCtx) IVSize() int {
	return int(C.EVP_CIPHER_CTX_get_iv_length(ctx.ctx))
}

func (ctx *cipherCtx) SetPadding(pad bool) {
	if pad {
		C.EVP_CIPHER_CTX_set_padding(ctx.ctx, 1)
	} else {
		C.EVP_CIPHER_CTX_set_padding(ctx.ctx, 0)
	}
}

func (ctx *cipherCtx) setParams(params *Param) error {
	if int(C.EVP_CIPHER_CTX_set_params(ctx.ctx, params.param)) != 1 {
		return errorFromErrorQueue()
	}
	return nil
}
func (ctx *cipherCtx) getParams(params *Param) error {
	if int(C.EVP_CIPHER_CTX_get_params(ctx.ctx, params.param)) != 1 {
		return errorFromErrorQueue()
	}
	return nil
}

type CipherJob interface {
	Cipher() *Cipher
	Update(data []byte) ([]byte, error)
	Final() ([]byte, error)
}

type cipherJob struct {
	ctx      *cipherCtx
	cipher   *Cipher
	finished bool
}

func newCipherJob(cipher *Cipher, key []byte, iv []byte, encrypt bool, skipIVLengthCheck bool) (*cipherJob, error) {
	if cipher == nil {
		return nil, ErrNullCipher
	}

	ctx, err := newCipherCtx()
	if err != nil {
		return nil, err
	}
	encval := C.int(0)
	if encrypt {
		encval = C.int(1)
	}
	if int(C.EVP_CipherInit_ex(
		ctx.ctx, cipher.ptr, nil, nil, nil, encval,
	)) != 1 {
		return nil, errorFromErrorQueue()
	}

	var keyStr, ivStr *C.uchar
	if len(key) > 0 {
		if len(key) != ctx.KeySize() {
			return nil, ErrInvalidKeyLength
		}
		keyStr = (*C.uchar)(&key[0])
	}

	if len(iv) > 0 {
		if !skipIVLengthCheck && len(iv) != ctx.IVSize() {
			return nil, ErrInvalidIVLength
		}
		if cipher.getFlags()&C.EVP_CIPH_FLAG_AEAD_CIPHER == C.EVP_CIPH_FLAG_AEAD_CIPHER {
			// Set the IV length (in case we use a non-default length IV)
			pBld, err := NewParamBld()
			if err != nil {
				return nil, err
			}
			if err = pBld.PushUInt(C.OSSL_CIPHER_PARAM_IVLEN, (uint)(len(iv))); err != nil {
				return nil, err
			}
			params, err := pBld.ToParam()
			if err != nil {
				return nil, err
			}
			if err = ctx.setParams(params); err != nil {
				return nil, err
			}
		}
		ivStr = (*C.uchar)(&iv[0])
	}
	if int(C.EVP_CipherInit_ex(
		ctx.ctx, nil, nil, keyStr, ivStr, encval,
	)) != 1 {
		return nil, errorFromErrorQueue()
	}
	return &cipherJob{ctx, cipher, false}, nil
}

// NewCipherJob creates a new cipher job using the given cipher/key/iv
func NewCipherJob(cipher *Cipher, key []byte, iv []byte, encrypt bool) (CipherJob, error) {
	return newCipherJob(cipher, key, iv, encrypt, false)
}

func (j *cipherJob) update(data []byte, extraData bool) ([]byte, error) {
	if j.finished {
		return nil, ErrCipherFinalised
	}
	if len(data) == 0 {
		return nil, nil
	}

	var out []byte = nil
	var outPtr *C.uchar = nil
	outl := C.int(len(out))
	if !extraData {
		out = make([]byte, len(data)+j.ctx.BlockSize())
		outPtr = (*C.uchar)(&out[0])
	}
	if int(C.EVP_CipherUpdate(
		j.ctx.ctx, outPtr, &outl, (*C.uchar)(&data[0]), C.int(len(data)),
	)) != 1 {
		return nil, errorFromErrorQueue()
	}
	if !extraData {
		return out[:outl], nil
	}
	return nil, nil
}
func (j *cipherJob) Update(data []byte) ([]byte, error) {
	return j.update(data, false)
}
func (j *cipherJob) ExtraData(data []byte) error {
	_, err := j.update(data, true)
	return err
}
func (j *cipherJob) Final() ([]byte, error) {
	j.finished = true
	out := make([]byte, j.ctx.BlockSize())
	var outl C.int
	if int(C.EVP_CipherFinal_ex(
		j.ctx.ctx, (*C.uchar)(&out[0]), &outl,
	)) != 1 {
		return nil, errorFromErrorQueue()
	}
	return out[:outl], nil
}
func (j *cipherJob) Cipher() *Cipher {
	return j.ctx.Cipher()
}

// Deprecated interfaces below

type EncryptionCipherJob interface {
	CipherJob

	// EncryptUpdate takes plaintext and returns the ciphertext.
	// It can be called multiple times as needed.
	//
	// Deprecated: use CipherJob.Update instead
	EncryptUpdate(input []byte) ([]byte, error)

	// EncryptFinal should be called after all plaintext has been processed.
	// It *may* return additional ciphertext if required to complete a block.
	//
	// Deprecated: use CipherJob.Final instead
	EncryptFinal() ([]byte, error)
}

type DecryptionCipherJob interface {
	CipherJob

	// DecryptUpdate takes ciphertext and returns the plaintext.
	// It can be called multiple times as needed.
	//
	// Deprecated: use CipherJob.Update instead
	DecryptUpdate(input []byte) ([]byte, error)

	// DecryptFinal should be called after all ciphertext has been processed.
	// It *may* return additional plaintext if required to complete a block.
	//
	// Deprecated: use CipherJob.Final instead
	DecryptFinal() ([]byte, error)
}

type encryptionCipherJob struct {
	*cipherJob
}

type decryptionCipherJob struct {
	*cipherJob
}

func newEncryptionCipherJob(c *Cipher, key, iv []byte, skipIVLengthCheck bool) (*encryptionCipherJob, error) {
	job, err := newCipherJob(c, key, iv, true, skipIVLengthCheck)
	if err != nil {
		return nil, err
	}
	return &encryptionCipherJob{cipherJob: job}, nil
}

func newDecryptionCipherJob(c *Cipher, key, iv []byte, skipIVLengthCheck bool) (*decryptionCipherJob, error) {
	job, err := newCipherJob(c, key, iv, false, skipIVLengthCheck)
	if err != nil {
		return nil, err
	}
	return &decryptionCipherJob{job}, nil
}

// NewEncryptionCipherJob creates a new encryption job
// Deprecated: use NewCipherJob with encrypt=true
func NewEncryptionCipherJob(c *Cipher, key, iv []byte) (EncryptionCipherJob, error) {
	return newEncryptionCipherJob(c, key, iv, false)
}

// NewDecryptionCipherJob creates a new encryption job
// Deprecated: use NewCipherJob with encrypt=false
func NewDecryptionCipherJob(c *Cipher, key, iv []byte) (DecryptionCipherJob, error) {
	return newDecryptionCipherJob(c, key, iv, false)
}

func (ctx *encryptionCipherJob) EncryptUpdate(input []byte) ([]byte, error) {
	return ctx.Update(input)
}

func (ctx *decryptionCipherJob) DecryptUpdate(input []byte) ([]byte, error) {
	return ctx.Update(input)
}

func (ctx *encryptionCipherJob) EncryptFinal() ([]byte, error) {
	return ctx.Final()
}

func (ctx *decryptionCipherJob) DecryptFinal() ([]byte, error) {
	return ctx.Final()
}
