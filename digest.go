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
	"strings"
	"unsafe"
)

var (
	ErrUnknownDigest   = errors.New("unknown digest")
	ErrLegacyDigest    = errors.New("legacy digest requested")
	ErrDigestFinalised = errors.New("digest job already finalised")
	legacyMD           = map[string]struct{}{"md4": {}}
)

// Digest represents and openssl message digest.
type Digest struct {
	name string
	ptr  *C.EVP_MD
}

// GetSize gets the size of the digest
func (d *Digest) GetSize() int {
	return int(C.EVP_MD_get_size(d.ptr))
}

// digestJob represents a digest job
type digestJob struct {
	digest   Digest
	ctx      *C.EVP_MD_CTX
	finished bool
}

// newDigestJob creates a new digest job for the given digest
func newDigestJob(digest Digest) (*digestJob, error) {
	ctx := C.EVP_MD_CTX_new()
	if ctx == nil {
		return nil, errorFromErrorQueue()
	}
	job := &digestJob{digest: digest, ctx: ctx, finished: false}
	runtime.SetFinalizer(job, func(j *digestJob) {
		j.Close()
	})
	if err := job.Reset(); err != nil {
		return nil, err
	}
	return job, nil
}

// Reset initialises (and therefore resets) the digest
func (d *digestJob) Reset() error {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	if int(C.EVP_DigestInit_ex(d.ctx, d.digest.ptr, nil)) != 1 {
		return errorFromErrorQueue()
	}
	d.finished = false
	return nil
}

func (d *digestJob) Close() {
	if d.ctx != nil {
		C.EVP_MD_CTX_free(d.ctx)
		d.ctx = nil
	}
}

// Update updates a digest job
func (d *digestJob) Update(data []byte) error {
	if d.finished {
		return ErrDigestFinalised
	}
	if len(data) == 0 {
		return nil
	}
	if C.EVP_DigestUpdate(
		d.ctx, unsafe.Pointer(&data[0]), C.size_t(len(data)),
	) != 1 {
		return errorFromErrorQueue()
	}
	return nil
}

// Write writes data to be digested and returns number of bytes written
func (d *digestJob) Write(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	if err := d.Update(p); err != nil {
		return 0, err
	}
	return len(p), nil
}

// Final finalises the digest job and returns the digest sum
func (d *digestJob) Final() ([]byte, error) {
	d.finished = true
	var finalWritten C.uint
	result := make([]byte, d.digest.GetSize())
	if C.EVP_DigestFinal_ex(
		d.ctx, (*C.uchar)(unsafe.Pointer(&result[0])), &finalWritten,
	) != 1 {
		return nil, errorFromErrorQueue()
	}
	return result[:finalWritten], nil
}

// Sum finalises the digest job and returns the digest sum
func (d *digestJob) Sum() ([]byte, error) {
	return d.Final()
}

// SignFinal finalises the digest job, signs it with the given pkey and returns the signature
func (d *digestJob) SignFinal(key *pKey) ([]byte, error) {
	d.finished = true
	var finalWritten C.uint
	result := make([]byte, C.EVP_PKEY_get_size(key.key))
	if C.EVP_SignFinal(
		d.ctx, (*C.uchar)(unsafe.Pointer(&result[0])), &finalWritten, key.key,
	) != 1 {
		return nil, errorFromErrorQueue()
	}
	return result[:finalWritten], nil
}

// VerifyFinal finalises the digest job, verifies it with the provided signature/pkey
func (d *digestJob) VerifyFinal(signature []byte, key *pKey) error {
	d.finished = true
	if C.EVP_VerifyFinal(
		d.ctx, (*C.uchar)(unsafe.Pointer(&signature[0])), C.uint(len(signature)), key.key,
	) != 1 {
		return errorFromErrorQueue()
	}
	return nil
}

func DigestRequiresLegacyProvider(algorithm string) bool {
	_, exists := legacyMD[strings.ToLower(algorithm)]
	return exists
}

// GetDigestByName returns the Digest with the name or nil and an error if the
// digest was not found.
func GetDigestByName(algorithm string, allowNonFIPS bool) (*Digest, error) {
	isLegacyDigest := DigestRequiresLegacyProvider(algorithm)
	if isLegacyDigest && !allowNonFIPS {
		return nil, ErrLegacyDigest
	}
	libCtx := &LibraryContext{}
	if allowNonFIPS {
		var err error
		libCtx, err = GetNonFIPSCtx(isLegacyDigest)
		if err != nil {
			return nil, err
		}
	}

	cname := C.CString(algorithm)
	defer C.free(unsafe.Pointer(cname))

	digest := C.EVP_MD_fetch(libCtx.ctx, cname, nil)
	if digest == nil {
		return nil, ErrUnknownDigest
	}

	// we can consider digests to use static mem; don't need to free
	return &Digest{name: algorithm, ptr: digest}, nil
}

// GetDigestByNid returns the Digest with the NID or nil and an error if the
// digest was not found.
func GetDigestByNid(nid NID, allowNonFIPS bool) (*Digest, error) {
	sn, err := Nid2ShortName(nid)
	if err != nil {
		return nil, err
	}
	return GetDigestByName(sn, allowNonFIPS)
}
