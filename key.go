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

// #include <openssl/evp.h>
// #include <openssl/rsa.h>
// #include <openssl/pem.h>
// #include <openssl/x509v3.h>
// #include <openssl/store.h>
import "C"

import (
	"errors"
	"fmt"
	"io"
	"runtime"
	"unsafe"
)

var (
	ErrEmptyBlock = errors.New("empty block")
	ErrLoadingKey = errors.New("failed loading private key")
)

type KeyType int

// Constants for the various key types.
const (
	KeyTypeNone     KeyType = C.EVP_PKEY_NONE
	KeyTypeRSA      KeyType = C.EVP_PKEY_RSA
	KeyTypeRSA2     KeyType = C.EVP_PKEY_RSA2
	KeyTypeRSAPSS   KeyType = C.EVP_PKEY_RSA_PSS
	KeyTypeDSA      KeyType = C.EVP_PKEY_DSA
	KeyTypeDSA1     KeyType = C.EVP_PKEY_DSA1
	KeyTypeDSA2     KeyType = C.EVP_PKEY_DSA2
	KeyTypeDSA3     KeyType = C.EVP_PKEY_DSA3
	KeyTypeDSA4     KeyType = C.EVP_PKEY_DSA4
	KeyTypeDH       KeyType = C.EVP_PKEY_DH
	KeyTypeDHX      KeyType = C.EVP_PKEY_DHX
	KeyTypeEC       KeyType = C.EVP_PKEY_EC
	KeyTypeSM2      KeyType = C.EVP_PKEY_SM2
	KeyTypeHMAC     KeyType = C.EVP_PKEY_HMAC
	KeyTypeCMAC     KeyType = C.EVP_PKEY_CMAC
	KeyTypeScrypt   KeyType = C.EVP_PKEY_SCRYPT
	KeyTypeTLS1PRF  KeyType = C.EVP_PKEY_TLS1_PRF
	KeyTypeHKDF     KeyType = C.EVP_PKEY_HKDF
	KeyTypePoly1305 KeyType = C.EVP_PKEY_POLY1305
	KeyTypeSIPHash  KeyType = C.EVP_PKEY_SIPHASH
	KeyTypeX25519   KeyType = C.EVP_PKEY_X25519
	KeyTypeED25519  KeyType = C.EVP_PKEY_ED25519
	KeyTypeX448     KeyType = C.EVP_PKEY_X448
	KeyTypeED448    KeyType = C.EVP_PKEY_ED448
)

type PublicKey interface {
	// VerifyPKCS1v15 verifies the data signature using PKCS1.15
	VerifyPKCS1v15(digest *Digest, data, sig []byte) error

	// MarshalPKIXPublicKeyPEM converts the public key to PEM-encoded PKIX format
	MarshalPKIXPublicKeyPEM() (pemBlock []byte, err error)

	// MarshalPKIXPublicKeyDER converts the public key to DER-encoded PKIX format
	MarshalPKIXPublicKeyDER() (derBlock []byte, err error)

	// KeyType returns an identifier for what kind of key is represented by this object.
	KeyType() KeyType

	// BaseType returns an identifier for what kind of key is represented
	// by this object.
	// Keys that share same algorithm but use different legacy formats
	// will have the same BaseType.
	//
	// For example, a key with a `KeyType() == KeyTypeRSA` and a key with a
	// `KeyType() == KeyTypeRSA2` would both have `BaseType() == KeyTypeRSA`.
	BaseType() NID

	// Equal compares the key with the passed in key.
	Equal(key PublicKey) bool

	// Size returns the size (in bytes) of signatures created with this key.
	Size() int

	evpPKey() *C.EVP_PKEY
}

type PrivateKey interface {
	PublicKey

	// SignPKCS1v15 signs the data using PKCS1.15
	SignPKCS1v15(*Digest, []byte) ([]byte, error)

	// MarshalPKCS1PrivateKeyPEM converts the private key to PEM-encoded PKCS1 format
	MarshalPKCS1PrivateKeyPEM() (pemBlock []byte, err error)

	// MarshalPKCS1PrivateKeyDER converts the private key to DER-encoded PKCS1 format
	MarshalPKCS1PrivateKeyDER() (derBlock []byte, err error)
}

type pKey struct {
	key *C.EVP_PKEY
}

func pKeyFromKey(key *C.EVP_PKEY) *pKey {
	pkey := &pKey{key: key}
	runtime.SetFinalizer(pkey, func(p *pKey) {
		C.EVP_PKEY_free(p.key)
	})
	return pkey
}

func (key *pKey) evpPKey() *C.EVP_PKEY { return key.key }

func (key *pKey) Equal(other PublicKey) bool {
	return C.EVP_PKEY_eq(key.key, other.evpPKey()) == 1
}

func (key *pKey) KeyType() KeyType {
	return KeyType(C.EVP_PKEY_get_id(key.key))
}

func (key *pKey) Size() int {
	return int(C.EVP_PKEY_get_size(key.key))
}

func (key *pKey) Bits() int {
	return int(C.EVP_PKEY_get_bits(key.key))
}

func (key *pKey) SecurityBits() int {
	return int(C.EVP_PKEY_get_security_bits(key.key))
}

func (key *pKey) BaseType() NID {
	return NID(C.EVP_PKEY_get_base_id(key.key))
}

func (key *pKey) SignPKCS1v15(digest *Digest, data []byte) ([]byte, error) {

	ctx := C.EVP_MD_CTX_new()
	defer C.EVP_MD_CTX_free(ctx)

	if key.KeyType() == KeyTypeED25519 {
		// do ED specific one-shot sign
		if digest != nil {
			return nil, errors.New("signpkcs1v15: digest must be null")
		}
		if len(data) == 0 {
			return nil, errors.New("signpkcs1v15: 0-length data or non-null digest")
		}

		if C.EVP_DigestSignInit(ctx, nil, nil, nil, key.key) != 1 {
			return nil, errorFromErrorQueue()
		}

		// evp signatures are 64 bytes
		sig := make([]byte, 64)
		var siglen C.size_t = 64
		if C.EVP_DigestSign(ctx,
			(*C.uchar)(unsafe.Pointer(&sig[0])),
			&siglen,
			(*C.uchar)(unsafe.Pointer(&data[0])),
			C.size_t(len(data))) != 1 {
			return nil, errorFromErrorQueue()
		}

		return sig[:siglen], nil
	} else {
		job, err := newDigestJob(*digest)
		if err != nil {
			return nil, err
		}
		if err = job.Update(data); err != nil {
			return nil, err
		}
		return job.SignFinal(key)
	}
}

func (key *pKey) VerifyPKCS1v15(digest *Digest, data, sig []byte) error {
	ctx := C.EVP_MD_CTX_new()
	defer C.EVP_MD_CTX_free(ctx)

	if len(sig) == 0 {
		return errors.New("verifypkcs1v15: 0-length sig")
	}

	if key.KeyType() == KeyTypeED25519 {
		// do ED specific one-shot sign

		if digest != nil || len(data) == 0 {
			return errors.New("verifypkcs1v15: 0-length data or non-null digest")
		}

		if C.EVP_DigestVerifyInit(ctx, nil, nil, nil, key.key) != 1 {
			return errorFromErrorQueue()
		}

		if C.EVP_DigestVerify(ctx,
			(*C.uchar)(unsafe.Pointer(&sig[0])),
			C.size_t(len(sig)),
			(*C.uchar)(unsafe.Pointer(&data[0])),
			C.size_t(len(data))) != 1 {
			return errorFromErrorQueue()
		}

		return nil

	} else {
		job, err := newDigestJob(*digest)
		if err != nil {
			return err
		}
		if err = job.Update(data); err != nil {
			return err
		}
		return job.VerifyFinal(sig, key)
	}
}

func (key *pKey) MarshalPKCS1PrivateKeyPEM() (pemBlock []byte, err error) {
	bio, err := newBio(nil)
	if err != nil {
		return nil, err
	}

	// PEM_write_bio_PrivateKey_traditional will use the key-specific PKCS1
	// format if one is available for that key type, otherwise it will encode
	// to a PKCS8 key.
	if int(C.PEM_write_bio_PrivateKey_traditional(
		bio.ptr, key.key, nil, nil, C.int(0), nil, nil,
	)) != 1 {
		return nil, errors.New("failed dumping private key")
	}

	pemBlock, err = io.ReadAll(bio.asAnyBio())
	runtime.KeepAlive(bio)
	return
}

func (key *pKey) MarshalPKCS1PrivateKeyDER() (derBlock []byte, err error) {
	bio, err := newBio(nil)
	if err != nil {
		return nil, err
	}

	if int(C.i2d_PrivateKey_bio(bio.ptr, key.key)) != 1 {
		return nil, errors.New("failed dumping private key der")
	}

	derBlock, err = io.ReadAll(bio.asAnyBio())
	runtime.KeepAlive(bio)
	return
}

func (key *pKey) MarshalPKIXPublicKeyPEM() (pemBlock []byte, err error) {
	bio, err := newBio(nil)
	if err != nil {
		return nil, err
	}

	if int(C.PEM_write_bio_PUBKEY(bio.ptr, key.key)) != 1 {
		return nil, errors.New("failed dumping public key pem")
	}

	pemBlock, err = io.ReadAll(bio.asAnyBio())
	runtime.KeepAlive(bio)
	return
}

func (key *pKey) MarshalPKIXPublicKeyDER() (derBlock []byte, err error) {
	bio, err := newBio(nil)
	if err != nil {
		return nil, err
	}

	if int(C.i2d_PUBKEY_bio(bio.ptr, key.key)) != 1 {
		return nil, errors.New("failed dumping public key der")
	}

	derBlock, err = io.ReadAll(bio.asAnyBio())
	runtime.KeepAlive(bio)
	return
}

// LoadPrivateKeyFromPEM loads a private key from a PEM-encoded block.
func LoadPrivateKeyFromPEM(pemBlock []byte) (PrivateKey, error) {
	if len(pemBlock) == 0 {
		return nil, ErrEmptyBlock
	}
	bio, err := newBio(pemBlock)
	if err != nil {
		return nil, err
	}
	key := C.PEM_read_bio_PrivateKey(bio.ptr, nil, nil, nil)
	runtime.KeepAlive(bio)
	if key == nil {
		return nil, ErrLoadingKey
	}

	return pKeyFromKey(key), nil
}

// LoadPrivateKeyFromPEMWithPassword loads a private key from a PEM-encoded block.
func LoadPrivateKeyFromPEMWithPassword(pemBlock []byte, password string) (PrivateKey, error) {
	if len(pemBlock) == 0 {
		return nil, ErrEmptyBlock
	}
	bio, err := newBio(pemBlock)
	if err != nil {
		return nil, err
	}
	cs := unsafe.Pointer(C.CString(password))
	defer C.free(cs)
	key := C.PEM_read_bio_PrivateKey(bio.ptr, nil, nil, cs)
	runtime.KeepAlive(bio)
	if key == nil {
		return nil, ErrLoadingKey
	}

	return pKeyFromKey(key), nil
}

// LoadPrivateKeyFromDER loads a private key from a DER-encoded block.
func LoadPrivateKeyFromDER(derBlock []byte) (PrivateKey, error) {
	if len(derBlock) == 0 {
		return nil, ErrEmptyBlock
	}
	bio, err := newBio(derBlock)
	if err != nil {
		return nil, err
	}

	key := C.d2i_PrivateKey_bio(bio.ptr, nil)
	runtime.KeepAlive(bio)
	if key == nil {
		return nil, ErrLoadingKey
	}

	return pKeyFromKey(key), nil
}

// LoadPrivateKeyByUri loads a private key similar to the openssl command.
// For example, you can pass in "handle:0x81000000"
//
// This function is a more simple implementation in load_key_certs_crls that the
// openssl command line utility uses, so most things that you can pass into the
// command line utility should work here.
func LoadPrivateKeyByUri(uri string) (PrivateKey, error) {
	cstrUri := C.CString(uri)
	defer C.free(unsafe.Pointer(cstrUri))

	ctx := C.OSSL_STORE_open_ex(cstrUri, nil, nil, nil, nil, nil, nil, nil)
	if ctx == nil {
		return nil, ErrLoadingKey
	}

	info := C.OSSL_STORE_load(ctx)
	if info == nil {
		return nil, ErrLoadingKey
	}

	key := C.OSSL_STORE_INFO_get1_PKEY(info)
	if key == nil {
		return nil, ErrLoadingKey
	}

	return pKeyFromKey(key), nil
}

// LoadPublicKeyFromPEM loads a public key from a PEM-encoded block.
func LoadPublicKeyFromPEM(pemBlock []byte) (PublicKey, error) {
	if len(pemBlock) == 0 {
		return nil, ErrEmptyBlock
	}
	bio, err := newBio(pemBlock)
	if err != nil {
		return nil, err
	}

	key := C.PEM_read_bio_PUBKEY(bio.ptr, nil, nil, nil)
	runtime.KeepAlive(bio)
	if key == nil {
		return nil, ErrLoadingKey
	}

	return pKeyFromKey(key), nil
}

// LoadPublicKeyFromDER loads a public key from a DER-encoded block.
func LoadPublicKeyFromDER(derBlock []byte) (PublicKey, error) {
	if len(derBlock) == 0 {
		return nil, ErrEmptyBlock
	}
	bio, err := newBio(derBlock)
	if err != nil {
		return nil, err
	}

	key := C.d2i_PUBKEY_bio(bio.ptr, nil)
	runtime.KeepAlive(bio)
	if key == nil {
		return nil, ErrLoadingKey
	}

	return pKeyFromKey(key), nil
}

type PrivateKeyContext interface {
	evpCtx() *C.EVP_PKEY_CTX
	SetRSAKeygenBits(bits int) error
	SetRSAKeygenPubExp(exponent int) error
}
type PrivateKeyGenerationContext interface {
	PrivateKeyContext
	Generate() (PrivateKey, error)
}
type PrivateKeyParamGenerationContext interface {
	PrivateKeyContext
	Generate() (PrivateKey, error)
	SetECParamGenCurveNID(curve EllipticCurve) error
}
type PrivateKeyDeriveContext interface {
	PrivateKeyContext
	SetPeer(peer PublicKey) error
	Derive() ([]byte, error)
}

type pkeyCtx struct {
	ctx   *C.EVP_PKEY_CTX
	keyID KeyType
}
type pkeyGenCtx struct {
	pkeyCtx
}
type pkeyParamGenCtx struct {
	pkeyCtx
}
type pkeyDeriveCtx struct {
	pkeyCtx
}

func (p *pkeyCtx) evpCtx() *C.EVP_PKEY_CTX {
	return p.ctx
}

func (p *pkeyCtx) SetRSAKeygenBits(bits int) error {
	if err := ensureErrorQueueIsClear(); err != nil {
		return fmt.Errorf("failed setting RSA keygen bits: %w", err)
	}
	if int(C.EVP_PKEY_CTX_set_rsa_keygen_bits(p.ctx, C.int(bits))) != 1 {
		return fmt.Errorf("failed setting RSA keygen bits: %w", errorFromErrorQueue())
	}
	return nil
}
func (p *pkeyCtx) SetRSAKeygenPubExp(exponent int) error {
	exponentBn, err := newBignumFromInt(exponent)
	if err != nil {
		return fmt.Errorf("failed creating RSA public exponent BN: %w", err)
	}
	if err := ensureErrorQueueIsClear(); err != nil {
		return fmt.Errorf("failed setting RSA keygen public exponent: %w", err)
	}
	if int(C.EVP_PKEY_CTX_set1_rsa_keygen_pubexp(p.ctx, exponentBn.bn)) != 1 {
		return fmt.Errorf("failed setting RSA keygen public exponent: %w", errorFromErrorQueue())
	}
	runtime.KeepAlive(exponentBn)
	return nil
}
func (p *pkeyCtx) generate() (PrivateKey, error) {
	if err := ensureErrorQueueIsClear(); err != nil {
		return nil, fmt.Errorf("failed generating PrivateKey: %w", err)
	}
	var key *C.EVP_PKEY
	if int(C.EVP_PKEY_generate(p.ctx, &key)) != 1 {
		return nil, fmt.Errorf("failing generating PrivateKey: %w", errorFromErrorQueue())
	}
	return pKeyFromKey(key), nil
}

func (p *pkeyParamGenCtx) SetECParamGenCurveNID(curve EllipticCurve) error {
	if err := ensureErrorQueueIsClear(); err != nil {
		return fmt.Errorf("failed setting EC paramgen curve NID: %w", err)
	}
	if int(C.EVP_PKEY_CTX_set_ec_paramgen_curve_nid(p.ctx, C.int(curve))) != 1 {
		return fmt.Errorf("failed setting EC paramgen curve NID: %w", errorFromErrorQueue())
	}
	return nil
}
func (p *pkeyParamGenCtx) Generate() (PrivateKey, error) {
	return p.generate()
}

func (p *pkeyGenCtx) Generate() (PrivateKey, error) {
	return p.generate()
}

func (p *pkeyDeriveCtx) SetPeer(peer PublicKey) error {
	if err := ensureErrorQueueIsClear(); err != nil {
		return fmt.Errorf("failed setting derive peer: %w", err)
	}
	if int(C.EVP_PKEY_derive_set_peer(p.ctx, peer.evpPKey())) != 1 {
		return fmt.Errorf("failed setting derive peer: %w", errorFromErrorQueue())
	}
	return nil
}
func (p *pkeyDeriveCtx) Derive() ([]byte, error) {
	if err := ensureErrorQueueIsClear(); err != nil {
		return nil, fmt.Errorf("failed deriving: %w", err)
	}
	var bufferLen C.size_t
	if int(C.EVP_PKEY_derive(p.ctx, nil, &bufferLen)) != 1 {
		return nil, fmt.Errorf("failed deriving: %w", errorFromErrorQueue())
	}
	buffer := make([]byte, bufferLen)
	if int(C.EVP_PKEY_derive(
		p.ctx, (*C.uchar)(unsafe.Pointer(&buffer[0])), &bufferLen),
	) != 1 {
		return nil, fmt.Errorf("failed deriving: %w", errorFromErrorQueue())
	}
	return buffer[:bufferLen], nil
}

func newPKeyContextFromKey(key PrivateKey) (*pkeyCtx, error) {
	if err := ensureErrorQueueIsClear(); err != nil {
		return nil, fmt.Errorf("failed creating new pKeyContext from key: %w", err)
	}
	ctx := C.EVP_PKEY_CTX_new(key.evpPKey(), nil)
	if ctx == nil {
		return nil, errors.New("failed to create pKeyCtx")
	}
	return &pkeyCtx{ctx, key.KeyType()}, nil
}
func newPKeyContextFromKeyType(keyType KeyType) (*pkeyCtx, error) {
	if err := ensureErrorQueueIsClear(); err != nil {
		return nil, fmt.Errorf("failed creating new pKeyContext from type: %w", err)
	}
	ctx := C.EVP_PKEY_CTX_new_id(C.int(keyType), nil)
	if ctx == nil {
		return nil, errors.New("failed to create pKeyCtx")
	}
	keyCtx := &pkeyCtx{ctx: ctx}
	runtime.SetFinalizer(keyCtx, func(c *pkeyCtx) {
		if c.ctx != nil {
			C.EVP_PKEY_CTX_free(c.ctx)
			c.ctx = nil
		}
	})
	return keyCtx, nil
}

func NewPKeyGenerationContextFromKey(key PrivateKey) (PrivateKeyGenerationContext, error) {
	ctx, err := newPKeyContextFromKey(key)
	if err != nil {
		return nil, err
	}
	if err := ensureErrorQueueIsClear(); err != nil {
		return nil, fmt.Errorf("failed initialise keygen: %w", err)
	}
	if int(C.EVP_PKEY_keygen_init(ctx.evpCtx())) != 1 {
		return nil, fmt.Errorf("failed initialise keygen: %w", errorFromErrorQueue())
	}
	return &pkeyGenCtx{*ctx}, nil
}
func NewPKeyGenerationContextFromKeyType(keyType KeyType) (PrivateKeyGenerationContext, error) {
	ctx, err := newPKeyContextFromKeyType(keyType)
	if err != nil {
		return nil, err
	}
	if err := ensureErrorQueueIsClear(); err != nil {
		return nil, fmt.Errorf("failed initialise keygen: %w", err)
	}
	if int(C.EVP_PKEY_keygen_init(ctx.evpCtx())) != 1 {
		return nil, fmt.Errorf("failed initialise keygen: %w", errorFromErrorQueue())
	}
	return &pkeyGenCtx{*ctx}, nil
}

func NewPKeyParamGenerationCtx(keyID KeyType) (PrivateKeyParamGenerationContext, error) {
	ctx, err := newPKeyContextFromKeyType(keyID)
	if err != nil {
		return nil, err
	}
	if err := ensureErrorQueueIsClear(); err != nil {
		return nil, fmt.Errorf("failed initialise paramgen: %w", err)
	}
	if int(C.EVP_PKEY_paramgen_init(ctx.evpCtx())) != 1 {
		return nil, fmt.Errorf("failed initialise paramgen: %w", errorFromErrorQueue())
	}
	return &pkeyParamGenCtx{*ctx}, nil
}

func NewPKeyDeriveContextFromKey(key PrivateKey) (PrivateKeyDeriveContext, error) {
	ctx, err := newPKeyContextFromKey(key)
	if err != nil {
		return nil, err
	}
	if err := ensureErrorQueueIsClear(); err != nil {
		return nil, fmt.Errorf("failed initialise derive: %w", err)
	}
	if int(C.EVP_PKEY_derive_init(ctx.evpCtx())) != 1 {
		return nil, fmt.Errorf("failed initialise derive: %w", errorFromErrorQueue())
	}
	return &pkeyDeriveCtx{*ctx}, nil
}

// GenerateRSAKey generates a new RSA private key with an exponent of 3.
func GenerateRSAKey(bits int) (PrivateKey, error) {
	return GenerateRSAKeyWithExponent(bits, 3)
}

// GenerateRSAKeyWithExponent generates a new RSA private key.
func GenerateRSAKeyWithExponent(bits int, exponent int) (PrivateKey, error) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	ctx, err := NewPKeyGenerationContextFromKeyType(KeyTypeRSA)
	if err != nil {
		return nil, err
	}
	if err = ctx.SetRSAKeygenBits(bits); err != nil {
		return nil, err
	}
	if err = ctx.SetRSAKeygenPubExp(exponent); err != nil {
		return nil, err
	}
	p, err := ctx.Generate()
	if err != nil {
		return nil, err
	}
	return p, nil
}

// GenerateECKey generates a new elliptic curve private key on the specified curve.
func GenerateECKey(curve EllipticCurve) (PrivateKey, error) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	paramCtx, err := NewPKeyParamGenerationCtx(KeyTypeEC)
	if err != nil {
		return nil, err
	}
	if err = paramCtx.SetECParamGenCurveNID(curve); err != nil {
		return nil, err
	}
	params, err := paramCtx.Generate()
	if err != nil {
		return nil, err
	}

	keyCtx, err := NewPKeyGenerationContextFromKey(params)
	if err != nil {
		return nil, err
	}
	key, err := keyCtx.Generate()
	if err != nil {
		return nil, err
	}
	return key, nil
}

// GenerateED25519Key generates a Ed25519 key
func GenerateED25519Key() (PrivateKey, error) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	keyCtx, err := NewPKeyGenerationContextFromKeyType(KeyTypeED25519)
	if err != nil {
		return nil, err
	}
	key, err := keyCtx.Generate()
	if err != nil {
		return nil, err
	}
	return key, nil
}
