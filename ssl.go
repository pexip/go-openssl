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
	log "github.com/sirupsen/logrus"
	"unsafe"

	"github.com/mattn/go-pointer"
)

type SSLTLSExtErr int

const (
	SSLTLSExtErrOK           SSLTLSExtErr = C.SSL_TLSEXT_ERR_OK
	SSLTLSExtErrAlertWarning SSLTLSExtErr = C.SSL_TLSEXT_ERR_ALERT_WARNING
	SSLTLSEXTErrAlertFatal   SSLTLSExtErr = C.SSL_TLSEXT_ERR_ALERT_FATAL
	SSLTLSEXTErrNoAck        SSLTLSExtErr = C.SSL_TLSEXT_ERR_NOACK
)

var (
	sslIdx = C.X_SSL_new_index()
)

//export get_ssl_idx
func get_ssl_idx() C.int {
	return sslIdx
}

type SSL struct {
	ssl      *C.SSL
	verifyCb VerifyCallback
}

//export go_ssl_verify_cb_thunk
func go_ssl_verify_cb_thunk(p unsafe.Pointer, ok C.int, ctx *C.X509_STORE_CTX) C.int {
	defer func() {
		if err := recover(); err != nil {
			log.Panicf("openssl: verify callback panic'd: %v", err)
		}
	}()
	verifyCb := pointer.Restore(p).(*SSL).verifyCb
	// set up defaults just in case verifyCb is nil
	if verifyCb != nil {
		store := &CertificateStoreCtx{ctx: ctx}
		if verifyCb(ok == 1, store) {
			ok = 1
		} else {
			ok = 0
		}
	}
	return ok
}

// GetServername returns server name according to rfc6066.
// See http://tools.ietf.org/html/rfc6066.
func (s *SSL) GetServername() string {
	return C.GoString(C.SSL_get_servername(s.ssl, C.TLSEXT_NAMETYPE_host_name))
}

// GetOptions returns SSL options. See
// https://www.openssl.org/docs/ssl/SSL_CTX_set_options.html
func (s *SSL) GetOptions() Options {
	return Options(C.SSL_get_options(s.ssl))
}

// SetOptions sets SSL options. See
// https://www.openssl.org/docs/ssl/SSL_CTX_set_options.html
func (s *SSL) SetOptions(options Options) Options {
	return Options(C.SSL_set_options(s.ssl, C.uint64_t(options)))
}

// ClearOptions clear SSL options. See
// https://www.openssl.org/docs/ssl/SSL_CTX_set_options.html
func (s *SSL) ClearOptions(options Options) Options {
	return Options(C.SSL_clear_options(s.ssl, C.uint64_t(options)))
}

// SetVerify controls peer verification settings. See
// http://www.openssl.org/docs/ssl/SSL_CTX_set_verify.html
func (s *SSL) SetVerify(options VerifyOptions, verifyCb VerifyCallback) {
	s.verifyCb = verifyCb
	if verifyCb != nil {
		C.SSL_set_verify(s.ssl, C.int(options), (*[0]byte)(C.X_SSL_verify_cb))
	} else {
		C.SSL_set_verify(s.ssl, C.int(options), nil)
	}
}

// SetVerifyMode controls peer verification setting. See
// http://www.openssl.org/docs/ssl/SSL_CTX_set_verify.html
func (s *SSL) SetVerifyMode(options VerifyOptions) {
	s.SetVerify(options, s.verifyCb)
}

// SetVerifyCallback controls peer verification setting. See
// http://www.openssl.org/docs/ssl/SSL_CTX_set_verify.html
func (s *SSL) SetVerifyCallback(verifyCb VerifyCallback) {
	s.SetVerify(s.VerifyMode(), verifyCb)
}

// GetVerifyCallback returns callback function. See
// http://www.openssl.org/docs/ssl/SSL_CTX_set_verify.html
func (s *SSL) GetVerifyCallback() VerifyCallback {
	return s.verifyCb
}

// VerifyMode returns peer verification setting. See
// http://www.openssl.org/docs/ssl/SSL_CTX_set_verify.html
func (s *SSL) VerifyMode() VerifyOptions {
	return VerifyOptions(C.SSL_get_verify_mode(s.ssl))
}

// SetVerifyDepth controls how many certificates deep the certificate
// verification logic is willing to follow a certificate chain. See
// https://www.openssl.org/docs/ssl/SSL_CTX_set_verify.html
func (s *SSL) SetVerifyDepth(depth int) {
	C.SSL_set_verify_depth(s.ssl, C.int(depth))
}

// GetVerifyDepth controls how many certificates deep the certificate
// verification logic is willing to follow a certificate chain. See
// https://www.openssl.org/docs/ssl/SSL_CTX_set_verify.html
func (s *SSL) GetVerifyDepth() int {
	return int(C.SSL_get_verify_depth(s.ssl))
}

// SetSSLCtx changes context to new one. Useful for Server Name Indication (SNI)
// rfc6066 http://tools.ietf.org/html/rfc6066. See
// http://stackoverflow.com/questions/22373332/serving-multiple-domains-in-one-box-with-sni
func (s *SSL) SetSSLCtx(ctx *Ctx) {
	/*
	 * SSL_set_SSL_CTX() only changes certs as of 1.0.0d
	 * adjust other things we care about
	 */
	C.SSL_set_SSL_CTX(s.ssl, ctx.ctx)
}

//export sni_cb_thunk
func sni_cb_thunk(p unsafe.Pointer, con *C.SSL, ad unsafe.Pointer, arg unsafe.Pointer) C.int {
	defer func() {
		if err := recover(); err != nil {
			log.Panicf("openssl: verify callback sni panic'd: %v", err)
		}
	}()

	sniCb := pointer.Restore(p).(*Ctx).sniCb

	s := &SSL{ssl: con}
	// This attaches a pointer to our SSL struct into the SNI callback.
	C.SSL_set_ex_data(s.ssl, get_ssl_idx(), pointer.Save(s))

	// Note: this is ctx.sniCb, not C.sniCb
	return C.int(sniCb(s))
}
