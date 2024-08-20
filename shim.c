/*
 * Copyright (C) 2014 Space Monkey, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */

#include <string.h>

#include <openssl/conf.h>

#include <openssl/bio.h>
#include <openssl/crypto.h>
#include <openssl/engine.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/ssl.h>

#include "_cgo_export.h"

/*
 * Functions defined in other .c files
 */
static int go_write_bio_puts(BIO *b, const char *str) {
	return go_write_bio_write(b, (char*)str, (int)strlen(str));
}


static int x_bio_create(BIO *b) {
	BIO_set_shutdown(b, 1);
	BIO_set_init(b, 1);
	BIO_set_data(b, NULL);
	BIO_clear_flags(b, ~0);
	return 1;
}

static int x_bio_free(BIO *b) {
	return 1;
}

static BIO_METHOD *writeBioMethod;
static BIO_METHOD *readBioMethod;

BIO_METHOD* BIO_s_readBio() { return readBioMethod; }
BIO_METHOD* BIO_s_writeBio() { return writeBioMethod; }

int x_bio_init_methods() {
	writeBioMethod = BIO_meth_new(BIO_TYPE_SOURCE_SINK, "Go Write BIO");
	if (!writeBioMethod) {
		return 1;
	}
	if (1 != BIO_meth_set_write(writeBioMethod,
				(int (*)(BIO *, const char *, int))go_write_bio_write)) {
		return 2;
	}
	if (1 != BIO_meth_set_puts(writeBioMethod, go_write_bio_puts)) {
		return 3;
	}
	if (1 != BIO_meth_set_ctrl(writeBioMethod, go_write_bio_ctrl)) {
		return 4;
	}
	if (1 != BIO_meth_set_create(writeBioMethod, x_bio_create)) {
		return 5;
	}
	if (1 != BIO_meth_set_destroy(writeBioMethod, x_bio_free)) {
		return 6;
	}

	readBioMethod = BIO_meth_new(BIO_TYPE_SOURCE_SINK, "Go Read BIO");
	if (!readBioMethod) {
		return 7;
	}
	if (1 != BIO_meth_set_read(readBioMethod, go_read_bio_read)) {
		return 8;
	}
	if (1 != BIO_meth_set_ctrl(readBioMethod, go_read_bio_ctrl)) {
		return 9;
	}
	if (1 != BIO_meth_set_create(readBioMethod, x_bio_create)) {
		return 10;
	}
	if (1 != BIO_meth_set_destroy(readBioMethod, x_bio_free)) {
		return 11;
	}

	return 0;
}

const EVP_MD *X_EVP_dss() {
	return NULL;
}

const EVP_MD *X_EVP_dss1() {
	return NULL;
}

const EVP_MD *X_EVP_sha() {
	return NULL;
}

int X_SSL_CTX_set_min_proto_version(SSL_CTX *ctx, long version) {
	return SSL_CTX_set_min_proto_version(ctx, version);
}

int X_SSL_CTX_set_max_proto_version(SSL_CTX *ctx, long version) {
	return SSL_CTX_set_max_proto_version(ctx, version);
}

/*
 ************************************************
 * common implementation
 ************************************************
 */

int X_shim_init() {
	return  x_bio_init_methods();
}

void * X_OPENSSL_malloc(size_t size) {
	return OPENSSL_malloc(size);
}

void X_OPENSSL_free(void *ref) {
	OPENSSL_free(ref);
}

long X_SSL_set_tlsext_host_name(SSL *ssl, const char *name) {
	return SSL_set_tlsext_host_name(ssl, name);
}
const char * X_SSL_get_cipher_name(const SSL *ssl) {
	return SSL_get_cipher_name(ssl);
}

int X_SSL_new_index() {
	return SSL_get_ex_new_index(0, NULL, NULL, NULL, go_ssl_crypto_ex_free);
}

int X_SSL_verify_cb(int ok, X509_STORE_CTX* store) {
	SSL* ssl = (SSL *)X509_STORE_CTX_get_ex_data(store,
			SSL_get_ex_data_X509_STORE_CTX_idx());
	void* p = SSL_get_ex_data(ssl, get_ssl_idx());
	// get the pointer to the go Ctx object and pass it back into the thunk
	return go_ssl_verify_cb_thunk(p, ok, store);
}

int X_SSL_CTX_new_index() {
	return SSL_CTX_get_ex_new_index(0, NULL, NULL, NULL, NULL);
}

long X_SSL_CTX_set_mode(SSL_CTX* ctx, long modes) {
	return SSL_CTX_set_mode(ctx, modes);
}

long X_SSL_CTX_get_mode(SSL_CTX* ctx) {
	return SSL_CTX_get_mode(ctx);
}

long X_SSL_CTX_set_session_cache_mode(SSL_CTX* ctx, long modes) {
	return SSL_CTX_set_session_cache_mode(ctx, modes);
}

long X_SSL_CTX_sess_set_cache_size(SSL_CTX* ctx, long t) {
	return SSL_CTX_sess_set_cache_size(ctx, t);
}

long X_SSL_CTX_sess_get_cache_size(SSL_CTX* ctx) {
	return SSL_CTX_sess_get_cache_size(ctx);
}

long X_SSL_CTX_add_extra_chain_cert(SSL_CTX* ctx, X509 *cert) {
	return SSL_CTX_add_extra_chain_cert(ctx, cert);
}

int X_SSL_CTX_set1_curves(SSL_CTX *ctx, int *clist, int clistlen) {
	return SSL_CTX_set1_curves(ctx, clist, clistlen);
}

long X_SSL_CTX_set_tlsext_servername_callback(
		SSL_CTX* ctx, int (*cb)(SSL *con, int *ad, void *args)) {
	return SSL_CTX_set_tlsext_servername_callback(ctx, cb);
}

int X_SSL_CTX_verify_cb(int ok, X509_STORE_CTX* store) {
	SSL* ssl = (SSL *)X509_STORE_CTX_get_ex_data(store,
			SSL_get_ex_data_X509_STORE_CTX_idx());
	SSL_CTX* ssl_ctx = SSL_get_SSL_CTX(ssl);
	void* p = SSL_CTX_get_ex_data(ssl_ctx, get_ssl_ctx_idx());
	// get the pointer to the go Ctx object and pass it back into the thunk
	return go_ssl_ctx_verify_cb_thunk(p, ok, store);
}

int X_SSL_CTX_set1_groups_list(SSL_CTX *ctx, void *s) {
	return SSL_CTX_set1_groups_list(ctx, s);
}


BIO *X_BIO_new_write_bio() {
	return BIO_new(BIO_s_writeBio());
}

BIO *X_BIO_new_read_bio() {
	return BIO_new(BIO_s_readBio());
}

const EVP_MD *X_EVP_md_null() {
	return EVP_md_null();
}

const EVP_MD *X_EVP_md5() {
	return EVP_md5();
}

const EVP_MD *X_EVP_ripemd160() {
	return EVP_ripemd160();
}

const EVP_MD *X_EVP_sha224() {
	return EVP_sha224();
}

const EVP_MD *X_EVP_sha1() {
	return EVP_sha1();
}

const EVP_MD *X_EVP_sha256() {
	return EVP_sha256();
}

const EVP_MD *X_EVP_sha384() {
	return EVP_sha384();
}

const EVP_MD *X_EVP_sha512() {
	return EVP_sha512();
}

int X_sk_X509_num(STACK_OF(X509) *sk) {
	return sk_X509_num(sk);
}

X509 *X_sk_X509_value(STACK_OF(X509)* sk, int i) {
	return sk_X509_value(sk, i);
}

int X_BN_num_bytes(const BIGNUM *a) {
	return BN_num_bytes(a);
}
