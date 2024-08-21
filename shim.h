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

#include <stdlib.h>
#include <string.h>
#include <inttypes.h>

#include <openssl/core_names.h>
#include <openssl/bio.h>
#include <openssl/crypto.h>
#include <openssl/dh.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/x509v3.h>
#include <openssl/ec.h>


/* shim  methods */
extern int X_shim_init();

/* Library methods */
extern void X_OPENSSL_free(void *ref);
extern void *X_OPENSSL_malloc(size_t size);

/* SSL macros */
extern long X_SSL_set_tlsext_host_name(SSL *ssl, const char *name);
extern const char * X_SSL_get_cipher_name(const SSL *ssl);
extern int X_SSL_new_index();

/* SSL methods */
extern int sni_cb(SSL *ssl_conn, int *ad, void *arg);
extern int X_SSL_verify_cb(int ok, X509_STORE_CTX* store);

/* SSL_CTX macros */
extern int X_SSL_CTX_new_index();
extern int X_SSL_CTX_set_min_proto_version(SSL_CTX *ctx, long version);
extern int X_SSL_CTX_set_max_proto_version(SSL_CTX *ctx, long version);
extern long X_SSL_CTX_set_mode(SSL_CTX* ctx, long modes);
extern long X_SSL_CTX_get_mode(SSL_CTX* ctx);
extern long X_SSL_CTX_set_session_cache_mode(SSL_CTX* ctx, long modes);
extern long X_SSL_CTX_sess_set_cache_size(SSL_CTX* ctx, long t);
extern long X_SSL_CTX_sess_get_cache_size(SSL_CTX* ctx);
extern int X_SSL_CTX_set1_curves(SSL_CTX *ctx, int *clist, int clistlen);
extern long X_SSL_CTX_add_extra_chain_cert(SSL_CTX* ctx, X509 *cert);
extern long X_SSL_CTX_set_tlsext_servername_callback(SSL_CTX* ctx, int (*cb)(SSL *con, int *ad, void *args));
extern int X_SSL_CTX_set1_groups_list(SSL_CTX* ctx, char *s);

/* SSL_CTX methods */
extern int X_SSL_CTX_verify_cb(int ok, X509_STORE_CTX* store);

/* BIO methods */
extern BIO *X_BIO_new_write_bio();
extern BIO *X_BIO_new_read_bio();

/* EVP methods */
extern const EVP_MD *X_EVP_md_null();
extern const EVP_MD *X_EVP_md5();
extern const EVP_MD *X_EVP_sha();
extern const EVP_MD *X_EVP_sha1();
extern const EVP_MD *X_EVP_dss();
extern const EVP_MD *X_EVP_dss1();
extern const EVP_MD *X_EVP_ripemd160();
extern const EVP_MD *X_EVP_sha224();
extern const EVP_MD *X_EVP_sha256();
extern const EVP_MD *X_EVP_sha384();
extern const EVP_MD *X_EVP_sha512();

/* X509 methods */
extern int X_sk_X509_num(STACK_OF(X509) *sk);
extern X509 *X_sk_X509_value(STACK_OF(X509)* sk, int i);

/* Object methods */
extern int OBJ_create(const char *oid,const char *sn,const char *ln);

/* Extension helper method */
extern const unsigned char * get_extension(X509 *x, int NID, int *data_len);
extern int add_custom_ext(X509 *cert, int nid, char *value, int len);

/* BigNum macros */
extern int X_BN_num_bytes(const BIGNUM *a);
