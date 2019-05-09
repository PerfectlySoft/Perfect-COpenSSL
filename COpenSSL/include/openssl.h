
#ifndef _COPENSSL_H_
#define _COPENSSL_H_

#include "../conf.h"
#include "../ssl.h"
#include "../err.h"
#include "../x509.h"
#include "../x509v3.h"
#include "../sha.h"
#include "../md5.h"
#include "../bio.h"
#include "../hmac.h"
#include "../rand.h"
#include "../cms.h"
#include "../evp.h"

static int copenssl_EVP_MD_size(const EVP_MD *md) {
	return EVP_MD_size(md);
}
static int copenssl_EVP_CIPHER_block_size(const EVP_CIPHER *cipher) {
	return EVP_CIPHER_block_size(cipher);
}
static int copenssl_EVP_CIPHER_key_length(const EVP_CIPHER *cipher) {
	return EVP_CIPHER_key_length(cipher);
}
static int copenssl_EVP_CIPHER_iv_length(const EVP_CIPHER *cipher) {
	return EVP_CIPHER_iv_length(cipher);
}
static EVP_MD_CTX * copenssl_EVP_MD_CTX_create() {
	return EVP_MD_CTX_create();
}

static void copenssl_EVP_MD_CTX_destroy(EVP_MD_CTX * ctx) {
	EVP_MD_CTX_destroy(ctx);
}

static void copenssl_ERR_load_crypto_strings() {
	ERR_load_crypto_strings();
}

static void copenssl_OPENSSL_add_all_algorithms_conf() {
	OPENSSL_add_all_algorithms_conf();
}

#if OPENSSL_VERSION_NUMBER >= 0x10100000L
#undef CRYPTO_set_locking_callback
static void CRYPTO_set_locking_callback(void (*func) (int mode, int type,
													  const char *file, int line)) {}
#undef CRYPTO_num_locks
static int CRYPTO_num_locks(void) {
	return 0;
}
#undef CRYPTO_set_id_callback
static void CRYPTO_set_id_callback(unsigned long (*func) (void)) {}
struct bio_method_st {};
struct asn1_object_st {};

struct ASN1_ITEM_st {};
struct asn1_pctx_st {};
struct asn1_sctx_st {};

struct dane_st {};
struct bio_st {};
struct bignum_st {};
struct bignum_ctx {};
struct bn_blinding_st {};
struct bn_mont_ctx_st {};
struct bn_recp_ctx_st {};
struct bn_gencb_st {};

struct evp_cipher_st {};
struct evp_cipher_ctx_st {};
struct evp_md_st {};
struct evp_md_ctx_st {};
struct evp_pkey_st {};

struct evp_pkey_asn1_method_st {};

struct evp_pkey_method_st {};
struct evp_pkey_ctx_st {};

struct evp_Encode_Ctx_st {};

struct hmac_ctx_st {};

struct dh_st {};
struct dh_method {};

struct dsa_st {};
struct dsa_method {};

struct rsa_st {};
struct rsa_meth_st {};

struct ec_key_st {};
struct ec_key_method_st {};

struct ssl_dane_st {};
struct x509_st {};
struct X509_crl_st {};
struct x509_crl_method_st {};
struct x509_revoked_st {};
struct X509_name_st {};
struct X509_pubkey_st {};
struct x509_store_st {};
struct x509_store_ctx_st {};

struct x509_object_st {};
struct x509_lookup_st {};
struct x509_lookup_method_st {};
struct X509_VERIFY_PARAM_st {};

struct pkcs8_priv_key_info_st {};

struct ossl_init_settings_st {};

struct ui_st {};
struct ui_method_st {};

struct engine_st {};
struct ssl_st {};
struct ssl_ctx_st {};

struct comp_ctx_st {};
struct comp_method_st {};

struct X509_POLICY_NODE_st {};
struct X509_POLICY_LEVEL_st {};
struct X509_POLICY_TREE_st {};
struct X509_POLICY_CACHE_st {};

struct ocsp_req_ctx_st {};
struct ocsp_response_st {};
struct ocsp_responder_id_st {};

struct sct_st {};
struct sct_ctx_st {};
struct ctlog_st {};
struct ctlog_store_st {};
struct ct_policy_eval_ctx_st {};

#endif

#endif
