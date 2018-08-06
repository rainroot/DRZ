
#include <mbedtls/cipher_internal.h>
#include <mbedtls/cipher.h>
#include <mbedtls/md_internal.h>
#include <mbedtls/md.h>
#include <mbedtls/ctr_drbg.h>

#include <mbedtls/des.h>
#include <mbedtls/error.h>
#include <mbedtls/md5.h>
#include <mbedtls/cipher.h>
#include <mbedtls/havege.h>

#include <mbedtls/sha256.h>
#include <mbedtls/entropy.h>
#include <mbedtls/certs.h>


typedef mbedtls_cipher_info_t cipher_kt_t;
typedef mbedtls_md_info_t md_kt_t;
typedef mbedtls_cipher_context_t cipher_ctx_t;
typedef mbedtls_md_context_t md_ctx_t;
typedef mbedtls_md_context_t hmac_ctx_t;

#define OPENVPN_MAX_IV_LENGTH    MBEDTLS_MAX_IV_LENGTH
#define OPENVPN_MODE_CBC   	MBEDTLS_MODE_CBC
#define OPENVPN_MODE_OFB   	MBEDTLS_MODE_OFB
#define OPENVPN_MODE_CFB 	   MBEDTLS_MODE_CFB
#define OPENVPN_MODE_GCM      MBEDTLS_MODE_GCM
#define OPENVPN_OP_ENCRYPT    MBEDTLS_ENCRYPT
#define OPENVPN_OP_DECRYPT    MBEDTLS_DECRYPT

#define MD4_DIGEST_LENGTH  16
#define MD5_DIGEST_LENGTH  16
#define SHA_DIGEST_LENGTH  20
#define DES_KEY_LENGTH 8


#define polar_ok(errval) \
			   polar_log_func_line_lite (0,1, __func__, __LINE__)

mbedtls_ctr_drbg_context *  rand_ctx_get () ;
const char * cipher_kt_name (const mbedtls_cipher_info_t *cipher_kt);
bool cipher_kt_mode_cbc(const cipher_kt_t *cipher);
bool polar_log_func_line_lite(unsigned int flags, int errval, const char *func, int line);
int rand_bytes(uint8_t *output, int len);
void crypto_init_lib (void);
int md_kt_size (const mbedtls_md_info_t *kt);
void hmac_ctx_init (mbedtls_md_context_t *ctx, const uint8_t *key, int key_len, const mbedtls_md_info_t *kt);
void hmac_ctx_update (mbedtls_md_context_t *ctx, const uint8_t *src, int src_len);
void hmac_ctx_final (mbedtls_md_context_t *ctx, uint8_t *dst);
void hmac_ctx_reset (mbedtls_md_context_t *ctx);
void hmac_ctx_cleanup(mbedtls_md_context_t *ctx);
const mbedtls_md_info_t * md_kt_get (const char *digest);
mbedtls_cipher_info_t * cipher_kt_get (const char *ciphername);
const char * translate_cipher_name_from_openvpn (const char *cipher_name);
int cipher_kt_key_size (const mbedtls_cipher_info_t *cipher_kt);
int cipher_kt_mode (const mbedtls_cipher_info_t *cipher_kt);
void cipher_ctx_init (mbedtls_cipher_context_t *ctx, uint8_t *key, int key_len, const mbedtls_cipher_info_t *kt, int enc);
void cipher_ctx_cleanup (mbedtls_cipher_context_t *ctx);
int key_des_num_cblocks (const mbedtls_cipher_info_t *kt);
bool key_des_check (uint8_t *key, int key_len, int ndc);
void key_des_fixup (uint8_t *key, int key_len, int ndc);
int hmac_ctx_size (const mbedtls_md_context_t *ctx);
int cipher_ctx_mode (const mbedtls_cipher_context_t *ctx);
int cipher_ctx_iv_length (const mbedtls_cipher_context_t *ctx);
int cipher_ctx_reset (mbedtls_cipher_context_t *ctx, uint8_t *iv_buf);
int cipher_ctx_update (mbedtls_cipher_context_t *ctx, uint8_t *dst, int *dst_len, uint8_t *src, int src_len);
int cipher_ctx_final (mbedtls_cipher_context_t *ctx, uint8_t *dst, int *dst_len);
bool polar_log_err(unsigned int flags, int errval, const char *prefix);
int cipher_kt_block_size (const mbedtls_cipher_info_t *cipher_kt);
const char * md_kt_name (const mbedtls_md_info_t *kt);







