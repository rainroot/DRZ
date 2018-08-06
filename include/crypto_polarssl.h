#include <polarssl/cipher.h>
#include <polarssl/md.h>
#include <polarssl/ctr_drbg.h>

#include <polarssl/des.h>
#include <polarssl/error.h>
#include <polarssl/md5.h>
#include <polarssl/cipher.h>
#include <polarssl/havege.h>

#include <polarssl/entropy.h>


typedef cipher_info_t cipher_kt_t;
typedef md_info_t md_kt_t;
typedef cipher_context_t cipher_ctx_t;
typedef md_context_t md_ctx_t;
typedef md_context_t hmac_ctx_t;

#define OPENVPN_MAX_IV_LENGTH    POLARSSL_MAX_IV_LENGTH
#define OPENVPN_MODE_CBC   POLARSSL_MODE_CBC
#define OPENVPN_MODE_OFB   POLARSSL_MODE_OFB
#define OPENVPN_MODE_CFB   POLARSSL_MODE_CFB
#define OPENVPN_OP_ENCRYPT    POLARSSL_ENCRYPT
#define OPENVPN_OP_DECRYPT    POLARSSL_DECRYPT

#define MD4_DIGEST_LENGTH  16
#define MD5_DIGEST_LENGTH  16
#define SHA_DIGEST_LENGTH  20
#define DES_KEY_LENGTH 8


#define polar_ok(errval) \
			   polar_log_func_line_lite (0,1, __func__, __LINE__)

ctr_drbg_context *  rand_ctx_get () ;
const char * cipher_kt_name (const cipher_info_t *cipher_kt);
bool cipher_kt_mode_cbc(const cipher_kt_t *cipher);
bool polar_log_func_line_lite(unsigned int flags, int errval, const char *func, int line);
int rand_bytes(uint8_t *output, int len);
void crypto_init_lib (void);
int md_kt_size (const md_info_t *kt);
void hmac_ctx_init (md_context_t *ctx, const uint8_t *key, int key_len, const md_info_t *kt);
void hmac_ctx_update (md_context_t *ctx, const uint8_t *src, int src_len);
void hmac_ctx_final (md_context_t *ctx, uint8_t *dst);
void hmac_ctx_reset (md_context_t *ctx);
void hmac_ctx_cleanup(md_context_t *ctx);
const md_info_t * md_kt_get (const char *digest);
cipher_info_t * cipher_kt_get (const char *ciphername);
const char * translate_cipher_name_from_openvpn (const char *cipher_name);
int cipher_kt_key_size (const cipher_info_t *cipher_kt);
int cipher_kt_mode (const cipher_info_t *cipher_kt);
void cipher_ctx_init (cipher_context_t *ctx, uint8_t *key, int key_len, const cipher_info_t *kt, int enc);
void cipher_ctx_cleanup (cipher_context_t *ctx);
int key_des_num_cblocks (const cipher_info_t *kt);
bool key_des_check (uint8_t *key, int key_len, int ndc);
void key_des_fixup (uint8_t *key, int key_len, int ndc);
int hmac_ctx_size (const md_context_t *ctx);
int cipher_ctx_mode (const cipher_context_t *ctx);
int cipher_ctx_iv_length (const cipher_context_t *ctx);
int cipher_ctx_reset (cipher_context_t *ctx, uint8_t *iv_buf);
int cipher_ctx_update (cipher_context_t *ctx, uint8_t *dst, int *dst_len, uint8_t *src, int src_len);
int cipher_ctx_final (cipher_context_t *ctx, uint8_t *dst, int *dst_len);
bool polar_log_err(unsigned int flags, int errval, const char *prefix);
int cipher_kt_block_size (const cipher_info_t *cipher_kt);
const char * md_kt_name (const md_info_t *kt);







