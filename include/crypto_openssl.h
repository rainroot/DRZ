#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/md5.h>

struct key_type;

typedef EVP_CIPHER cipher_kt_t;
typedef EVP_MD md_kt_t;
typedef EVP_CIPHER_CTX cipher_ctx_t;
typedef EVP_MD_CTX md_ctx_t;
typedef HMAC_CTX hmac_ctx_t;


#define OPENVPN_MAX_IV_LENGTH		EVP_MAX_IV_LENGTH
#define OPENVPN_MODE_CBC			EVP_CIPH_CBC_MODE
#define OPENVPN_MODE_OFB			EVP_CIPH_OFB_MODE
#define OPENVPN_MODE_CFB			EVP_CIPH_CFB_MODE
#define OPENVPN_OP_ENCRYPT			1
#define OPENVPN_OP_DECRYPT			0
#define DES_KEY_LENGTH				8
#define MD4_DIGEST_LENGTH			16

#include <openssl/engine.h>
ENGINE *try_load_engine (const char *engine);
ENGINE *setup_engine (const char *engine);

void crypto_init_lib (void);
void crypto_uninit_lib (void);
void crypto_clear_error (void);

int rand_bytes(uint8_t *output, int len);

const EVP_MD * md_kt_get (const char *digest);
const char * md_kt_name (const EVP_MD *kt);
int md_kt_size (const EVP_MD *kt);
void show_available_ciphers ();
void show_available_engines ();
void show_available_digests ();
int md_full (const EVP_MD *kt, const uint8_t *src, int src_len, uint8_t *dst);
int key_des_num_cblocks (const EVP_CIPHER *kt);
bool key_des_check (uint8_t *key, int key_len, int ndc);
void key_des_fixup (uint8_t *key, int key_len, int ndc);
void crypto_init_lib_engine (const char *engine_name);
//EVP_CIPHER * cipher_kt_get (const char *ciphername,struct key_type *kt);
const char * translate_cipher_name_from_openvpn (const char *cipher_name);
int cipher_kt_key_size (EVP_CIPHER *cipher_kt);
int cipher_kt_mode (const EVP_CIPHER *cipher_kt);
void cipher_ctx_init (EVP_CIPHER_CTX *ctx, uint8_t *key, int key_len, const EVP_CIPHER *kt, int enc);
const char * cipher_kt_name (const EVP_CIPHER *cipher_kt);
int cipher_kt_block_size (const EVP_CIPHER *cipher_kt);
int cipher_kt_iv_size (const EVP_CIPHER *cipher_kt);
void hmac_ctx_init (HMAC_CTX *ctx, const uint8_t *key, int key_len, const EVP_MD *kt);
int hmac_ctx_size (const HMAC_CTX *ctx);
int cipher_ctx_iv_length (const EVP_CIPHER_CTX *ctx);
int cipher_ctx_mode (const EVP_CIPHER_CTX *ctx);
int cipher_ctx_reset (EVP_CIPHER_CTX *ctx, uint8_t *iv_buf);
int cipher_ctx_update (EVP_CIPHER_CTX *ctx, uint8_t *dst, int *dst_len, uint8_t *src, int src_len);
int cipher_ctx_final (EVP_CIPHER_CTX *ctx, uint8_t *dst, int *dst_len);
void hmac_ctx_reset (HMAC_CTX *ctx);
void hmac_ctx_update (HMAC_CTX *ctx, const uint8_t *src, int src_len);
void hmac_ctx_final (HMAC_CTX *ctx, uint8_t *dst);
void hmac_ctx_cleanup(HMAC_CTX *ctx);
inline int EVP_CipherInit_ov (EVP_CIPHER_CTX *ctx, const EVP_CIPHER *type, uint8_t *key, uint8_t *iv, int enc);
inline int EVP_CipherUpdate_ov (EVP_CIPHER_CTX *ctx, uint8_t *out, int *outl, uint8_t *in, int inl);
EVP_CIPHER * cipher_kt_get (const char *ciphername);
void cipher_ctx_cleanup (EVP_CIPHER_CTX *ctx);
