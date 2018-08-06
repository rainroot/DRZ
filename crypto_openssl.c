#include <rain_common.h>

#ifdef OPENSSL_CONF
#include <openssl/objects.h>
#include <openssl/evp.h>
#include <openssl/des.h>

static bool engine_initialized = false;
static ENGINE *engine_persist = NULL;


ENGINE * try_load_engine (const char *engine)
{
	ENGINE *e = ENGINE_by_id ("dynamic");
	if (e)
	{
		if (!ENGINE_ctrl_cmd_string (e, "SO_PATH", engine, 0)
				|| !ENGINE_ctrl_cmd_string (e, "LOAD", NULL, 0))
		{
			ENGINE_free (e);
			e = NULL;
		}
	}
	return e;
}

ENGINE * setup_engine (const char *engine)
{
	ENGINE *e = NULL;
	ENGINE_load_builtin_engines ();
	if (engine)
	{
		if (strcmp (engine, "auto") == 0)
		{
			MM("Initializing OpenSSL auto engine support\n");
			ENGINE_register_all_complete ();
			return NULL;
		}
		if ((e = ENGINE_by_id (engine)) == NULL && (e = try_load_engine (engine)) == NULL)
		{
			MM("OpenSSL error: cannot load engine '%s'\n", engine);
		}

		if (!ENGINE_set_default (e, ENGINE_METHOD_ALL))
		{
			MM("OpenSSL error: ENGINE_set_default failed on engine '%s'\n", engine);
		}

		MM("Initializing OpenSSL support for engine '%s'\n",ENGINE_get_id (e));
	}
	return e;
}

void crypto_init_lib (void)
{
	ERR_load_crypto_strings ();
	OpenSSL_add_all_algorithms ();

}

void crypto_uninit_lib (void)
{
	EVP_cleanup ();
	ERR_free_strings ();

	if (engine_initialized)
	{
		ENGINE_cleanup ();
		engine_persist = NULL;
		engine_initialized = false;
	}
}

void crypto_clear_error (void)
{
	ERR_clear_error ();
}


int rand_bytes(uint8_t *output, int len)
{
	return RAND_bytes (output, len);
}


const EVP_MD * md_kt_get (const char *digest)
{
	const EVP_MD *md = NULL;
	assert(digest);
	md = EVP_get_digestbyname (digest);
	if (!md){
		MM("Message hash algorithm '%s' not found\n", digest);
	}
	if (EVP_MD_size (md) > MAX_HMAC_KEY_LENGTH){
		MM("Message hash algorithm '%s' uses a default hash size (%d bytes) which is larger than Drizzle VPN current maximum hash size (%d bytes)\n",
		     digest,
		     EVP_MD_size (md),
		     MAX_HMAC_KEY_LENGTH);
	}
	return md;
}

const char * md_kt_name (const EVP_MD *kt)
{
	if (NULL == kt){
		return "[null-digest]";
	}
	return EVP_MD_name (kt);
}

int md_kt_size (const EVP_MD *kt)
{
	return EVP_MD_size(kt);
}


int md_full (const EVP_MD *kt, const uint8_t *src, int src_len, uint8_t *dst)
{
	unsigned int in_md_len = 0;
	return EVP_Digest(src, src_len, dst, &in_md_len, kt, NULL);
}

void md_ctx_init (EVP_MD_CTX *ctx, const EVP_MD *kt)
{
	assert(NULL != ctx && NULL != kt);
	memset(ctx,0x00,sizeof(EVP_MD_CTX));
	EVP_MD_CTX_init (ctx);
	EVP_DigestInit(ctx, kt);
}

void md_ctx_cleanup(EVP_MD_CTX *ctx)
{
	EVP_MD_CTX_cleanup(ctx);
}

int md_ctx_size (const EVP_MD_CTX *ctx)
{
	return EVP_MD_CTX_size(ctx);
}

void md_ctx_update (EVP_MD_CTX *ctx, const uint8_t *src, int src_len)
{
	EVP_DigestUpdate(ctx, src, src_len);
}

void md_ctx_final (EVP_MD_CTX *ctx, uint8_t *dst)
{
	unsigned int in_md_len = 0;
	EVP_DigestFinal(ctx, dst, &in_md_len);
}



int key_des_num_cblocks (const EVP_CIPHER *kt)
{
	int ret = 0;
	const char *name = OBJ_nid2sn (EVP_CIPHER_nid (kt));
	if (name)
	{
		if (!strncmp (name, "DES-", 4))
		{
			ret = EVP_CIPHER_key_length (kt) / sizeof (DES_cblock);
		}
		else if (!strncmp (name, "DESX-", 5))
		{
			ret = 1;
		}
	}
	return ret;
}

bool key_des_check (uint8_t *key, int key_len, int ndc)
{
	int i;

	if(key_len){}

	for (i = 0; i < ndc; ++i)
	{
		if(i > 0){
			key += sizeof(DES_cblock);
		}
		DES_cblock *dc = (DES_cblock*)(key);

		if (!dc)
		{
			MM("ERR: CRYPTO INFO: check_key_DES: insufficient key material \n");
			goto err;
		}
		if (DES_is_weak_key(dc))
		{
			MM("ERR: CRYPTO INFO: check_key_DES: weak key detected \n");
			goto err;
		}
		if (!DES_check_key_parity (dc))
		{
			MM("ERR: CRYPTO INFO: check_key_DES: bad parity detected \n");
			goto err;
		}
	}

	return true;

err:
	ERR_clear_error ();
	return false;
}

void key_des_fixup (uint8_t *key, int key_len, int ndc)
{
	int i;
	if(key_len){}
	for (i = 0; i < ndc; ++i)
	{
		if( i > 0){
			key += sizeof(DES_cblock);
		}
		DES_cblock *dc = (DES_cblock*)(key);
		if (!dc)
		{
			MM("ERR: CRYPTO INFO: fixup_key_DES: insufficient key material \n");
			ERR_clear_error ();
			return;
		}
		DES_set_odd_parity (dc);
	}
}


void crypto_init_lib_engine (const char *engine_name)
{
	if (!engine_initialized)
	{
		assert (engine_name);
		assert (!engine_persist);
		engine_persist = setup_engine (engine_name);
		engine_initialized = true;
	}
}

const char * translate_cipher_name_from_openvpn (const char *cipher_name) {
	return cipher_name;
}

const char * translate_cipher_name_to_openvpn (const char *cipher_name) {
	return cipher_name;
}

EVP_CIPHER * cipher_kt_get (const char *ciphername)
{
	EVP_CIPHER *cipher = NULL;

	assert (ciphername);

	cipher = (EVP_CIPHER *)EVP_get_cipherbyname (ciphername);

	if ((NULL == cipher) || !(OBJ_nid2sn (EVP_CIPHER_nid (cipher)))){
		MM("## ERR:  Cipher algorithm '%s' not found\n", ciphername);
		exit(0);
	}

	if (EVP_CIPHER_key_length (cipher) > MAX_CIPHER_KEY_LENGTH){

		MM("## ERR: %s %d ##\n",__func__,__LINE__);
		exit(0);
	}

	return cipher;
}

const char * cipher_kt_name (const EVP_CIPHER *cipher_kt)
{
	if (NULL == cipher_kt){
		return "[null-cipher]";
	}

	return EVP_CIPHER_name (cipher_kt);
}

int cipher_kt_key_size (EVP_CIPHER *cipher_kt)
{
	int ret=0;
	ret = EVP_CIPHER_key_length (cipher_kt);
	return ret;
}

int cipher_kt_iv_size (const EVP_CIPHER *cipher_kt)
{
	return EVP_CIPHER_iv_length (cipher_kt);
}

int cipher_kt_block_size (const EVP_CIPHER *cipher_kt)
{
	return EVP_CIPHER_block_size (cipher_kt);
}

int cipher_kt_mode (const EVP_CIPHER *cipher_kt)
{
	assert(NULL != cipher_kt);
	return EVP_CIPHER_mode (cipher_kt);
}





void cipher_ctx_init (EVP_CIPHER_CTX *ctx, uint8_t *key, int key_len, const EVP_CIPHER *kt, int enc)
{
	assert(NULL != kt && NULL != ctx);

	EVP_CIPHER_CTX_init (ctx);
	if (!EVP_CipherInit_ov (ctx, kt, NULL, NULL, enc)){
		MM( "EVP cipher init #1 \n");
	}
#if 0
#ifdef HAVE_EVP_CIPHER_CTX_SET_KEY_LENGTH
	if (!EVP_CIPHER_CTX_set_key_length (ctx, key_len)){
		printf( "EVP set key size");
	}
#endif
#endif
	//if (!EVP_CipherInit_ov (ctx, NULL, key, NULL, enc)){
	if (!EVP_CipherInit(ctx, NULL, key, NULL, enc)){
		MM("EVP cipher init #2 \n");
	}
	assert (EVP_CIPHER_CTX_key_length (ctx) <= key_len);
}

void cipher_ctx_cleanup (EVP_CIPHER_CTX *ctx)
{
	EVP_CIPHER_CTX_cleanup (ctx);
}

int cipher_ctx_iv_length (const EVP_CIPHER_CTX *ctx)
{
	return EVP_CIPHER_CTX_iv_length (ctx);
}

int cipher_ctx_block_size(const EVP_CIPHER_CTX *ctx)
{
	return EVP_CIPHER_CTX_block_size (ctx);
}

int cipher_ctx_mode (const EVP_CIPHER_CTX *ctx)
{
	return EVP_CIPHER_CTX_mode (ctx);
}

int cipher_ctx_reset (EVP_CIPHER_CTX *ctx, uint8_t *iv_buf)
{
	//return EVP_CipherInit_ov (ctx, NULL, NULL, iv_buf, -1);
	return EVP_CipherInit(ctx, NULL, NULL, iv_buf, -1);
}

int cipher_ctx_update (EVP_CIPHER_CTX *ctx, uint8_t *dst, int *dst_len, uint8_t *src, int src_len)
{
	//return EVP_CipherUpdate_ov (ctx, dst, dst_len, src, src_len);
	return EVP_CipherUpdate(ctx, dst, dst_len, src, src_len);
}

int cipher_ctx_final (EVP_CIPHER_CTX *ctx, uint8_t *dst, int *dst_len)
{
	return EVP_CipherFinal (ctx, dst, dst_len);
}


void hmac_ctx_init (HMAC_CTX *ctx, const uint8_t *key, int key_len, const EVP_MD *kt)
{
	assert(NULL != kt && NULL != ctx);
	HMAC_CTX_init (ctx);
	HMAC_Init_ex (ctx, key, key_len, kt, NULL);
	assert (HMAC_size (ctx) <= key_len);
}

void hmac_ctx_cleanup(HMAC_CTX *ctx)
{
	if(ctx != NULL){
		HMAC_CTX_cleanup (ctx);
	}else{
		printf("## ERR: EXIT %s %d ##\n",__func__,__LINE__);
		exit(0);
	}
}

int hmac_ctx_size (const HMAC_CTX *ctx)
{
	return HMAC_size (ctx);
}

void hmac_ctx_reset (HMAC_CTX *ctx)
{
	HMAC_Init_ex (ctx, NULL, 0, NULL, NULL);
}

void hmac_ctx_update (HMAC_CTX *ctx, const uint8_t *src, int src_len)
{
	HMAC_Update (ctx, src, src_len);
}

void hmac_ctx_final (HMAC_CTX *ctx, uint8_t *dst)
{
	unsigned int in_hmac_len = 0;

	HMAC_Final (ctx, dst, &in_hmac_len);
}

inline int EVP_CipherInit_ov (EVP_CIPHER_CTX *ctx, const EVP_CIPHER *type, uint8_t *key, uint8_t *iv, int enc)
{
	return EVP_CipherInit (ctx, type, key, iv, enc);
}

inline int EVP_CipherUpdate_ov (EVP_CIPHER_CTX *ctx, uint8_t *out, int *outl, uint8_t *in, int inl)
{
	return EVP_CipherUpdate (ctx, out, outl, in, inl);
}
#endif
