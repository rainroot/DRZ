#include <rain_common.h>

#ifdef MBEDTLS_CONF

char * time_string (time_t t, int usec, bool show_usec)
{
	struct timeval tv;
	char *out = malloc(64);
	memset(out,0x00,64);
	if (t)
	{
		tv.tv_sec = t;
		tv.tv_usec = usec;
	}
	else
	{
		gettimeofday (&tv, NULL);
	}

	t = tv.tv_sec;
	snprintf(out,strlen(ctime(&t))-1,"%s",ctime(&t));

	if (show_usec && tv.tv_usec){
		sprintf(out,"%s us=%d",out,(int)tv.tv_usec);
	}
	return out;
}

void crypto_init_lib_engine (const char *engine_name)
{
	if(engine_name){}
	MM("Note: PolarSSL hardware crypto engine functionality is not " "available \n");
}

void crypto_init_lib (void)
{
}

void crypto_uninit_lib (void)
{
}

void crypto_clear_error (void)
{
}
#if 1
bool mbedtls_log_err(unsigned int flags, int errval, const char *prefix)
{
	if(flags){}

	if (0 != errval)
	{
		char errstr[256];
		mbedtls_strerror(errval, errstr, sizeof(errstr));

		if (NULL == prefix){
		  	prefix = "PolarSSL error";
		}
		MM("%s: %s \n", prefix, errstr);
	}

	return 0 == errval;
}

bool mbedtls_log_func_line(unsigned int flags, int errval, const char *func, int line)
{
	char prefix[256];
	if(flags){}

	if (!snprintf(prefix, sizeof(prefix), "%s:%d", func, line)){
		return mbedtls_log_err(flags, errval, func);
	}

	return mbedtls_log_err(flags, errval, prefix);
}

bool mbedtls_log_func_line_lite(unsigned int flags, int errval, const char *func, int line) 
{
	if(flags){}
	if(errval){}
	if(func){}
	if(line){}

#if 0
	if (errval) {
		return polar_log_func_line (flags, errval, func, line);
	}
	return true;
#else

	return true;
#endif
}


#endif

typedef struct { 
	const char * openvpn_name; 
	const char * polarssl_name; 
}cipher_name_pair;

cipher_name_pair cipher_name_translation_table[] = {
	{ "BF-CBC", "BLOWFISH-CBC" },
	{ "BF-CFB", "BLOWFISH-CFB64" },
	{ "CAMELLIA-128-CFB", "CAMELLIA-128-CFB128" },
	{ "CAMELLIA-192-CFB", "CAMELLIA-192-CFB128" },
	{ "CAMELLIA-256-CFB", "CAMELLIA-256-CFB128" }
};

const size_t cipher_name_translation_table_count = sizeof(cipher_name_translation_table) / sizeof(*cipher_name_translation_table);

static void print_cipher(const cipher_kt_t *info)
{

	if (info && (cipher_kt_mode_cbc(info)
#ifdef HAVE_AEAD_CIPHER_MODES
				|| cipher_kt_mode_aead(info)
#endif
				))
	{
		const char *ssl_only = cipher_kt_mode_cbc(info) ? "" : ", TLS client/server mode only";
		const char *var_key_size = info->flags & MBEDTLS_CIPHER_VARIABLE_KEY_LEN ? " by default" : "";

		printf("%s  (%d bit key%s, %d bit block%s)\n", cipher_kt_name(info), cipher_kt_key_size(info) * 8, var_key_size,cipher_kt_block_size(info) * 8, ssl_only);
	}

}

void show_available_ciphers ()
{
	const int *ciphers = mbedtls_cipher_list();

	while (*ciphers != 0)
	{
		const cipher_kt_t *info = mbedtls_cipher_info_from_type(*ciphers);
		if (info && cipher_kt_block_size(info) >= 128/8)
		{
			print_cipher(info);
		}
		ciphers++;
	}

	printf("\nThe following ciphers have a block size of less than 128 bits, \n"
			"and are therefore deprecated.  Do not use unless you have to.\n\n");
	ciphers = mbedtls_cipher_list();
	while (*ciphers != 0)
	{
		const cipher_kt_t *info = mbedtls_cipher_info_from_type(*ciphers);
		if (info && cipher_kt_block_size(info) < 128/8)
		{
			print_cipher(info);
		}
		ciphers++;
	}
	printf("\n");

#if 0
	const int *ciphers = mbedtls_cipher_list();
	while (*ciphers != 0)
	{
		const cipher_kt_t *info = mbedtls_cipher_info_from_type(*ciphers);
		if (info && cipher_kt_block_size(info) >= 128/8)
		{
			print_cipher(info);
		}
		ciphers++;
	}

	printf ("\nThe following ciphers have a block size of less than 128 bits, \n"
			"and are therefore deprecated.  Do not use unless you have to.\n\n");
	ciphers = mbedtls_cipher_list();
	while (*ciphers != 0)
	{
		const cipher_kt_t *info = mbedtls_cipher_info_from_type(*ciphers);
		if (info && cipher_kt_block_size(info) < 128/8)
		{
			print_cipher(info);
		}
		ciphers++;
	}
	printf ("\n");
#endif
}


const cipher_name_pair * get_cipher_name_pair(const char *cipher_name) {
	cipher_name_pair *pair;
	size_t i = 0;

	for (; i < sizeof (cipher_name_translation_table) / sizeof (*cipher_name_translation_table); i++)
	{
		pair = &cipher_name_translation_table[i];
		if (0 == strcmp (cipher_name, pair->openvpn_name) || 0 == strcmp (cipher_name, pair->polarssl_name)){
			return pair;
		}
	}
	return NULL;
}
void show_available_digests ()
{
	const int *digests = mbedtls_md_list();
	while (*digests != 0)
	{
		const mbedtls_md_info_t *info = mbedtls_md_info_from_type(*digests);

		if (info){
			 printf("%s %d bit default key\n", mbedtls_md_get_name(info),mbedtls_md_get_size(info) * 8);
		}
		digests++;
	}
	printf ("\n");
}
void show_available_engines ()
{
	printf ("Sorry, PolarSSL hardware crypto engine functionality is not " "available\n");
}


const char * translate_cipher_name_from_openvpn (const char *cipher_name) {
	const cipher_name_pair *pair = get_cipher_name_pair(cipher_name);

	if (NULL == pair){
		return cipher_name;
	}

	return pair->polarssl_name;
}

const char * translate_cipher_name_to_openvpn (const char *cipher_name) {
	const cipher_name_pair *pair = get_cipher_name_pair(cipher_name);

	if (NULL == pair){
		return cipher_name;
	}

	return pair->openvpn_name;
}



mbedtls_ctr_drbg_context * rand_ctx_get() //rainroot
{

	static mbedtls_entropy_context ec = {0};
	static mbedtls_ctr_drbg_context cd_ctx = {0};
	static bool rand_initialised = false;

	if (!rand_initialised)
	{

		char *pers_string = malloc(100);
		memset(pers_string,0x00,100);
		char *time_str = time_string(0, 0, 0);
		sprintf(pers_string,"OpenVPN %0u %p %s",getpid(), &cd_ctx, time_str);

		mbedtls_entropy_init(&ec);

		mbedtls_ctr_drbg_init(&cd_ctx);

		if (mbedtls_ctr_drbg_seed(&cd_ctx, mbedtls_entropy_func, &ec,pers_string, strlen(pers_string)) < 0)
		{
			MM("Failed to initialize random generator\n");
		}
		free(pers_string);
		free(time_str);
		rand_initialised = true;
	}

	return &cd_ctx;
}

int rand_bytes(uint8_t *output, int len)
{
	mbedtls_ctr_drbg_context *rng_ctx = rand_ctx_get();
	
	while (len > 0)
	{
		const size_t blen = min_int (len, MBEDTLS_CTR_DRBG_MAX_REQUEST);
		if (0 != mbedtls_ctr_drbg_random(rng_ctx, output, blen)){
			return 0;
		}
		output += blen;
		len -= blen;
	}

	return 1;
}


int key_des_num_cblocks (const mbedtls_cipher_info_t *kt)
{
	int ret = 0;
	if (kt->type == MBEDTLS_CIPHER_DES_CBC){
		ret = 1;
	}
	if (kt->type == MBEDTLS_CIPHER_DES_EDE_CBC){
		ret = 2;
	}
	if (kt->type == MBEDTLS_CIPHER_DES_EDE3_CBC){
		ret = 3;
	}

	MM("CRYPTO INFO: n_DES_cblocks=%d \n", ret);
	return ret;
}

bool key_des_check (uint8_t *key, int key_len, int ndc)
{

	int i;

	if(key_len){}

	for (i = 0; i < ndc; ++i)
	{
		if(i > 0){
			key += MBEDTLS_DES_KEY_SIZE;
		}

		if (!key)
		{
			MM("ERR: CRYPTO INFO: check_key_DES: insufficient key material \n");
			goto err;
		}
		if (0 != mbedtls_des_key_check_weak(key))
		{
			MM("ERR: CRYPTO INFO: check_key_DES: weak key detected \n");
			goto err;
		}
		if (0 != mbedtls_des_key_check_key_parity(key))
		{
			MM("ERR: CRYPTO INFO: check_key_DES: bad parity detected \n");
			goto err;
		}
	}
	return true;

err:
	return false;
}

void key_des_fixup (uint8_t *key, int key_len, int ndc)
{
	int i;
	if(key_len){}
	for (i = 0; i < ndc; ++i)
	{
		if( i > 0){
			key += MBEDTLS_DES_KEY_SIZE;
		}
		if (!key)
		{
			MM("ERR: CRYPTO INFO: fixup_key_DES: insufficient key material \n");
			return;
		}
		mbedtls_des_key_set_parity(key);
	}
}

mbedtls_cipher_info_t * cipher_kt_get (const char *ciphername)
{
	mbedtls_cipher_info_t *cipher = NULL;

	if(ciphername != NULL){

		cipher = (mbedtls_cipher_info_t *)mbedtls_cipher_info_from_string(ciphername);

		if (NULL == cipher){
			MM("Cipher algorithm '%s' not found \n", ciphername);
			exit(0);
		}

		if (cipher->key_bitlen/8 > MAX_CIPHER_KEY_LENGTH){
			MM("Cipher algorithm '%s' uses a default key size (%d bytes) which is larger than  current maximum key size (%d bytes) \n",
					ciphername,
					cipher->key_bitlen/8,
					MAX_CIPHER_KEY_LENGTH);
			return NULL;
		}

	}
	return cipher;
}

const char * cipher_kt_name (const mbedtls_cipher_info_t *cipher_kt)
{
	if (NULL == cipher_kt){
		return "[null-cipher]";
	}

	return translate_cipher_name_to_openvpn(cipher_kt->name);
}

int cipher_kt_key_size (const mbedtls_cipher_info_t *cipher_kt)
{
	if (NULL == cipher_kt){
		return 0;
	}
	return cipher_kt->key_bitlen/8;
}

int cipher_kt_iv_size (const mbedtls_cipher_info_t *cipher_kt)
{
	if (NULL == cipher_kt){
		return 0;
	}
	return cipher_kt->iv_size;
}

int cipher_kt_block_size (const mbedtls_cipher_info_t *cipher_kt)
{
	if (NULL == cipher_kt){
		return 0;
	}
	return cipher_kt->block_size;
}

int cipher_kt_tag_size(const mbedtls_cipher_info_t *cipher_kt)
{
#ifdef HAVE_AEAD_CIPHER_MODES
	if (cipher_kt && cipher_kt_mode_aead(cipher_kt))
	{
		return OPENVPN_AEAD_TAG_LENGTH;
	}
#endif
	return 0;
}

int cipher_kt_mode (const mbedtls_cipher_info_t *cipher_kt)
{
	assert(NULL != cipher_kt);
	return cipher_kt->mode;
}

bool cipher_kt_mode_cbc(const cipher_kt_t *cipher)
{
	return cipher && cipher_kt_mode(cipher) == OPENVPN_MODE_CBC;
}

bool cipher_kt_mode_ofb_cfb(const cipher_kt_t *cipher)
{
	  return cipher && (cipher_kt_mode(cipher) == OPENVPN_MODE_OFB || cipher_kt_mode(cipher) == OPENVPN_MODE_CFB);
}

#ifdef HAVE_AEAD_CIPHER_MODES
bool cipher_kt_mode_aead(const cipher_kt_t *cipher)
{
	return cipher && cipher_kt_mode(cipher) == OPENVPN_MODE_GCM;
}
#endif

void cipher_ctx_init (mbedtls_cipher_context_t *ctx, uint8_t *key, int key_len, const mbedtls_cipher_info_t *kt, const mbedtls_operation_t operation)
{
	assert(NULL != kt && NULL != ctx);

	if (mbedtls_cipher_setup(ctx, kt)){
		MM("PolarSSL cipher context init #1\n");
	}
	if (mbedtls_cipher_setkey(ctx, key, key_len*8, operation)){
		MM("PolarSSL cipher set key\n");
	}
	assert (ctx->key_bitlen <= key_len * 8);
}

void cipher_ctx_cleanup (mbedtls_cipher_context_t *ctx)
{
	mbedtls_cipher_free(ctx);
}

int cipher_ctx_iv_length (const mbedtls_cipher_context_t *ctx)
{
	return mbedtls_cipher_get_iv_size(ctx);
}

int cipher_ctx_get_tag(cipher_ctx_t *ctx, uint8_t *tag, int tag_len)
{
#ifdef HAVE_AEAD_CIPHER_MODES
	if (tag_len > SIZE_MAX)
	{
		return 0;
	}

	if (!mbed_ok(mbedtls_cipher_write_tag(ctx, (unsigned char *) tag, tag_len)))
	{
		return 0;
	}

	return 1;
#else  /* ifdef HAVE_AEAD_CIPHER_MODES */
	return 0;
#endif /* HAVE_AEAD_CIPHER_MODES */
}

int cipher_ctx_block_size(const mbedtls_cipher_context_t *ctx)
{
	return mbedtls_cipher_get_block_size(ctx);
}

int cipher_ctx_mode (const mbedtls_cipher_context_t *ctx)
{
	return cipher_kt_mode(ctx->cipher_info);
}

const cipher_kt_t * cipher_ctx_get_cipher_kt (const cipher_ctx_t *ctx)
{
	return ctx ? ctx->cipher_info : NULL;
}

int cipher_ctx_reset (mbedtls_cipher_context_t *ctx, uint8_t *iv_buf)
{
	if (mbedtls_cipher_reset(ctx)){
		MM("##ERR:  %s %d ##\n",__func__,__LINE__);
		return 0;
	}

	if (mbedtls_cipher_set_iv(ctx, iv_buf, ctx->cipher_info->iv_size)){
		MM("##ERR:  %s %d ##\n",__func__,__LINE__);
		return 0;
	}
	return 1;
}

int cipher_ctx_update_ad(cipher_ctx_t *ctx, const uint8_t *src, int src_len)
{
#ifdef HAVE_AEAD_CIPHER_MODES
	if (src_len > SIZE_MAX)
	{
		return 0;
	}

	if (mbedtls_cipher_update_ad(ctx, src, src_len) < 0)
	{
		return 0;
	}

	return 1;
#else  /* ifdef HAVE_AEAD_CIPHER_MODES */
	return 0;
#endif /* HAVE_AEAD_CIPHER_MODES */
}

int cipher_ctx_update (mbedtls_cipher_context_t *ctx, uint8_t *dst, int *dst_len, uint8_t *src, int src_len)
{

	size_t s_dst_len = *dst_len;
	if (mbedtls_cipher_update(ctx, src, (size_t)src_len, dst, &s_dst_len) < 0){
		MM("##ERR:  %s %d ##\n",__func__,__LINE__);
		return 0;
	}
	*dst_len = s_dst_len;
	return 1;
}

int cipher_ctx_final (mbedtls_cipher_context_t *ctx, uint8_t *dst, int *dst_len)
{
	size_t s_dst_len = *dst_len;

	if (mbedtls_cipher_finish(ctx, dst, &s_dst_len) < 0){
		MM("##ERR:  %s %d ##\n",__func__,__LINE__);
		return 0;
	}

	*dst_len = s_dst_len;
	return 1;
}

int cipher_ctx_final_check_tag(mbedtls_cipher_context_t *ctx, uint8_t *dst, int *dst_len, uint8_t *tag, size_t tag_len)
{
#ifdef HAVE_AEAD_CIPHER_MODES
	size_t olen = 0;

	if (MBEDTLS_DECRYPT != ctx->operation)
	{
		return 0;
	}

	if (tag_len > SIZE_MAX)
	{
		return 0;
	}

	if (!mbed_ok(mbedtls_cipher_finish(ctx, dst, &olen)))
	{
		msg(D_CRYPT_ERRORS, "%s: cipher_ctx_final() failed", __func__);
		return 0;
	}

	if (olen > INT_MAX)
	{
		return 0;
	}
	*dst_len = olen;

	if (!mbed_ok(mbedtls_cipher_check_tag(ctx, (const unsigned char *) tag,
					tag_len)))
	{
		return 0;
	}

	return 1;
#else  /* ifdef HAVE_AEAD_CIPHER_MODES */
	return 0;
#endif /* HAVE_AEAD_CIPHER_MODES */
}

void cipher_des_encrypt_ecb (const unsigned char key[DES_KEY_LENGTH], unsigned char *src,unsigned char *dst)
{
	mbedtls_des_context ctx;

	if(mbedtls_des_setkey_enc(&ctx, key) < 0){
		MM("##ERR:  %s %d ##\n",__func__,__LINE__);
		exit(0);
	}

	if(mbedtls_des_crypt_ecb(&ctx, src, dst) < 0){
		MM("##ERR:  %s %d ##\n",__func__,__LINE__);
		exit(0);
	}

}


const mbedtls_md_info_t * md_kt_get (const char *digest)
{
	const mbedtls_md_info_t *md = NULL;
	assert (digest);

	md = mbedtls_md_info_from_string(digest);
	if (md == NULL){
		MM("## EXIT : Message hash algorithm '%s' not found ##\n", digest);
		exit(0);
	}
	if (mbedtls_md_get_size(md) > MAX_HMAC_KEY_LENGTH)
	{
		MM("Message hash algorithm '%s' uses a default hash size (%d bytes) which is larger than Drizzle current maximum hash size (%d bytes) \n",
				digest,
				mbedtls_md_get_size(md),
				MAX_HMAC_KEY_LENGTH);
	}
	return md;
}

const char * md_kt_name (const mbedtls_md_info_t *kt)
{
	if (NULL == kt){
		return "[null-digest]";
	}
	return mbedtls_md_get_name(kt);
}

int md_kt_size (const mbedtls_md_info_t *kt)
{
	if (NULL == kt){
		return 0;
	}
	return mbedtls_md_get_size(kt);
}


int md_full (const md_kt_t *kt, const uint8_t *src, int src_len, uint8_t *dst)
{
	return 0 == mbedtls_md(kt, src, src_len, dst);
}

void md_ctx_init (mbedtls_md_context_t *ctx, const mbedtls_md_info_t *kt)
{

	mbedtls_md_init_ctx(ctx, kt);
	mbedtls_md_setup(ctx, kt, 0);
	mbedtls_md_starts(ctx);
}

void md_ctx_cleanup(mbedtls_md_context_t *ctx)
{
	if(ctx){}
}

int md_ctx_size (const mbedtls_md_context_t *ctx)
{
	if (NULL == ctx){
		return 0;
	}
	return mbedtls_md_get_size(ctx->md_info);
}

void md_ctx_update (mbedtls_md_context_t *ctx, const char *src, int src_len)
{
	assert(0 == mbedtls_md_update(ctx, (const unsigned char *)src, src_len));
}

void md_ctx_final (mbedtls_md_context_t *ctx, char *dst)
{
	assert(0 == mbedtls_md_finish(ctx, (unsigned char *)dst));
	mbedtls_md_free(ctx);
}


void hmac_ctx_init (mbedtls_md_context_t *ctx, const uint8_t *key, int key_len, const mbedtls_md_info_t *kt)
{

	mbedtls_md_init(ctx);
	mbedtls_md_setup(ctx, kt, 1);
	mbedtls_md_hmac_starts(ctx, key, key_len);

}

void hmac_ctx_cleanup(mbedtls_md_context_t *ctx)
{
	mbedtls_md_free(ctx);
}

int hmac_ctx_size (const mbedtls_md_context_t *ctx)
{
	if (NULL == ctx){
		return 0;
	}
	return mbedtls_md_get_size(ctx->md_info);
}

void hmac_ctx_reset (mbedtls_md_context_t *ctx)
{
	assert(0 == mbedtls_md_hmac_reset(ctx));
}

void hmac_ctx_update (mbedtls_md_context_t *ctx, const uint8_t *src, int src_len)
{
	assert(0 == mbedtls_md_hmac_update(ctx, src, src_len));
}

void hmac_ctx_final (mbedtls_md_context_t *ctx, uint8_t *dst)
{
	assert(0 == mbedtls_md_hmac_finish(ctx, dst));
}

#endif
