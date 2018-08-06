#include <rain_common.h>

#ifdef MBEDTLS_CONF

#include <mbedtls/threading.h>

mbedtls_threading_mutex_t debug_mutex;
pthread_mutex_t mydata_mutex;

void tls_init_lib(void)
{
	pthread_mutex_init(&mydata_mutex,NULL);
	mbedtls_mutex_init( &debug_mutex );
}

void tls_free_lib(void)
{
	mbedtls_mutex_free( &debug_mutex );
}

void tls_clear_error()
{
}

void tls_ctx_server_new(struct tls_root_ctx *ctx, unsigned int ssl_flags)
{
	if(ssl_flags){}

	if(ctx == NULL){
		MM("# ERR: EXIT()  %s %d ctx = NULL  ##\n",__func__,__LINE__);
		exit(0);
	}else{

		ctx->dhm_ctx = malloc(sizeof(mbedtls_dhm_context));
		memset(ctx->dhm_ctx,0x00,sizeof(mbedtls_dhm_context));

		ctx->ca_chain = malloc(sizeof(mbedtls_x509_crt));
		memset(ctx->ca_chain,0x00,sizeof(mbedtls_x509_crt));

		ctx->endpoint = MBEDTLS_SSL_IS_SERVER;
		ctx->initialised = true;
	}
}

void tls_ctx_client_new(struct tls_root_ctx *ctx, unsigned int ssl_flags)
{
	if(ssl_flags){}
	if(ctx == NULL){
		MM("# ERR : EXIT() %s %d ctx = NULL  ##\n",__func__,__LINE__);
		exit(0);
	}else{

		ctx->dhm_ctx = malloc(sizeof(mbedtls_dhm_context));
		memset(ctx->dhm_ctx,0x00,sizeof(mbedtls_dhm_context));

		ctx->ca_chain = malloc(sizeof(mbedtls_x509_crt));
		memset(ctx->ca_chain,0x00,sizeof(mbedtls_x509_crt));

		ctx->endpoint = MBEDTLS_SSL_IS_CLIENT;
		ctx->initialised = true;

	}
}

void tls_ctx_free(struct tls_root_ctx *ctx)
{
	printf("########################################################################## %s %d ##############\n",__func__,__LINE__);
	if(ctx == NULL){
		MM("# ERR :  EXIT() %s %d ctx = NULL  ##\n",__func__,__LINE__);
		exit(0);
	}else{
		mbedtls_pk_free(ctx->priv_key);
		if (ctx->priv_key){
			sfree(ctx->priv_key);
		}

		mbedtls_x509_crt_free(ctx->ca_chain);
		if (ctx->ca_chain){
			sfree(ctx->ca_chain);
		}

		mbedtls_x509_crt_free(ctx->crt_chain);
		if (ctx->crt_chain){
			sfree(ctx->crt_chain);
		}

		mbedtls_dhm_free(ctx->dhm_ctx);
		if (ctx->dhm_ctx){
			sfree(ctx->dhm_ctx);
		}

      mbedtls_x509_crl_free(ctx->crl);
      if (ctx->crl)
      {
            free(ctx->crl);
      }

#if defined(ENABLE_PKCS11)
		if (ctx->priv_key_pkcs11 != NULL) {
			mbedtls_pkcs11_priv_key_free(ctx->priv_key_pkcs11);
			sfree(ctx->priv_key_pkcs11);
		}
#endif
#if defined(MANAGMENT_EXTERNAL_KEY)
		if (ctx->external_key != NULL){
			sfree(ctx->external_key);
		}
#endif

		if (ctx->allowed_ciphers){
			sfree(ctx->allowed_ciphers);
		}
		//free(ctx->ctx);
		//ctx->ctx = NULL;
		ctx->initialised = false;
	}
}

bool tls_ctx_initialised(struct tls_root_ctx *ctx)
{
	if(ctx == NULL){
		MM("# ERR : %s %d ctx = NULL  ##\n",__func__,__LINE__);
		exit(0);
	}
	return ctx->initialised;
}

void key_state_export_keying_material(struct key_state_ssl *ssl, struct tls_session *session)
{
}

void tls_ctx_set_options (struct tls_root_ctx *ctx, unsigned int ssl_flags)
{
	if(ctx){}
	if(ssl_flags){}
}
typedef struct { const char *openssl_name; const char *iana_name; } tls_cipher_name_pair;
#if 0
static const char * tls_translate_cipher_name (const char * cipher_name) {
	const tls_cipher_name_pair * pair = tls_get_cipher_name_pair(cipher_name, strlen(cipher_name));

	if (NULL == pair)
	{
		return cipher_name;
	}

	if (0 != strcmp(cipher_name, pair->iana_name))
	{
		MM("Deprecated cipher suite name '%s', please use IANA name '%s'\n", pair->openssl_name, pair->iana_name);
	}
	return pair->iana_name;
}

void tls_ctx_restrict_ciphers(struct tls_root_ctx *ctx, const char *ciphers)
{

	char *tmp_ciphers, *tmp_ciphers_orig, *token;
	int i, cipher_count;
	int ciphers_len;

	if (NULL == ciphers)
	{
		return; /* Nothing to do */

	}
	ciphers_len = strlen(ciphers);

	assert(NULL != ctx);
	assert(0 != ciphers_len);

	/* Get number of ciphers */
	for (i = 0, cipher_count = 1; i < ciphers_len; i++){
		if (ciphers[i] == ':')
		{
			cipher_count++;
		}
	}

		ctx->allowed_ciphers = calloc(cipher_count+1,sizeof(int));

	i = 0;
	tmp_ciphers_orig = tmp_ciphers = malloc(sizeof(ciphers));
	memset(tmp_ciphers,0x00,sizeof(ciphers));

	token = strtok(tmp_ciphers, ":");
	while (token)
	{
		ctx->allowed_ciphers[i] = mbedtls_ssl_get_ciphersuite_id(tls_translate_cipher_name(token));
		if (0 != ctx->allowed_ciphers[i])
		{
			i++;
		}
		token = strtok(NULL, ":");
	}
	free(tmp_ciphers_orig);
}
#endif
void tls_ctx_check_cert_time (const struct tls_root_ctx *ctx)
{
	//ASSERT (ctx);
	if (ctx->crt_chain == NULL)
	{
		return;
	}

	if (mbedtls_x509_time_is_future (&ctx->crt_chain->valid_from))
	{
		MM("WARNING: Your certificate is not yet valid!\n");
	}

	if (mbedtls_x509_time_is_past(&ctx->crt_chain->valid_to))
	{
		MM("WARNING: Your certificate has expired!\n");
	}
}


void tls_ctx_load_dh_params (struct tls_root_ctx *ctx, const char *dh_file, const char *dh_inline)
{
	if(ctx == NULL){
		MM("# ERR : %s %d ctx = NULL  ##\n",__func__,__LINE__);
		exit(0);
	}
	if (!strcmp (dh_file, INLINE_FILE_TAG) && dh_inline)
	{
		if (mbedtls_dhm_parse_dhm(ctx->dhm_ctx,(const unsigned char *) dh_inline, strlen(dh_inline) + 1) < 0 ){
			MM("Cannot read inline DH parameters\n");
		}
	}
	else
	{
		//if (!polar_ok(dhm_parse_dhmfile(ctx->dhm_ctx, dh_file))){
		if (mbedtls_dhm_parse_dhmfile(ctx->dhm_ctx, dh_file) < 0){
			MM("Cannot read DH parameters from file %s\n", dh_file);
		}
	}

	//MM("Diffie-Hellman initialized with " counter_format " bit key", (counter_type) 8 * mpi_size(&ctx->dhm_ctx->P));
}

int tls_ctx_load_pkcs12(struct tls_root_ctx *ctx, const char *pkcs12_file, const char *pkcs12_file_inline,bool load_ca_file)
{
	if(ctx){}
	if(pkcs12_file){}
	if(pkcs12_file_inline){}
	if(load_ca_file){}
	MM("PKCS #12 files not yet supported for mbedtls.\n");
	return 0;
}

#ifdef ENABLE_CRYPTOAPI
void tls_ctx_load_cryptoapi(struct tls_root_ctx *ctx, const char *cryptoapi_cert)
{
	if(ctx){}
	if(cryptoapi_cert){}
	MM("Windows CryptoAPI not yet supported for mbedtls.\n");
}
#endif /* WIN32 */

void tls_ctx_load_cert_file (struct tls_root_ctx *ctx, const char *cert_file, const char *cert_inline)
{
	//ASSERT(NULL != ctx);
	if (!ctx->crt_chain)
	{
		ctx->crt_chain = malloc(sizeof(mbedtls_x509_crt));
		memset(ctx->crt_chain,0x00,sizeof(mbedtls_x509_crt));
	}

	if (!strcmp (cert_file, INLINE_FILE_TAG) && cert_inline)
	{
		if (mbedtls_x509_crt_parse(ctx->crt_chain, (const unsigned char *) cert_inline, strlen(cert_inline)) < 0 ){
			MM("Cannot load inline certificate file\n");
		}
	}
	else
	{
		if (mbedtls_x509_crt_parse_file(ctx->crt_chain, cert_file) < 0 )
		{
			MM("Cannot load certificate file %s\n", cert_file);
		}
	}
}

int tls_ctx_load_priv_file (struct tls_root_ctx *ctx, const char *priv_key_file, const char *priv_key_inline)
{
	int status;
	//ASSERT(NULL != ctx);

	if (!ctx->priv_key)
	{
		ctx->priv_key = malloc(sizeof(mbedtls_pk_context));
		memset(ctx->priv_key,0x00,sizeof(mbedtls_pk_context));
	}

	if (!strcmp (priv_key_file, INLINE_FILE_TAG) && priv_key_inline)
	{
		status = mbedtls_pk_parse_key(ctx->priv_key, (const unsigned char *) priv_key_inline, strlen(priv_key_inline)+1,NULL, 0);

		if (MBEDTLS_ERR_PK_PASSWORD_REQUIRED == status)
		{
			char passbuf[512] = {0};
			pem_password_callback(passbuf, 512, 0, NULL);
			status = mbedtls_pk_parse_key(ctx->priv_key,(const unsigned char *) priv_key_inline, strlen(priv_key_inline)+1,(unsigned char *) passbuf, strlen(passbuf));
		}
	}
	else
	{
		status = mbedtls_pk_parse_keyfile(ctx->priv_key, priv_key_file, NULL);
		if (MBEDTLS_ERR_PK_PASSWORD_REQUIRED == status)
		{
			char passbuf[512] = {0};
			pem_password_callback(passbuf, 512, 0, NULL);
			status = mbedtls_pk_parse_keyfile(ctx->priv_key, priv_key_file, passbuf);
		}
	}
	if (status < 0)
	{
#if 0
#ifdef ENABLE_MANAGEMENT
		if (management && (MBEDTLS_ERR_PK_PASSWORD_MISMATCH == status))
			management_auth_failure (management, UP_TYPE_PRIVATE_KEY, NULL);
#endif
#endif
		MM("Cannot load private key file %s\n", priv_key_file);
		return 1;
	}

	if (mbedtls_pk_check_pair(&ctx->crt_chain->pk, ctx->priv_key) < 0)
	{
		MM("Private key does not match the certificate \n");
		return 1;
	}
	return 0;
}

void tls_ctx_load_ca (struct tls_root_ctx *ctx, const char *ca_file,const char *ca_inline, const char *ca_path, bool tls_server)
{
	if(tls_server){}

	if (ca_path){
		MM("ERROR: Mbedtls cannot handle the capath directive\n");
	}

	if (ca_file && !strcmp (ca_file, INLINE_FILE_TAG) && ca_inline)
	{
		if (mbedtls_x509_crt_parse(ctx->ca_chain,(const unsigned char *) ca_inline, strlen(ca_inline)+1) < 0){
			MM("Cannot load inline CA certificates\n");
		}
	}
	else
	{
		if (mbedtls_x509_crt_parse_file(ctx->ca_chain, ca_file) < 0){
			MM("Cannot load CA certificate file %s\n", ca_file);
		}
	}
}

void tls_ctx_load_extra_certs (struct tls_root_ctx *ctx, const char *extra_certs_file, const char *extra_certs_inline)
{
	//ASSERT(NULL != ctx);

	if (!ctx->crt_chain)
	{
		ctx->crt_chain = malloc(sizeof(mbedtls_x509_crt));
		memset(ctx->crt_chain,0x00,sizeof(mbedtls_x509_crt));

	}

	if (!strcmp (extra_certs_file, INLINE_FILE_TAG) && extra_certs_inline)
	{
		if (mbedtls_x509_crt_parse(ctx->crt_chain, (const unsigned char *) extra_certs_inline,strlen(extra_certs_inline)+1) < 0){
			MM("Cannot load inline extra-certs file\n");
		}
	}
	else
	{
		if (mbedtls_x509_crt_parse_file(ctx->crt_chain, extra_certs_file) < 0){
			MM("Cannot load extra-certs file: %s\n", extra_certs_file);
		}
	}
}

static inline void buf_free_entry(buffer_entry *entry)
{
	if (NULL != entry)
	{
		sfree(entry->data);
		sfree(entry);
	}
}

static void buf_free_entries(endless_buffer *buf)
{
	while(buf->first_block)
	{
		buffer_entry *cur_block = buf->first_block;
		buf->first_block = cur_block->next_block;
		buf_free_entry(cur_block);
	}
	buf->last_block = NULL;
}

static int endless_buf_read( void * ctx, unsigned char * out, size_t out_len )
{
	endless_buffer *in = (endless_buffer *) ctx;
	size_t read_len = 0;

	if (in->first_block == NULL){
		return MBEDTLS_ERR_SSL_WANT_READ;
	}

	while (in->first_block != NULL && read_len < out_len)
	{
		int block_len = in->first_block->length - in->data_start;
		if ((size_t)block_len <= out_len - read_len)
		{
			buffer_entry *cur_entry = in->first_block;
			memcpy(out + read_len, cur_entry->data + in->data_start,block_len);

			read_len += block_len;

			in->first_block = cur_entry->next_block;
			in->data_start = 0;

			if (in->first_block == NULL){
				in->last_block = NULL;
			}

			buf_free_entry(cur_entry);
		}
		else
		{
			memcpy(out + read_len, in->first_block->data + in->data_start,out_len - read_len);
			in->data_start += out_len - read_len;
			read_len = out_len;
		}
	}

	return read_len;
}

static int endless_buf_write( void *ctx, const unsigned char *in, size_t len )
{
	int ret = 0;
	if(ctx == NULL){
		MM("## ERR: EXIT %s %d ##\n",__func__,__LINE__);
		ret = -1;
	}else{
		endless_buffer *out = (endless_buffer *) ctx;
		buffer_entry *new_block = malloc(sizeof(buffer_entry));
		memset(new_block,0x00,sizeof(buffer_entry));

		if (NULL == new_block){
			return MBEDTLS_ERR_NET_SEND_FAILED;
		}

		new_block->data = malloc(len);
		if (NULL == new_block->data)
		{
			sfree(new_block);
			return MBEDTLS_ERR_NET_SEND_FAILED;
		}

		new_block->length = len;
		new_block->next_block = NULL;

		memcpy(new_block->data, in, len);

		if (NULL == out->first_block){
			out->first_block = new_block;
		}

		if (NULL != out->last_block){
			out->last_block->next_block = new_block;
		}

		out->last_block = new_block;
		ret = len;
	}
	return ret;
}

static int ssl_bio_read( void *ctx, unsigned char *out, size_t out_len)
{
	bio_ctx *my_ctx = (bio_ctx *) ctx;
	return endless_buf_read(&my_ctx->in, out, out_len);
}

static int ssl_bio_write( void *ctx, const unsigned char *in, size_t in_len)
{
	bio_ctx *my_ctx = (bio_ctx *) ctx;
	return endless_buf_write(&my_ctx->out, in, in_len);
}


#if 1
static void my_debug( void *ctx, int level, const char *str )
{
	if(ctx){}
	if(level){}
	if(str){}
	MM("MBEDTLS  msg: %s \n", str);
}
#endif

void tls_ctx_personalise_random(struct tls_root_ctx *ctx)
{
	static char old_sha256_hash[32] = {0};
	unsigned char sha256_hash[32] = {0};
	mbedtls_ctr_drbg_context *cd_ctx = rand_ctx_get();

	if (NULL != ctx->crt_chain)
	{
		mbedtls_x509_crt *cert = ctx->crt_chain;

		mbedtls_sha256(cert->tbs.p, cert->tbs.len, sha256_hash, false);
		if ( 0 != memcmp(old_sha256_hash, sha256_hash, sizeof(sha256_hash)))
		{
			mbedtls_ctr_drbg_update(cd_ctx, sha256_hash, 32);
			memcpy(old_sha256_hash, sha256_hash, sizeof(old_sha256_hash));
		}
	}
}

int tls_version_max(void)
{
	return TLS_VER_1_2;
#if 0
#if defined(MBEDTLS_SSL_MAJOR_VERSION_3) && defined(SSL_MINOR_VERSION_3)
	return TLS_VER_1_2;
#elif defined(MBEDTLS_SSL_MAJOR_VERSION_3) && defined(SSL_MINOR_VERSION_2)
	return TLS_VER_1_1;
#else
	return TLS_VER_1_0;
#endif
#endif
}

static void tls_version_to_major_minor(int tls_ver, int *major, int *minor) {

	switch (tls_ver)
	{
		case TLS_VER_1_0:
			*major = MBEDTLS_SSL_MAJOR_VERSION_3;
			*minor = MBEDTLS_SSL_MINOR_VERSION_1;
			break;

		case TLS_VER_1_1:
			*major = MBEDTLS_SSL_MAJOR_VERSION_3;
			*minor = MBEDTLS_SSL_MINOR_VERSION_2;
			break;

		case TLS_VER_1_2:
			*major = MBEDTLS_SSL_MAJOR_VERSION_3;
			*minor = MBEDTLS_SSL_MINOR_VERSION_3;
			break;

		default:
			MM("%s: invalid TLS version %d \n", __func__, tls_ver);
			break;
	}
}


void backend_tls_ctx_reload_crl(struct tls_root_ctx *ctx, const char *crl_file, const char *crl_inline)
{
	if(crl_file == NULL){
		MM("## ERR: exit ### %s %d ##\n",__func__,__LINE__);
		exit(0);
	}

	if (ctx->crl == NULL)
	{
		ctx->crl = malloc(sizeof(mbedtls_x509_crl));
		memset(ctx->crl,0x00,sizeof(mbedtls_x509_crl));
	}
	mbedtls_x509_crl_free(ctx->crl);

	if (!strcmp(crl_file, INLINE_FILE_TAG) && crl_inline)
	{
		if (mbedtls_x509_crl_parse(ctx->crl, (const unsigned char *)crl_inline, strlen(crl_inline)+1) < 0)
		{
			MM("## ERR:  exit ## %s %d ##\n",__func__,__LINE__);
			exit(0);
			goto err;
		}
	}
	else
	{
		if (mbedtls_x509_crl_parse_file(ctx->crl, crl_file) < 0)
		{
			MM("## ERR:  exit ## %s %d ##\n",__func__,__LINE__);
			exit(0);
			goto err;
		}
	}
	return;

err:
	mbedtls_x509_crl_free(ctx->crl);
}

void key_state_ssl_init(struct epoll_ptr_data *epd,struct key_state_ssl *ks_ssl, const struct tls_root_ctx *ssl_ctx, int is_server)
{
	struct main_data *md = (struct main_data *)epd->gl_var;
	struct options *opt = md->opt;
	unsigned int ssl_flags = opt->ssl_flags;

	mbedtls_ssl_config_init(&ks_ssl->ssl_config);
	mbedtls_ssl_config_defaults(&ks_ssl->ssl_config, ssl_ctx->endpoint,MBEDTLS_SSL_TRANSPORT_STREAM, MBEDTLS_SSL_PRESET_DEFAULT);

#ifdef MBEDTLS_DEBUG_C
	mbedtls_debug_set_threshold(3);
#endif

	mbedtls_ssl_conf_dbg(&ks_ssl->ssl_config, my_debug, NULL);
	mbedtls_ssl_conf_rng(&ks_ssl->ssl_config, mbedtls_ctr_drbg_random,rand_ctx_get());

	if (ssl_ctx->allowed_ciphers)
	{
		mbedtls_ssl_conf_ciphersuites(&ks_ssl->ssl_config, ssl_ctx->allowed_ciphers);
	}

#if defined(MBEDTLS_SSL_CBC_RECORD_SPLITTING)
	mbedtls_ssl_conf_cbc_record_splitting(&ks_ssl->ssl_config,MBEDTLS_SSL_CBC_RECORD_SPLITTING_DISABLED);
#endif /* MBEDTLS_SSL_CBC_RECORD_SPLITTING */

	if (is_server == SERVER)
	{
		mbedtls_ssl_conf_dh_param_ctx(&ks_ssl->ssl_config, ssl_ctx->dhm_ctx);
	}

	mbedtls_ssl_conf_own_cert(&ks_ssl->ssl_config, ssl_ctx->crt_chain,ssl_ctx->priv_key);

	if (is_server == SERVER && ssl_flags & SSLF_USERNAME_AS_COMMON_NAME)
	{
		mbedtls_ssl_conf_authmode(&ks_ssl->ssl_config, MBEDTLS_SSL_VERIFY_OPTIONAL);
	}
	else if (is_server == SERVER && (!(ssl_flags & SSLF_CLIENT_CERT_NOT_REQUIRED)))
	{
		mbedtls_ssl_conf_authmode(&ks_ssl->ssl_config, MBEDTLS_SSL_VERIFY_REQUIRED);
	}

	mbedtls_ssl_conf_verify(&ks_ssl->ssl_config, verify_callback,(uint32_t *)epd );

	mbedtls_ssl_conf_ca_chain(&ks_ssl->ssl_config, ssl_ctx->ca_chain, ssl_ctx->crl);

	{
		const int tls_version_min = (ssl_flags >> SSLF_TLS_VERSION_MIN_SHIFT) &SSLF_TLS_VERSION_MIN_MASK;

		/* default to TLS 1.0 */
		int major = MBEDTLS_SSL_MAJOR_VERSION_3;
		int minor = MBEDTLS_SSL_MINOR_VERSION_1;

		if (tls_version_min > TLS_VER_UNSPEC)
		{
			tls_version_to_major_minor(tls_version_min, &major, &minor);
		}

		mbedtls_ssl_conf_min_version(&ks_ssl->ssl_config, major, minor);
	}

	/* Initialize maximum TLS version */
	{
		const int tls_version_max = (ssl_flags >> SSLF_TLS_VERSION_MAX_SHIFT)&SSLF_TLS_VERSION_MAX_MASK;

		if (tls_version_max > TLS_VER_UNSPEC)
		{
			int major, minor;
			tls_version_to_major_minor(tls_version_max, &major, &minor);
			mbedtls_ssl_conf_max_version(&ks_ssl->ssl_config, major, minor);
		}
	}

	/* Initialise SSL context */
	ks_ssl->ctx = malloc(sizeof(mbedtls_ssl_context));
	memset(ks_ssl->ctx,0x00,sizeof(mbedtls_ssl_context));

	mbedtls_ssl_init(ks_ssl->ctx);
	mbedtls_ssl_set_bio(ks_ssl->ctx, &ks_ssl->bio_ctx, ssl_bio_write,ssl_bio_read, NULL);

	//memset(ks_ssl->bio_ctx,0x00,sizeof(ks_ssl->bio_ctx));
	mbedtls_ssl_set_bio(ks_ssl->ctx, &ks_ssl->bio_ctx, ssl_bio_write,ssl_bio_read, NULL);
}

void key_state_ssl_remove(struct epoll_ptr_data *epd,bool all)
{
	int i=0;
	int delid=0;
	struct main_data *md = NULL;
	struct options *opt = NULL;
	md = (struct main_data *)epd->gl_var;
	opt = md->opt;

	if(all == true){
		for(i = 0 ; i < 8 ; i++){
			int xx=0;
			if(epd->ss->sk[i].key.decrypt.cipher != NULL){
				for(xx = 0; xx < (int)opt->core;xx++){
					free_key_ctx(&epd->ss->sk[i].key.decrypt,xx);
				}
			}
			if(epd->ss->sk[i].key.encrypt.cipher != NULL){
				for(xx = 0; xx < (int)opt->core;xx++){
					free_key_ctx(&epd->ss->sk[i].key.encrypt,xx);
				}
			}
			if(epd->ss->sk[i].prb != NULL){
				sfree(epd->ss->sk[i].prb);
				epd->ss->sk[i].prb = NULL;
				epd->ss->sk[i].prb_len = 0;
			}
			if(epd->ss->sk[i].pwb != NULL){
				sfree(epd->ss->sk[i].pwb);
				epd->ss->sk[i].pwb = NULL;
				epd->ss->sk[i].pwb_len = 0;
			}

			if(epd->ss->sk[i].ks_ssl != NULL){
				MM("## %s %d ##\n",__func__,__LINE__);
				key_state_ssl_free(epd->ss->sk[i].ks_ssl,true);
#if 0
				if(i == 7){
					key_state_ssl_free(epd->ss->sk[i].ks_ssl,true);
				}else{
					key_state_ssl_free(epd->ss->sk[i].ks_ssl,false);
				}
#endif
				sfree(epd->ss->sk[i].ks_ssl);
				epd->ss->sk[i].ks_ssl = NULL;
			}
		}
	}else{

		//printf("############ %s %d %s ### \n",__func__,__LINE__,epd->name);

		if(epd->ss->keyid == 7){
			delid = 0;
			if(epd->ss->sk[delid].key.decrypt.cipher != NULL){
				for(i = 0; i < (int)opt->core;i++){
					free_key_ctx(&epd->ss->sk[delid].key.decrypt,i);
				}
			}
			if(epd->ss->sk[delid].key.encrypt.cipher != NULL){
				for(i = 0; i < (int)opt->core;i++){
					free_key_ctx(&epd->ss->sk[delid].key.encrypt,i);
				}
			}
			if(epd->ss->sk[delid].prb != NULL){
				sfree(epd->ss->sk[delid].prb);
				epd->ss->sk[delid].prb = NULL;
				epd->ss->sk[delid].prb_len = 0;
			}
			if(epd->ss->sk[delid].pwb != NULL){
				sfree(epd->ss->sk[delid].pwb);
				epd->ss->sk[delid].pwb = NULL;
				epd->ss->sk[delid].pwb_len = 0;
			}

			if(epd->ss->sk[delid].ks_ssl != NULL){
				key_state_ssl_free(epd->ss->sk[delid].ks_ssl,false);
				MM("## %s %d ##\n",__func__,__LINE__);
				sfree(epd->ss->sk[delid].ks_ssl);
				epd->ss->sk[delid].ks_ssl = NULL;
			}
		}


		if((epd->ss->keyid == 1) || (epd->ss->keyid == 0)){
			delid = 6;
		}else if((epd->ss->keyid == 2)){
			delid = 7;
		}else {
			delid = (epd->ss->keyid - 2);
		}
		if(epd->ss->sk[delid].key.decrypt.cipher != NULL){
			for(i = 0; i < (int)opt->core;i++){
				free_key_ctx(&epd->ss->sk[delid].key.decrypt,i);
			}
		}
		if(epd->ss->sk[delid].key.encrypt.cipher != NULL){
			for(i = 0; i < (int)opt->core;i++){
				free_key_ctx(&epd->ss->sk[delid].key.encrypt,i);
			}
		}
		if(epd->ss->sk[delid].prb != NULL){
			sfree(epd->ss->sk[delid].prb);
			epd->ss->sk[delid].prb = NULL;
			epd->ss->sk[delid].prb_len = 0;
		}
		if(epd->ss->sk[delid].pwb != NULL){
			sfree(epd->ss->sk[delid].pwb);
			epd->ss->sk[delid].pwb = NULL;
			epd->ss->sk[delid].pwb_len = 0;
		}

		if(epd->ss->sk[delid].ks_ssl != NULL){
			key_state_ssl_free(epd->ss->sk[delid].ks_ssl,false);
			sfree(epd->ss->sk[delid].ks_ssl);
			MM("## %s %d ##\n",__func__,__LINE__);
			epd->ss->sk[delid].ks_ssl = NULL;
		}

		epd->ss->sk[delid].state = S_UNDEF;
	}
}


void key_state_ssl_free(struct key_state_ssl *ks_ssl,bool all)
{
	if(all){}
	if (ks_ssl != NULL) {
		if (ks_ssl->ctx != NULL)
		{
			mbedtls_ssl_free(ks_ssl->ctx);
			sfree(ks_ssl->ctx);
		}
		mbedtls_ssl_config_free(&ks_ssl->ssl_config);
		buf_free_entries(&ks_ssl->bio_ctx.in);
		buf_free_entries(&ks_ssl->bio_ctx.out);
		//CLEAR(*ks_ssl);
		ks_ssl->ctx = NULL;
	}
}

int key_state_write_plaintext (struct key_state_ssl *ks, char *buf,int len)
{
	MM("## %s %d ##\n",__func__,__LINE__);
	int retval = 0;
	if(ks != NULL){
		retval = key_state_write_plaintext_const(ks, buf, len);

		memset (buf, 0, len);
	}
	return retval;
}

int key_state_write_plaintext_const (struct key_state_ssl *ks, char *data, int len)
{
	MM("## %s %d ##\n",__func__,__LINE__);
	int retval = 0;
	if(ks != NULL){
		pthread_mutex_lock(&mydata_mutex);
		retval = mbedtls_ssl_write(ks->ctx, (const unsigned char *)data, len);
		pthread_mutex_unlock(&mydata_mutex);

		if (retval < 0)
		{
			if (MBEDTLS_ERR_SSL_WANT_WRITE == retval || MBEDTLS_ERR_SSL_WANT_READ == retval){
				MM("## ERR: %s %d ##\n",__func__,__LINE__);
				return 0;
			}
			MM("## ERR: %s %d ##\n",__func__,__LINE__);
			//mbedtls_log_err (1, retval, "TLS ERROR: write tls_write_plaintext_const error");
			return -1;
			retval = -1;
		}else{

			if (retval != len)
			{
				MM("## ERR: %s %d write tls_write_plaintext_const incomplete %d/%d\n",__func__,__LINE__,retval, len);
				return -1;
				retval = -1;
			}
			memset(data,0x00,len);
			return 1;
		}
		//MM("## %s %d write tls_write_plaintext_const %d bytes\n",__func__,__LINE__,retval);
	}else{
		MM("## ERR: %s %d ##\n",__func__,__LINE__);
		return -1;
		retval = -1;
	}
	return retval;
}

int key_state_read_ciphertext (struct key_state_ssl *ks, char *buf, int len ,int maxlen)
{
	MM("## %s %d ##\n",__func__,__LINE__);
	int retval = 0;
	if(ks != NULL){
		if (maxlen < len){
			len = maxlen;
		}

		pthread_mutex_lock(&mydata_mutex);
		retval = endless_buf_read(&ks->bio_ctx.out, (unsigned char *)buf, len);
		pthread_mutex_unlock(&mydata_mutex);

		if (retval < 0)
		{
			if (MBEDTLS_ERR_SSL_WANT_WRITE == retval || MBEDTLS_ERR_SSL_WANT_READ == retval){
				return 0;
			}
			MM("## ERR: %s %d ##\n",__func__,__LINE__);
			//mbedtls_log_err (1, retval, "TLS_ERROR: read tls_read_ciphertext error");
			return -1;
		}
		if (0 == retval)
		{
			return 0;
		}
	}
	return retval;
}


int key_state_write_ciphertext (struct key_state_ssl *ks, char *buf,int len)
{
	MM("## %s %d ##\n",__func__,__LINE__);
	int retval = 0;
	if(ks != NULL){
		pthread_mutex_lock(&mydata_mutex);
		retval = endless_buf_write(&ks->bio_ctx.in, (const unsigned char *)buf, len);
		pthread_mutex_unlock(&mydata_mutex);

		if (retval < 0)
		{
			if (MBEDTLS_ERR_SSL_WANT_WRITE == retval || MBEDTLS_ERR_SSL_WANT_READ == retval){
				return 0;
				retval = 0;
			}else{
				MM("## ERR: %s %d ##\n",__func__,__LINE__);
				return -1;
				//mbedtls_log_err (1, retval,"TLS ERROR: write tls_write_ciphertext error");
				retval = -1;
			}
		}else{

			if (retval != len)
			{
				MM("TLS ERROR: write tls_write_ciphertext incomplete %d/%d\n",retval, len);
				return -1;
				retval = -1;
			}

		}
		//MM("## %s %d write tls_write_ciphertext %d bytes\n",__func__,__LINE__,retval);

		memset (buf, 0, len);
		return 1;
		if(retval > 0){
			retval = 1;
		}
	}
	return 0;
	return retval;
}

int key_state_read_plaintext (struct key_state_ssl *ks, char *buf,int len, int maxlen)
{
	MM("## %s %d ##\n",__func__,__LINE__);
	int retval = 0;
	if(ks != NULL && ks->ctx != NULL){
	MM("## %s %d ##\n",__func__,__LINE__);
		if (maxlen < len){
			len = maxlen;
		}
		pthread_mutex_lock(&mydata_mutex);
		retval = mbedtls_ssl_read(ks->ctx, (unsigned char *)buf, len);
		pthread_mutex_unlock(&mydata_mutex);
		if (retval < 0)
		{
	MM("## %s %d retval : %d ##\n",__func__,__LINE__,retval);
			if (MBEDTLS_ERR_SSL_WANT_WRITE == retval || MBEDTLS_ERR_SSL_WANT_READ == retval){
				MM("## ERR: %s %d %d ##\n",__func__,__LINE__,retval);
				return 0;
			}
			MM("## ERR: %s %d %d ##\n",__func__,__LINE__,retval);
			mbedtls_log_err (1, retval, "TLS_ERROR: read tls_read_plaintext error");
			return -1;
		}
		if (0 == retval)
		{
	MM("## %s %d ##\n",__func__,__LINE__);
			MM("## %s %d retval : 0##\n",__func__,__LINE__);
			return 0;
		}

	}
	MM("## %s %d ##\n",__func__,__LINE__);
	return retval;
}

void print_details (struct key_state_ssl * ks_ssl, const char *prefix)
{
	const mbedtls_x509_crt *cert;
	char s1[256];
	char s2[256];

	s1[0] = s2[0] = 0;
	snprintf (s1, sizeof (s1), "%s %s, cipher %s",
			prefix,
			mbedtls_ssl_get_version(ks_ssl->ctx),
			mbedtls_ssl_get_ciphersuite(ks_ssl->ctx));

	cert = mbedtls_ssl_get_peer_cert(ks_ssl->ctx);
	if (cert != NULL)
	{
		snprintf (s2, sizeof (s2), ", %zu bit key", mbedtls_pk_get_bitlen(&cert->pk));
	}

	MM("%s%s\n", s1, s2);
}

void show_available_tls_ciphers (const char *cipher_list)
{
	if(cipher_list){}
#if 0
	struct tls_root_ctx tls_ctx;
	const int *ciphers = mbedtls_ssl_list_ciphersuites();

	if (cipher_list) {
		tls_ctx_restrict_ciphers(&tls_ctx, cipher_list);
		ciphers = tls_ctx.allowed_ciphers;
	}
	while (*ciphers != 0)
	{
		printf ("%s\n", ssl_get_ciphersuite_name(*ciphers));
		ciphers++;
	}
	printf ("\n");
	//printf ("\n" SHOW_TLS_CIPHER_LIST_WARNING);
#endif
}

void get_highest_preference_tls_cipher (char *buf, int size)
{
	const char *cipher_name;
	const int *ciphers = mbedtls_ssl_list_ciphersuites();
	if (*ciphers == 0){
		MM("Cannot retrieve list of supported SSL ciphers.\n");
	}

	cipher_name = mbedtls_ssl_get_ciphersuite_name(*ciphers);
	strncpynt (buf, cipher_name, size);
}

const char * get_ssl_library_version(void)
{
	static char polar_version[30];
	unsigned int pv = mbedtls_version_get_number();
	sprintf( polar_version, "MBEDTLSL %d.%d.%d",(pv>>24)&0xff, (pv>>16)&0xff, (pv>>8)&0xff );
	return polar_version;
}

#endif
