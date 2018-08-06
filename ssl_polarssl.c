#include <rain_common.h>

#ifdef POLARSSL_CONF

int mydata_index;
pthread_mutex_t mydata_mutex;

threading_mutex_t debug_mutex;
void tls_init_lib(void)
{
	pthread_mutex_init(&mydata_mutex,NULL);
	//polarssl_mutex_init( &debug_mutex );
}

void tls_free_lib(void)
{
	//polarssl_mutex_free( &debug_mutex );
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

		ctx->dhm_ctx = malloc(sizeof(dhm_context));
		memset(ctx->dhm_ctx,0x00,sizeof(dhm_context));

		ctx->ca_chain = malloc(sizeof(x509_crt));
		memset(ctx->ca_chain,0x00,sizeof(x509_crt));

		ctx->endpoint = SSL_IS_SERVER;
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
		ctx->dhm_ctx = malloc(sizeof(dhm_context));
		memset(ctx->dhm_ctx,0x00,sizeof(dhm_context));

		ctx->ca_chain = malloc(sizeof(x509_crt));
		memset(ctx->ca_chain,0x00,sizeof(x509_crt));

		ctx->endpoint = SSL_IS_CLIENT;
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
		pk_free(ctx->priv_key);
		if (ctx->priv_key){
			sfree(ctx->priv_key);
		}

		x509_crt_free(ctx->ca_chain);
		if (ctx->ca_chain){
			sfree(ctx->ca_chain);
		}

		x509_crt_free(ctx->crt_chain);
		if (ctx->crt_chain){
			sfree(ctx->crt_chain);
		}

		dhm_free(ctx->dhm_ctx);
		if (ctx->dhm_ctx){
			sfree(ctx->dhm_ctx);
		}

#if defined(ENABLE_PKCS11)
		if (ctx->priv_key_pkcs11 != NULL) {
			pkcs11_priv_key_free(ctx->priv_key_pkcs11);
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

void tls_ctx_set_options (struct tls_root_ctx *ctx, unsigned int ssl_flags)
{
	if(ctx){}
	if(ssl_flags){}
}
#if 0
typedef struct { const char *openssl_name; const char *iana_name; } tls_cipher_name_pair;
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
#endif

#if 0
void tls_ctx_restrict_ciphers(struct tls_root_ctx *ctx, const char *ciphers)
{
	size_t begin_of_cipher, end_of_cipher;
	const char *current_cipher;
	size_t current_cipher_len;
	const struct tls_cipher_name_pair *cipher_pair;
	const size_t openssl_ciphers_size = 4096;
	char openssl_ciphers[openssl_ciphers_size];
	size_t openssl_ciphers_len = 0;
	openssl_ciphers[0] = '\0';


	if(ctx == NULL){
		MM("# ERR : %s %d ctx = NULL  ##\n",__func__,__LINE__);
		exit(0);
	}
	begin_of_cipher = end_of_cipher = 0;
	for (; begin_of_cipher < strlen(ciphers); begin_of_cipher = end_of_cipher) {
		end_of_cipher += strcspn(&ciphers[begin_of_cipher], ":");
		cipher_pair = tls_get_cipher_name_pair(&ciphers[begin_of_cipher], end_of_cipher - begin_of_cipher);

		if (NULL == cipher_pair)
		{
			current_cipher = &ciphers[begin_of_cipher];
			current_cipher_len = end_of_cipher - begin_of_cipher;
			//MM("No valid translation found for TLS cipher '%.*s'\n", (int) MIN(current_cipher_len, 256), current_cipher);
		}
		else
		{
			current_cipher = cipher_pair->openssl_name;
			current_cipher_len = strlen(current_cipher);

			if (end_of_cipher - begin_of_cipher == current_cipher_len && 0 == memcmp (&ciphers[begin_of_cipher], cipher_pair->openssl_name, end_of_cipher - begin_of_cipher))
			{
				MM( "Deprecated TLS cipher name '%s', please use IANA name '%s'\n", cipher_pair->openssl_name, cipher_pair->iana_name);
			}
		}

		if (((openssl_ciphers_size-1) - openssl_ciphers_len) < current_cipher_len) {
			MM("Failed to set restricted TLS cipher list, too long (>%zu).\n", openssl_ciphers_size-1);
		}

		memcpy(&openssl_ciphers[openssl_ciphers_len], current_cipher, current_cipher_len);
		openssl_ciphers_len += current_cipher_len;
		openssl_ciphers[openssl_ciphers_len] = ':';
		openssl_ciphers_len++;

		end_of_cipher++;
	}

	if (openssl_ciphers_len > 0){
		openssl_ciphers[openssl_ciphers_len-1] = '\0';
	}

	if(!SSL_CTX_set_cipher_list(ctx->ctx, openssl_ciphers)){
		MM( "Failed to set restricted TLS cipher list: %s", openssl_ciphers);
	}
}
#endif

void tls_ctx_check_cert_time (const struct tls_root_ctx *ctx)
{
	//ASSERT (ctx);
	if (ctx->crt_chain == NULL)
	{
		return;
	}

	if (x509_time_future (&ctx->crt_chain->valid_from))
	{
		MM("WARNING: Your certificate is not yet valid!\n");
	}

	if (x509_time_expired (&ctx->crt_chain->valid_to))
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
		//if (!polar_ok(dhm_parse_dhm(ctx->dhm_ctx,(const unsigned char *) dh_inline, strlen(dh_inline)))){
		if (dhm_parse_dhm(ctx->dhm_ctx,(const unsigned char *) dh_inline, strlen(dh_inline)) < 0 ){
			MM("Cannot read inline DH parameters\n");
		}
	}
	else
	{
		//if (!polar_ok(dhm_parse_dhmfile(ctx->dhm_ctx, dh_file))){
		if (dhm_parse_dhmfile(ctx->dhm_ctx, dh_file) < 0){
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
	MM("PKCS #12 files not yet supported for PolarSSL.\n");
	return 0;
}

#ifdef ENABLE_CRYPTOAPI
void tls_ctx_load_cryptoapi(struct tls_root_ctx *ctx, const char *cryptoapi_cert)
{
	if(ctx){}
	if(cryptoapi_cert){}
	MM("Windows CryptoAPI not yet supported for PolarSSL.\n");
}
#endif /* WIN32 */

void tls_ctx_load_cert_file (struct tls_root_ctx *ctx, const char *cert_file, const char *cert_inline)
{
	//ASSERT(NULL != ctx);
	if (!ctx->crt_chain)
	{
		ctx->crt_chain = malloc(sizeof(x509_crt));
	}

	if (!strcmp (cert_file, INLINE_FILE_TAG) && cert_inline)
	{
		//if (!polar_ok(x509_crt_parse(ctx->crt_chain, (const unsigned char *) cert_inline, strlen(cert_inline)))){
		if (x509_crt_parse(ctx->crt_chain, (const unsigned char *) cert_inline, strlen(cert_inline)) < 0 ){
			MM("Cannot load inline certificate file\n");
		}
	}
	else
	{
		//if (!polar_ok(x509_crt_parse_file(ctx->crt_chain, cert_file)))
		if (x509_crt_parse_file(ctx->crt_chain, cert_file) < 0 )
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
		ctx->priv_key = malloc(sizeof(pk_context));
		memset(ctx->priv_key,0x00,sizeof(pk_context));
	}

	if (!strcmp (priv_key_file, INLINE_FILE_TAG) && priv_key_inline)
	{
		status = pk_parse_key(ctx->priv_key, (const unsigned char *) priv_key_inline, strlen(priv_key_inline),NULL, 0);

		if (POLARSSL_ERR_PK_PASSWORD_REQUIRED == status)
		{
			char passbuf[512] = {0};
			pem_password_callback(passbuf, 512, 0, NULL);
			status = pk_parse_key(ctx->priv_key,(const unsigned char *) priv_key_inline, strlen(priv_key_inline),(unsigned char *) passbuf, strlen(passbuf));
		}
	}
	else
	{
		status = pk_parse_keyfile(ctx->priv_key, priv_key_file, NULL);
		if (POLARSSL_ERR_PK_PASSWORD_REQUIRED == status)
		{
			char passbuf[512] = {0};
			pem_password_callback(passbuf, 512, 0, NULL);
			status = pk_parse_keyfile(ctx->priv_key, priv_key_file, passbuf);
		}
	}
	//if (!polar_ok(status))
	if (status < 0)
	{
#if 0
#ifdef ENABLE_MANAGEMENT
		if (management && (POLARSSL_ERR_PK_PASSWORD_MISMATCH == status))
			management_auth_failure (management, UP_TYPE_PRIVATE_KEY, NULL);
#endif
#endif
		MM("Cannot load private key file %s\n", priv_key_file);
		return 1;
	}

	//warn_if_group_others_accessible (priv_key_file);

	/* TODO: Check Private Key */
#if 0
	if (!SSL_CTX_check_private_key (ctx))
		msg (M_SSLERR, "Private key does not match the certificate");
#endif
	return 0;
}

void tls_ctx_load_ca (struct tls_root_ctx *ctx, const char *ca_file,const char *ca_inline, const char *ca_path, bool tls_server)
{
	if(tls_server){}

	if (ca_path){
		MM("ERROR: PolarSSL cannot handle the capath directive\n");
	}

	if (ca_file && !strcmp (ca_file, INLINE_FILE_TAG) && ca_inline)
	{
		//if (!polar_ok(x509_crt_parse(ctx->ca_chain,(const unsigned char *) ca_inline, strlen(ca_inline)))){
		if (x509_crt_parse(ctx->ca_chain,(const unsigned char *) ca_inline, strlen(ca_inline)) < 0){
			MM("Cannot load inline CA certificates\n");
		}
	}
	else
	{
		//if (!polar_ok(x509_crt_parse_file(ctx->ca_chain, ca_file))){
		if (x509_crt_parse_file(ctx->ca_chain, ca_file) < 0){
			MM("Cannot load CA certificate file %s\n", ca_file);
		}
	}
}

void tls_ctx_load_extra_certs (struct tls_root_ctx *ctx, const char *extra_certs_file, const char *extra_certs_inline)
{
	//ASSERT(NULL != ctx);

	if (!ctx->crt_chain)
	{
		ctx->crt_chain = malloc(sizeof(x509_crt));
		memset(ctx->crt_chain,0x00,sizeof(x509_crt));

	}

	if (!strcmp (extra_certs_file, INLINE_FILE_TAG) && extra_certs_inline)
	{
		//if (!polar_ok(x509_crt_parse(ctx->crt_chain, (const unsigned char *) extra_certs_inline,strlen(extra_certs_inline)))){
		if (x509_crt_parse(ctx->crt_chain, (const unsigned char *) extra_certs_inline,strlen(extra_certs_inline)) < 0){
			MM("Cannot load inline extra-certs file\n");
		}
	}
	else
	{
		//if (!polar_ok(x509_crt_parse_file(ctx->crt_chain, extra_certs_file))){
		if (x509_crt_parse_file(ctx->crt_chain, extra_certs_file) < 0){
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
		return POLARSSL_ERR_NET_WANT_READ;
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
		if (NULL == new_block){
			return POLARSSL_ERR_NET_SEND_FAILED;
		}

		new_block->data = malloc(len);
		if (NULL == new_block->data)
		{
			sfree(new_block);
			return POLARSSL_ERR_NET_SEND_FAILED;
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

#if 0
static void my_debug( void *ctx, int level, const char *str )
{
	if(ctx){}
	if(level){}
	if(str){}
	MM("PolarSSL msg: %s \n", str);
}
#endif

void tls_ctx_personalise_random(struct tls_root_ctx *ctx)
{
	static char old_sha256_hash[32] = {0};
	unsigned char sha256_hash[32] = {0};
	ctr_drbg_context *cd_ctx = rand_ctx_get();

	if (NULL != ctx->crt_chain)
	{
		x509_crt *cert = ctx->crt_chain;

		sha256(cert->tbs.p, cert->tbs.len, sha256_hash, false);
		if ( 0 != memcmp(old_sha256_hash, sha256_hash, sizeof(sha256_hash)))
		{
			ctr_drbg_update(cd_ctx, sha256_hash, 32);
			memcpy(old_sha256_hash, sha256_hash, sizeof(old_sha256_hash));
		}
	}
}

int tls_version_max(void)
{
	return TLS_VER_1_2;
#if 0
#if defined(SSL_MAJOR_VERSION_3) && defined(SSL_MINOR_VERSION_3)
	return TLS_VER_1_2;
#elif defined(SSL_MAJOR_VERSION_3) && defined(SSL_MINOR_VERSION_2)
	return TLS_VER_1_1;
#else
	return TLS_VER_1_0;
#endif
#endif
}

static void tls_version_to_major_minor(int tls_ver, int *major, int *minor) {
	//ASSERT(major);
	//ASSERT(minor);

	switch (tls_ver)
	{
		case TLS_VER_1_0:
			*major = SSL_MAJOR_VERSION_3;
			*minor = SSL_MINOR_VERSION_1;
			break;
		case TLS_VER_1_1:
			*major = SSL_MAJOR_VERSION_3;
			*minor = SSL_MINOR_VERSION_2;
			break;
		case TLS_VER_1_2:
			*major = SSL_MAJOR_VERSION_3;
			*minor = SSL_MINOR_VERSION_3;
			break;
		default:
			MM("%s: invalid TLS version %d \n", __func__, tls_ver);
			break;
	}
}

void key_state_ssl_init(struct epoll_ptr_data *epd,struct key_state_ssl *ks_ssl, const struct tls_root_ctx *ssl_ctx, int is_server)
{

	struct main_data *md = (struct main_data *)epd->gl_var;
	struct options *opt = md->opt;
	unsigned int ssl_flags = opt->ssl_flags;

	ks_ssl->ctx = malloc(sizeof(ssl_context));
	memset(ks_ssl->ctx,0x00,sizeof(ssl_context));

	if (ssl_init(ks_ssl->ctx) >= 0)
	{
		//debug_set_threshold(3);
		//ssl_set_dbg (ks_ssl->ctx, my_debug, NULL);

		ssl_set_endpoint (ks_ssl->ctx, ssl_ctx->endpoint);

		ssl_set_rng (ks_ssl->ctx, ctr_drbg_random, (void *)rand_ctx_get());

		if (ssl_ctx->allowed_ciphers){
			ssl_set_ciphersuites (ks_ssl->ctx, ssl_ctx->allowed_ciphers);
		}
#if 0
#if defined(POLARSSL_SSL_CBC_RECORD_SPLITTING)
		ssl_set_cbc_record_splitting (ks_ssl->ctx, SSL_CBC_RECORD_SPLITTING_DISABLED);
#endif
#endif

		if (is_server == SERVER){
			//polar_ok (ssl_set_dh_param_ctx (ks_ssl->ctx, ssl_ctx->dhm_ctx));
			ssl_set_dh_param_ctx (ks_ssl->ctx, ssl_ctx->dhm_ctx);
		}

		//polar_ok (ssl_set_own_cert (ks_ssl->ctx, ssl_ctx->crt_chain,ssl_ctx->priv_key));
		ssl_set_own_cert (ks_ssl->ctx, ssl_ctx->crt_chain,ssl_ctx->priv_key);

		if (ssl_flags & SSLF_CLIENT_CERT_NOT_REQUIRED)
		{
			MM("WARNING: POTENTIALLY DANGEROUS OPTION ""--client-cert-not-required may accept clients which do not present ""a certificate\n");
		}
		else
		{
			ssl_set_authmode (ks_ssl->ctx, SSL_VERIFY_REQUIRED);
			ssl_set_verify (ks_ssl->ctx, verify_callback, epd);
		}

		ssl_set_ca_chain (ks_ssl->ctx, ssl_ctx->ca_chain, NULL, NULL );

		{
			const int tls_version_min = (ssl_flags >> SSLF_TLS_VERSION_MIN_SHIFT) & SSLF_TLS_VERSION_MIN_MASK;

			int major = SSL_MAJOR_VERSION_3;
			int minor = SSL_MINOR_VERSION_1;

			if (tls_version_min > TLS_VER_UNSPEC){
				tls_version_to_major_minor(tls_version_min, &major, &minor);
			}

			ssl_set_min_version(ks_ssl->ctx, major, minor);
		}
		{
			const int tls_version_max = (ssl_flags >> SSLF_TLS_VERSION_MAX_SHIFT) & SSLF_TLS_VERSION_MAX_MASK;

			if (tls_version_max > TLS_VER_UNSPEC)
			{
				int major, minor;
				tls_version_to_major_minor(tls_version_max, &major, &minor);
				ssl_set_max_version(ks_ssl->ctx, major, minor);
			}
		}

		ks_ssl->ct_in = malloc(sizeof(endless_buffer));
		memset(ks_ssl->ct_in,0x00,sizeof(endless_buffer));

		ks_ssl->ct_out = malloc(sizeof(endless_buffer));
		memset(ks_ssl->ct_out,0x00,sizeof(endless_buffer));

		ssl_set_bio (ks_ssl->ctx, endless_buf_read, ks_ssl->ct_in,endless_buf_write, ks_ssl->ct_out);
	}
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
			ssl_free(ks_ssl->ctx);
			sfree(ks_ssl->ctx);
		}
		if (ks_ssl->ct_in != NULL) {
			buf_free_entries(ks_ssl->ct_in);
			sfree(ks_ssl->ct_in);
		}
		if (ks_ssl->ct_out != NULL) {
			buf_free_entries(ks_ssl->ct_out);
			sfree(ks_ssl->ct_out);
		}
		ks_ssl->ctx = NULL;
	}
}

int key_state_write_plaintext (struct key_state_ssl *ks, char *buf,int len)
{
	int retval = 0;
	if(ks != NULL){
		pthread_mutex_lock(&mydata_mutex);
		retval = ssl_write(ks->ctx, (const unsigned char *)buf,(size_t)len);
		pthread_mutex_unlock(&mydata_mutex);

		if (retval < 0)
		{
			if (POLARSSL_ERR_NET_WANT_WRITE == retval || POLARSSL_ERR_NET_WANT_READ == retval){
				return 0;
			}
			MM("TLS ERROR: write tls_write_plaintext error\n");
			return -1;
		}

		if (retval != len)
		{
			MM("TLS ERROR: write tls_write_plaintext incomplete %d/%d\n", retval,len);
			return -1;
		}

		//MM("## %s %d write tls_write_plaintext %d bytes\n",__func__,__LINE__,retval);

		memset (buf, 0, len);
		return 1;

	}else{
		return retval;
	}
}

int key_state_write_plaintext_const (struct key_state_ssl *ks, char *data, int len)
{
	int retval = 0;
	if(ks != NULL){
		pthread_mutex_lock(&mydata_mutex);
		retval = ssl_write(ks->ctx, (const unsigned char *)data, len);
		pthread_mutex_unlock(&mydata_mutex);

		if (retval < 0)
		{
			if (POLARSSL_ERR_NET_WANT_WRITE == retval || POLARSSL_ERR_NET_WANT_READ == retval){
				return 0;
			}
			MM("## ERR: %s %d ##\n",__func__,__LINE__);
			polar_log_err (1, retval, "TLS ERROR: write tls_write_plaintext_const error");
			return -1;
		}

		if (retval != len)
		{
			//MM("TLS ERROR: write tls_write_plaintext_const incomplete %d/%d\n",retval, len);
			return -1;
		}

		//MM("## %s %d write tls_write_plaintext_const %d bytes\n",__func__,__LINE__,retval);
		return 1;
	}else{
		return retval;
	}
}

int key_state_read_ciphertext (struct key_state_ssl *ks, char *buf, int len ,int maxlen)
{
	int retval = 0;
	if(ks != NULL){
		if (maxlen < len){
			len = maxlen;
		}

		pthread_mutex_lock(&mydata_mutex);
		retval = endless_buf_read(ks->ct_out, (unsigned char *)buf, len);
		pthread_mutex_unlock(&mydata_mutex);

		if (retval < 0)
		{
			if (POLARSSL_ERR_NET_WANT_WRITE == retval || POLARSSL_ERR_NET_WANT_READ == retval){
				return 0;
			}
			MM("## ERR: %s %d ##\n",__func__,__LINE__);
			polar_log_err (1, retval, "TLS_ERROR: read tls_read_ciphertext error");
			return -1;
		}
		if (0 == retval)
		{
			return 0;
		}

		//MM("read tls_read_ciphertext %d bytes\n", retval);
	}
	return retval;
}


int key_state_write_ciphertext (struct key_state_ssl *ks, char *buf,int len)
{
	int retval = 0;
	if(ks != NULL){
		pthread_mutex_lock(&mydata_mutex);
		retval = endless_buf_write(ks->ct_in, (const unsigned char *)buf, len);
		pthread_mutex_unlock(&mydata_mutex);

		if (retval < 0)
		{
			if (POLARSSL_ERR_NET_WANT_WRITE == retval || POLARSSL_ERR_NET_WANT_READ == retval){
				return 0;
			}
			MM("## ERR: %s %d ##\n",__func__,__LINE__);
			polar_log_err (1, retval,"TLS ERROR: write tls_write_ciphertext error");
			return -1;
		}

		if (retval != len)
		{
			MM("TLS ERROR: write tls_write_ciphertext incomplete %d/%d\n",retval, len);
			return -1;
		}

		//MM("## %s %d write tls_write_ciphertext %d bytes\n",__func__,__LINE__,retval);

		memset (buf, 0, len);
		return 1;

	}else{
		return 0;
	}
}

int key_state_read_plaintext (struct key_state_ssl *ks, char *buf,int len, int maxlen)
{

	int retval = 0;
	if(ks != NULL){
		if (maxlen < len){
			len = maxlen;
		}
		pthread_mutex_lock(&mydata_mutex);
		retval = ssl_read(ks->ctx, (unsigned char *)buf, len);
		pthread_mutex_unlock(&mydata_mutex);
		if (retval < 0)
		{
			if (POLARSSL_ERR_NET_WANT_WRITE == retval || POLARSSL_ERR_NET_WANT_READ == retval){
				return 0;
			}
			MM("## ERR: %s %d %d ##\n",__func__,__LINE__,retval);
			polar_log_err (1, retval, "TLS_ERROR: read tls_read_plaintext error");
			return -1;
		}
		if (0 == retval)
		{
			MM("## %s %d retval : 0##\n",__func__,__LINE__);
			return 0;
		}

		//MM("## %s %d read tls_read_plaintext %d bytes\n",__func__,__LINE__,retval);
	}
	return retval;
}

void print_details (struct key_state_ssl * ks_ssl, const char *prefix)
{
	const x509_crt *cert;
	char s1[256];
	char s2[256];

	s1[0] = s2[0] = 0;
	snprintf (s1, sizeof (s1), "%s %s, cipher %s",
			prefix,
			ssl_get_version (ks_ssl->ctx),
			ssl_get_ciphersuite(ks_ssl->ctx));

	cert = ssl_get_peer_cert(ks_ssl->ctx);
	if (cert != NULL)
	{
		snprintf (s2, sizeof (s2), ", %zu bit key", pk_get_size(&cert->pk));
	}

	MM("%s%s\n", s1, s2);
}

void show_available_tls_ciphers (const char *cipher_list)
{
	if(cipher_list){}
#if 0
	struct tls_root_ctx tls_ctx;
	const int *ciphers = ssl_list_ciphersuites();

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
	const int *ciphers = ssl_list_ciphersuites();
	if (*ciphers == 0){
		MM("Cannot retrieve list of supported SSL ciphers.\n");
	}

	cipher_name = ssl_get_ciphersuite_name(*ciphers);
	strncpynt (buf, cipher_name, size);
}

const char * get_ssl_library_version(void)
{
	static char polar_version[30];
	unsigned int pv = version_get_number();
	sprintf( polar_version, "PolarSSL %d.%d.%d",(pv>>24)&0xff, (pv>>16)&0xff, (pv>>8)&0xff );
	return polar_version;
}

#endif
