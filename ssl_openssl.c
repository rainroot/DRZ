#include <rain_common.h>

#ifdef OPENSSL_CONF

int mydata_index;
pthread_mutex_t mydata_mutex;


int tls_init_lib(void)
{

	SSL_library_init();
	SSL_load_error_strings();
	OpenSSL_add_all_algorithms ();
	mydata_index = SSL_get_ex_new_index(0, "struct session *", NULL, NULL, NULL);
	//MM("## %s %d %d ##\n",__func__,__LINE__,mydata_index);
	
	pthread_mutex_init(&mydata_mutex,NULL);
	return mydata_index;
}

void tls_free_lib(void)
{
	EVP_cleanup();
	ERR_free_strings();
}

void tls_clear_error()
{
	ERR_clear_error();
}
#if 0
RSA * tmp_rsa_cb (SSL * s, int b, int keylength)
{
	static RSA *rsa_tmp = NULL;

	if(s){}
	if(b){}

	if (rsa_tmp == NULL)
	{
		BIGNUM *bn = BN_new();
		rsa_tmp = RSA_new();

		MM("Generating temp (%d bit) RSA key", keylength);

		if(!bn || !BN_set_word(bn, RSA_F4) || !RSA_generate_key_ex(rsa_tmp, keylength, bn, NULL)){
			MM( "Failed to generate temp RSA key");
		}

		if (bn){
			BN_free( bn );
		}
	}
	return (rsa_tmp);
}
#endif

void tls_ctx_server_new(struct tls_root_ctx *ctx, unsigned int ssl_flags)
{
	if(ssl_flags){}
	printf("############# %s %d #################################=================================\n",__func__,__LINE__);
	//const int tls_version_min = (ssl_flags >> SSLF_TLS_VERSION_SHIFT) & SSLF_TLS_VERSION_MASK;
	if(ctx == NULL){
		MM("# ERR: EXIT()  %s %d ctx = NULL  ##\n",__func__,__LINE__);
		exit(0);
	}else{

#if 0
		if (tls_version_min > TLS_VER_UNSPEC){
			ctx->ctx = SSL_CTX_new (SSLv23_server_method ());
		}else{
			ctx->ctx = SSL_CTX_new (TLSv1_server_method ());
		}
#else
		ctx->ctx = SSL_CTX_new (SSLv23_server_method ());

#endif

		if (ctx->ctx == NULL){
			MM( "SSL_CTX_new SSLv23_server_method");
		}

		//SSL_CTX_set_tmp_rsa_callback (ctx->ctx, tmp_rsa_cb);

	}
}

void tls_ctx_client_new(struct tls_root_ctx *ctx, unsigned int ssl_flags)
{
	if(ssl_flags){}

	//const int tls_version_min = (ssl_flags >> SSLF_TLS_VERSION_SHIFT) & SSLF_TLS_VERSION_MASK;

	if(ctx == NULL){
		MM("# ERR : EXIT() %s %d ctx = NULL  ##\n",__func__,__LINE__);
		exit(0);
	}else{

#if 0
		if (tls_version_min > TLS_VER_UNSPEC){
			ctx->ctx = SSL_CTX_new (SSLv23_client_method ());
		}else{
			ctx->ctx = SSL_CTX_new (TLSv1_client_method ());
		}
#else

		ctx->ctx = SSL_CTX_new (SSLv23_client_method ());
#endif

		if (ctx->ctx == NULL){
			MM("ERR : EXIT() %s %d SSL_CTX_new SSLv23_client_method\n",__func__,__LINE__);
			exit(0);
		}
	}
}

void tls_ctx_free(struct tls_root_ctx *ctx)
{
	if(ctx == NULL){
		MM("# ERR :  EXIT() %s %d ctx = NULL  ##\n",__func__,__LINE__);
		exit(0);
	}else{
		if (NULL != ctx->ctx){
			SSL_CTX_free (ctx->ctx);
		}
		ctx->ctx = NULL;
	}
}

bool tls_ctx_initialised(struct tls_root_ctx *ctx)
{
	if(ctx == NULL){
		MM("# ERR : EXIT() %s %d ctx = NULL  ##\n",__func__,__LINE__);
		exit(0);
	}
	return NULL != ctx->ctx;
}

void info_callback (SSL * s, int where, int ret)
{

	if(s){}
	if(where){}
	if(ret){}
#if 0
	if (where & SSL_CB_LOOP)
	{
		MM("SSL state (%s): %s \n", where & SSL_ST_CONNECT ? "connect" :where & SSL_ST_ACCEPT ? "accept" :"undefined", SSL_state_string_long (s));
	}
	else if (where & SSL_CB_ALERT)
	{
		MM( "SSL alert (%s): %s: %s \n", where & SSL_CB_READ ? "read" : "write", SSL_alert_type_string_long (ret),SSL_alert_desc_string_long (ret));
	}
#endif
}

int tls_version_max(void)
{
	return TLS_VER_1_2;
}

void tls_ctx_set_options (struct tls_root_ctx *ctx, unsigned int ssl_flags)
{

	if(ctx == NULL){
		MM("# ERR : EXIT() %s %d ctx = NULL  ##\n",__func__,__LINE__);
		exit(0);
	}
	{
		long sslopt = SSL_OP_SINGLE_DH_USE | SSL_OP_NO_TICKET | SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3;
		const int tls_version_min = (ssl_flags >> SSLF_TLS_VERSION_SHIFT) & SSLF_TLS_VERSION_MASK;
		if (tls_version_min > TLS_VER_1_0){
			sslopt |= SSL_OP_NO_TLSv1;
		}
		if (tls_version_min > TLS_VER_1_1){
			sslopt |= SSL_OP_NO_TLSv1_1;
		}
		if (tls_version_min > TLS_VER_1_2){
			sslopt |= SSL_OP_NO_TLSv1_2;
		}
		SSL_CTX_set_options (ctx->ctx, sslopt);
	}

	SSL_CTX_set_mode(ctx->ctx, SSL_MODE_RELEASE_BUFFERS);
	SSL_CTX_set_session_cache_mode (ctx->ctx, SSL_SESS_CACHE_OFF);
	SSL_CTX_set_default_passwd_cb (ctx->ctx, pem_password_callback);
	//SSL_CTX_set_default_passwd_cb (ctx->ctx, NULL);

	if (ssl_flags & SSLF_CLIENT_CERT_NOT_REQUIRED)
	{
		MM("WARNING: POTENTIALLY DANGEROUS OPTION "
				"--client-cert-not-required may accept clients which do not present "
				"a certificate\n");
	}else{
		SSL_CTX_set_verify (ctx->ctx, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, verify_callback); //rainroot
		SSL_CTX_set_info_callback (ctx->ctx, (void*)info_callback);
	}
}
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

void tls_ctx_load_dh_params (struct tls_root_ctx *ctx, const char *dh_file, const char *dh_file_inline)
{
	DH *dh;
	BIO *bio;

	if(ctx == NULL){
		MM("# ERR : %s %d ctx = NULL  ##\n",__func__,__LINE__);
		exit(0);
	}
	if (!strcmp (dh_file, INLINE_FILE_TAG) && dh_file_inline)
	{
		if (!(bio = BIO_new_mem_buf ((char *)dh_file_inline, -1))){
			MM("ERR: Cannot open memory BIO for inline DH parameters\n");
		}
	}
	else
	{
		if (!(bio = BIO_new_file (dh_file, "r"))){
			MM( "ERR: Cannot open %s for DH parameters \n", dh_file);
		}
	}

	dh = PEM_read_bio_DHparams (bio, NULL, NULL, NULL);
	BIO_free (bio);

	if (!dh){
		MM( "ERR: Cannot load DH parameters from %s \n", dh_file);
	}
	if (!SSL_CTX_set_tmp_dh (ctx->ctx, dh)){
		MM( "ERR: SSL_CTX_set_tmp_dh \n");
	}

	MM("Diffie-Hellman initialized with %d bit key \n",8 * DH_size (dh));

	DH_free (dh);
}

int tls_ctx_load_pkcs12(struct tls_root_ctx *ctx, char *pkcs12_file,char *pkcs12_file_inline,bool load_ca_file)
{
	FILE *fp;
	EVP_PKEY *pkey;
	X509 *cert;
	STACK_OF(X509) *ca = NULL;
	PKCS12 *p12;
	int i;
	char password[256];

	if(ctx == NULL){
		MM("# ERR : %s %d ctx = NULL  ##\n",__func__,__LINE__);
		exit(0);
	}
	if (!strcmp (pkcs12_file, INLINE_FILE_TAG) && pkcs12_file_inline)
	{
		BIO *b64 = BIO_new(BIO_f_base64());
		BIO *bio = BIO_new_mem_buf((void *) pkcs12_file_inline, (int) strlen(pkcs12_file_inline));

		if((b64 == NULL) || (bio == NULL)){
			MM("# ERR : %s %d ctx = NULL  ##\n",__func__,__LINE__);
			exit(0);

		}

		BIO_push(b64, bio);
		p12 = d2i_PKCS12_bio(b64, NULL);
		if (p12 == NULL){
			MM( "Error reading inline PKCS#12 file\n");
		}
		BIO_free(b64);
		BIO_free(bio);
	}
	else
	{
		if (!(fp = fopen(pkcs12_file, "rb"))){
			MM("Error opening file %s\n", pkcs12_file);
		}
		p12 = d2i_PKCS12_fp(fp, NULL);
		fclose(fp);
		if (p12==NULL){
			MM( "Error reading PKCS#12 file %s\n", pkcs12_file);
		}
	}

	if (!PKCS12_parse(p12, "", &pkey, &cert, &ca))
	{
		//pem_password_callback (password, sizeof(password) - 1, 0, NULL);
		ca = NULL;
		if (!PKCS12_parse(p12, password, &pkey, &cert, &ca))
		{
			PKCS12_free(p12);
			return 1;
		}
	}
	PKCS12_free(p12);

	if (!SSL_CTX_use_certificate (ctx->ctx, cert)){
		MM("Cannot use certificate\n");
	}

	if (!SSL_CTX_use_PrivateKey (ctx->ctx, pkey)){
		MM("Cannot use private key\n");
	}
	//warn_if_group_others_accessible (pkcs12_file);

	if (!SSL_CTX_check_private_key (ctx->ctx)){
		MM( "Private key does not match the certificate\n");
	}

	if (load_ca_file)
	{
		if (ca && sk_X509_num(ca))
		{
			for (i = 0; i < sk_X509_num(ca); i++)
			{
				X509_STORE *cert_store = SSL_CTX_get_cert_store(ctx->ctx);
				if (!X509_STORE_add_cert(cert_store,sk_X509_value(ca, i))){
					MM( "Cannot add certificate to certificate chain (X509_STORE_add_cert)\n");
				}
				if (!SSL_CTX_add_client_CA(ctx->ctx, sk_X509_value(ca, i))){
					MM("Cannot add certificate to client CA list (SSL_CTX_add_client_CA)\n");
				}
			}
		}
	} else {
		if (ca && sk_X509_num(ca))
		{
			for (i = 0; i < sk_X509_num(ca); i++)
			{
				if (!SSL_CTX_add_extra_chain_cert(ctx->ctx,sk_X509_value(ca, i))){
					MM("Cannot add extra certificate to chain (SSL_CTX_add_extra_chain_cert)\n");
				}
			}
		}
	}
	return 0;
}

void tls_ctx_add_extra_certs (struct tls_root_ctx *ctx, BIO *bio)
{
	X509 *cert;
	for (;;)
	{
		cert = NULL;
		if (!PEM_read_bio_X509 (bio, &cert, 0, NULL)){
			break;
		}
		if (!cert){
			MM( "Error reading extra certificate\n");
		}
		if (SSL_CTX_add_extra_chain_cert(ctx->ctx, cert) != 1){
			MM("Error adding extra certificate\n");
		}
	}
}

void tls_ctx_load_cert_file_and_copy (struct tls_root_ctx *ctx, const char *cert_file, const char *cert_file_inline, X509 **x509)
{
	BIO *in = NULL;
	X509 *x = NULL;
	int ret = 0;
	bool inline_file = false;

	if(ctx == NULL){
		MM("# ERR : %s %d ctx = NULL  ##\n",__func__,__LINE__);
		exit(0);
	}
	if (NULL != x509){
		if(*x509 == NULL){
			MM("# ERR : %s %d ctx = NULL  ##\n",__func__,__LINE__);
			exit(0);
		}
	}

	inline_file = (strcmp (cert_file, INLINE_FILE_TAG) == 0);

	if (inline_file && cert_file_inline){
		in = BIO_new_mem_buf ((char *)cert_file_inline, -1);
	}else{
		in = BIO_new_file (cert_file, "r");
	}

	if (in == NULL)
	{
		SSLerr (SSL_F_SSL_CTX_USE_CERTIFICATE_FILE, ERR_R_SYS_LIB);
		goto end;
	}

	//x = PEM_read_bio_X509 (in, NULL, ctx->ctx->default_passwd_callback, ctx->ctx->default_passwd_callback_userdata);
	x = PEM_read_bio_X509 (in, NULL, SSL_CTX_get_default_passwd_cb(ctx->ctx), SSL_CTX_get_default_passwd_cb_userdata(ctx->ctx));
	if (x == NULL)
	{
		MM("## ERR: %s %d ##\n",__func__,__LINE__);
		SSLerr (SSL_F_SSL_CTX_USE_CERTIFICATE_FILE, ERR_R_PEM_LIB);
		goto end;
	}

	ret = SSL_CTX_use_certificate (ctx->ctx, x);
	if (ret){
		tls_ctx_add_extra_certs (ctx, in);
	}

end:
	if (!ret)
	{
		if (inline_file){
			MM("Cannot load inline certificate file\n");
		}else{
			MM( "ERR: %s %d  Cannot load certificate file %s\n",__func__,__LINE__, cert_file);
		}
	}

	if (in != NULL){
		BIO_free(in);
	}
	if (x509){
		*x509 = x;
	}else if (x){
		X509_free (x);
	}
}

void tls_ctx_load_cert_file (struct tls_root_ctx *ctx, const char *cert_file,const char *cert_file_inline)
{
	tls_ctx_load_cert_file_and_copy (ctx, cert_file, cert_file_inline, NULL);
}

void tls_ctx_free_cert_file (X509 *x509)
{
	X509_free(x509);
}

int tls_ctx_load_priv_file (struct tls_root_ctx *ctx, const char *priv_key_file,const char *priv_key_file_inline)
{
	//int status;
	SSL_CTX *ssl_ctx = NULL;
	BIO *in = NULL;
	EVP_PKEY *pkey = NULL;
	int ret = 1;

	if(ctx == NULL){
		MM("# ERR : %s %d ctx = NULL  ##\n",__func__,__LINE__);
		exit(0);
	}

	ssl_ctx = ctx->ctx;

	if (!strcmp (priv_key_file, INLINE_FILE_TAG) && priv_key_file_inline){
		in = BIO_new_mem_buf ((char *)priv_key_file_inline, -1);
	}else{
		in = BIO_new_file (priv_key_file, "r");
	}

	if (!in){
		goto end;
	}

	//pkey = PEM_read_bio_PrivateKey (in, NULL,ssl_ctx->default_passwd_callback,ssl_ctx->default_passwd_callback_userdata);
	pkey = PEM_read_bio_PrivateKey (in, NULL,SSL_CTX_get_default_passwd_cb(ctx->ctx),SSL_CTX_get_default_passwd_cb_userdata(ctx->ctx));
	if (!pkey){
		goto end;
	}

	if (!SSL_CTX_use_PrivateKey (ssl_ctx, pkey))
	{
		MM("Cannot load private key file %s\n", priv_key_file);
		goto end;
	}
	//warn_if_group_others_accessible (priv_key_file);

	if (!SSL_CTX_check_private_key (ssl_ctx)){
		MM("Private key does not match the certificate");
	}
	ret = 0;

end:
	if (pkey){
		EVP_PKEY_free (pkey);
	}
	if (in){
		BIO_free (in);
	}
	return ret;
}

int sk_x509_name_cmp(const X509_NAME * const *a, const X509_NAME * const *b)
{
	return X509_NAME_cmp (*a, *b);
}

void tls_ctx_load_ca (struct tls_root_ctx *ctx, const char *ca_file,const char *ca_file_inline,const char *ca_path, bool tls_server)
{
	STACK_OF(X509_INFO) *info_stack = NULL;
	STACK_OF(X509_NAME) *cert_names = NULL;
	X509_LOOKUP *lookup = NULL;
	X509_STORE *store = NULL;
	X509_NAME *xn = NULL;
	BIO *in = NULL;
	int i, added = 0, prev = 0;


	if(ctx == NULL){
		MM("# ERR : %s %d ctx = NULL  ##\n",__func__,__LINE__);
		exit(0);
	}
	store = SSL_CTX_get_cert_store(ctx->ctx);
	if (!store){
		MM("Cannot get certificate store (SSL_CTX_get_cert_store)\n");
	}

	if (ca_file)
	{
		if (!strcmp (ca_file, INLINE_FILE_TAG) && ca_file_inline){
			in = BIO_new_mem_buf ((char *)ca_file_inline, -1);
		}else{
			in = BIO_new_file (ca_file, "r");
		}

		if (in){
			info_stack = PEM_X509_INFO_read_bio (in, NULL, NULL, NULL);
		}

		if (info_stack)
		{
			for (i = 0; i < sk_X509_INFO_num (info_stack); i++)
			{
				X509_INFO *info = sk_X509_INFO_value (info_stack, i);
				if (info->crl){
					X509_STORE_add_crl (store, info->crl);
				}

				if (tls_server && !info->x509)
				{
					MM("X509 name was missing in TLS mode\n");
				}

				if (info->x509)
				{
					X509_STORE_add_cert (store, info->x509);
					added++;

					if (!tls_server){
						continue;
					}

					if (cert_names == NULL)
					{
						cert_names = sk_X509_NAME_new (sk_x509_name_cmp);
						if (!cert_names){
							continue;
						}
					}

					xn = X509_get_subject_name (info->x509);
					if (!xn){
						continue;
					}

					if (sk_X509_NAME_find (cert_names, xn) == -1)
					{
						xn = X509_NAME_dup (xn);
						if (!xn){
							continue;
						}
						sk_X509_NAME_push (cert_names, xn);
					}
				}

				if (tls_server) {
					int cnum = sk_X509_NAME_num (cert_names);
					if (cnum != (prev + 1)) {
						//MM( "Cannot load CA certificate file %s (entry %d did not validate)\n", np(ca_file), added);
					}
					prev = cnum;
				}

			}
			sk_X509_INFO_pop_free (info_stack, X509_INFO_free);
		}

		if (tls_server){
			SSL_CTX_set_client_CA_list (ctx->ctx, cert_names);
		}

		if (!added){
			//MM("Cannot load CA certificate file %s (no entries were read)\n", np(ca_file));
		}

		if (tls_server) {
			int cnum = sk_X509_NAME_num (cert_names);
			if (cnum != added){
				//MM( "Cannot load CA certificate file %s (only %d of %d entries were valid X509 names)\n", np(ca_file), cnum, added);
			}
		}

		if (in){
			BIO_free (in);
		}
	}

	if (ca_path)
	{
		lookup = X509_STORE_add_lookup (store, X509_LOOKUP_hash_dir ());
		if (lookup && X509_LOOKUP_add_dir (lookup, ca_path, X509_FILETYPE_PEM)){
			MM( "WARNING: experimental option --capath %s", ca_path);
		}else{
			MM( "Cannot add lookup at --capath %s", ca_path);
		}
		X509_STORE_set_flags (store, X509_V_FLAG_CRL_CHECK | X509_V_FLAG_CRL_CHECK_ALL);
	}
}

void tls_ctx_load_extra_certs (struct tls_root_ctx *ctx, const char *extra_certs_file,const char *extra_certs_file_inline)
{
	BIO *in;
	if (!strcmp (extra_certs_file, INLINE_FILE_TAG) && extra_certs_file_inline){
		in = BIO_new_mem_buf ((char *)extra_certs_file_inline, -1);
	}else{
		in = BIO_new_file (extra_certs_file, "r");
	}

	if (in == NULL){
		MM("Cannot load extra-certs file: %s\n", extra_certs_file);
	}else{
		tls_ctx_add_extra_certs (ctx, in);
	}
	BIO_free (in);
}


BIO * getbio (const BIO_METHOD * type, const char *desc)
{
	BIO *ret;
	ret = BIO_new (type);
	if (!ret){
		MM( "Error creating %s BIO\n", desc);
	}
	return ret;
}

int bio_write (BIO *bio, char *data, int size, const char *desc)
{
	int i;
	//int ret = 0;
	if(size <= 0){
		MM("## ERR size %d %s %d ##\n",size,__func__,__LINE__);
		return -1;
	}
	if (size)
	{
		i = BIO_write (bio, data, size);

		if (i < 0)
		{
			if (BIO_should_retry (bio))
			{
				i=0;
			}
			else
			{
				MM("TLS ERROR: BIO write %s error\n", desc);
				i=1;
				ERR_clear_error ();
			}
		}
		else if (i != size)
		{
			MM("TLS ERROR: BIO write %s incomplete %d/%d \n", desc, i, size);
			i=-1;
			ERR_clear_error ();
		}
		else
		{
			//MM("BIO write %s %d bytes\n", desc, i);
			i=1;
			//ret = 1;
		}
	}
	return i;
}


void bio_write_post (const int status, char *buf,int size)
{
	if (status == 1)
	{
		memset (buf, 0,size);
	}
}

int bio_read (BIO *bio, char *buf,int size, int maxlen, const char *desc)
{
	int i;
	//int ret = 0;
	if (maxlen < size){
		size = maxlen;
	}

	i = BIO_read (bio, buf,size);

	if (i < 0)
	{
		if (BIO_should_retry (bio))
		{
			i = 0;
		}
		else
		{
			MM( "TLS_ERROR: BIO read %s error \n", desc);
			i = -1;
			ERR_clear_error ();
		}
	}else if(!i){
		MM("################# BIO ERR %s %d ###########\n",__func__,__LINE__);
	}else {
		//MM( "BIO read %s %d bytes\n", desc, i);
	}
	return i;
}

//void key_state_ssl_init(struct key_state_ssl *ks_ssl, const struct tls_root_ctx *ssl_ctx, bool is_server, int mydata_index)
void key_state_ssl_init(struct epoll_ptr_data *epd,struct key_state_ssl *ks_ssl, const struct tls_root_ctx *ssl_ctx, int mode)
{
	if(ks_ssl->ssl == NULL){
		ks_ssl->ssl = SSL_new (ssl_ctx->ctx);
		if (!ks_ssl->ssl){
			MM("## ERR: SSL_new failed %s %d ##\n",__func__,__LINE__);
		}

		SSL_set_ex_data (ks_ssl->ssl, mydata_index, epd); // rainroot <---- tls_session

		ks_ssl->ssl_bio = getbio (BIO_f_ssl (), "ssl_bio");
		ks_ssl->ct_in = getbio (BIO_s_mem (), "ct_in");
		ks_ssl->ct_out = getbio (BIO_s_mem (), "ct_out");

		if (mode == SERVER){
			SSL_set_accept_state (ks_ssl->ssl);
		}else if(mode == CLIENT){
			SSL_set_connect_state (ks_ssl->ssl);
		}

		SSL_set_bio (ks_ssl->ssl, ks_ssl->ct_in, ks_ssl->ct_out);
		BIO_set_ssl (ks_ssl->ssl_bio, ks_ssl->ssl, BIO_NOCLOSE);

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
					//printf("## %s %d decrypt free xx %d i %d ##\n",__func__,__LINE__,xx,i);
					free_key_ctx(&epd->ss->sk[i].key.decrypt,xx);
				}
			}
			if(epd->ss->sk[i].key.encrypt.cipher != NULL){
				for(xx = 0; xx < (int)opt->core;xx++){
					//printf("## %s %d encrypt free xx %d i %d ##\n",__func__,__LINE__,xx,i);
					free_key_ctx(&epd->ss->sk[i].key.encrypt,xx);
				}
			}
			if(epd->ss->sk[i].prb != NULL){
				//printf("## %s %d prb free %d ##\n",__func__,__LINE__,i);
				sfree(epd->ss->sk[i].prb,epd->ss->sk[i].prb_len);
				epd->ss->sk[i].prb = NULL;
				epd->ss->sk[i].prb_len = 0;
			}
			if(epd->ss->sk[i].pwb != NULL){
				//printf("## %s %d pwb free %d ##\n",__func__,__LINE__,i);
				sfree(epd->ss->sk[i].pwb,epd->ss->sk[i].pwb_len);
				epd->ss->sk[i].pwb = NULL;
				epd->ss->sk[i].pwb_len = 0;
			}

			if(epd->ss->sk[i].ks_ssl != NULL){
				key_state_ssl_free(epd->ss->sk[i].ks_ssl,false);
				sfree(epd->ss->sk[i].ks_ssl,sizeof(struct key_state_ssl));
				epd->ss->sk[i].ks_ssl = NULL;
			}
		}
	}else{
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
				sfree(epd->ss->sk[delid].prb,epd->ss->sk[delid].prb_len);
				epd->ss->sk[delid].prb = NULL;
				epd->ss->sk[delid].prb_len = 0;
			}
			if(epd->ss->sk[delid].pwb != NULL){
				sfree(epd->ss->sk[delid].pwb,epd->ss->sk[delid].pwb_len);
				epd->ss->sk[delid].pwb = NULL;
				epd->ss->sk[delid].pwb_len = 0;
			}

			if(epd->ss->sk[delid].ks_ssl != NULL){
				key_state_ssl_free(epd->ss->sk[delid].ks_ssl,false);
				sfree(epd->ss->sk[delid].ks_ssl,sizeof(struct key_state_ssl));
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
			sfree(epd->ss->sk[delid].prb,epd->ss->sk[delid].prb_len);
			epd->ss->sk[delid].prb = NULL;
			epd->ss->sk[delid].prb_len = 0;
		}
		if(epd->ss->sk[delid].pwb != NULL){
			sfree(epd->ss->sk[delid].pwb,epd->ss->sk[delid].pwb_len);
			epd->ss->sk[delid].pwb = NULL;
			epd->ss->sk[delid].pwb_len = 0;
		}

		if(epd->ss->sk[delid].ks_ssl != NULL){
			key_state_ssl_free(epd->ss->sk[delid].ks_ssl,false);
			sfree(epd->ss->sk[delid].ks_ssl,sizeof(struct key_state_ssl));
			epd->ss->sk[delid].ks_ssl = NULL;
		}


		epd->ss->sk[delid].state = S_UNDEF;
	}
}

void key_state_ssl_free(struct key_state_ssl *ks_ssl,bool all)
{
	if(ks_ssl){}
	if(all){}
#if 0
	if(all == true){
#if 0
		if(ks_ssl->ct_in != NULL){
			BIO_free(ks_ssl->ct_in);
			BIO_free_all(ks_ssl->ct_in);
			ks_ssl->ct_in = NULL;
		}
		if(ks_ssl->ct_out != NULL){
			BIO_free(ks_ssl->ct_out);
			BIO_free_all(ks_ssl->ct_out);
			ks_ssl->ct_out = NULL;
		}
		if(ks_ssl->ssl_bio != NULL){

			BIO_free(ks_ssl->ssl_bio);
			BIO_free_all(ks_ssl->ssl_bio);
			ks_ssl->ssl_bio = NULL;
		}
#else

		if (ks_ssl->ssl != NULL) {
			//BIO_free_all(ks_ssl->ssl_bio);
			//SSL_set_shutdown(ks_ssl->ssl_bio,SSL_SENT_SHUTDOWN|SSL_RECEIVED_SHUTDOWN);
			//SSL_shutdown(ks_ssl->ssl);

			SSL_free (ks_ssl->ssl);
			BIO_free_all(ks_ssl->ssl_bio);

			ks_ssl->ssl = NULL;

		}

#endif
	}else{

		if (ks_ssl->ssl != NULL) {
			//BIO_free_all(ks_ssl->ssl_bio);
			//SSL_set_shutdown(ks_ssl->ssl_bio,SSL_SENT_SHUTDOWN|SSL_RECEIVED_SHUTDOWN);
			//SSL_shutdown(ks_ssl->ssl);

			BIO_free(ks_ssl->ssl_bio);
			BIO_free(ks_ssl->ct_in);
			BIO_free(ks_ssl->ct_out);
			SSL_free(ks_ssl->ssl);

			//BIO_free_all(ks_ssl->ssl_bio);
			ks_ssl->ssl = NULL;

		}

	}
	//SHUTDOWN(SSL_get_fd(ks_ssl->ssl));
	//ERR_remove_state(0);
	//CRYPTO_cleanup_all_ex_data();
	ERR_free_strings();
	ERR_remove_thread_state(0);
	//EVP_cleanup();
	//
	//
#else

	//BIO_free(ks_ssl->ct_in);
	//BIO_free(ks_ssl->ct_out);
	//BIO_free(ks_ssl->ssl_bio);
#if 1
	BIO_free_all(ks_ssl->ssl_bio);
	SSL_free(ks_ssl->ssl);
#endif

	//ks_ssl->ssl_bio = NULL;
	ks_ssl->ssl = NULL;
#endif
}

int key_state_write_plaintext (struct key_state_ssl *ks_ssl, char *buf,int size)
{
	int ret = 0;
	if(ks_ssl == NULL){
		MM("## ERR: %s %d ##\n",__func__,__LINE__);
		return -1;
	}
	if(ks_ssl->ssl_bio == NULL){
		MM("## ERR: %s %d ##\n",__func__,__LINE__);
		return -1;
	}

	pthread_mutex_lock(&mydata_mutex);
	ret = bio_write (ks_ssl->ssl_bio, buf, size , "tls_write_plaintext");
	pthread_mutex_unlock(&mydata_mutex);
	return ret;
}

int key_state_write_plaintext_const (struct key_state_ssl *ks_ssl, char *data, int len)
{
	int ret = 0;
	if(ks_ssl == NULL){
		MM("## ERR: %s %d ##\n",__func__,__LINE__);
		return -1;
	}
	if(ks_ssl->ssl_bio == NULL){
		MM("## ERR: %s %d ##\n",__func__,__LINE__);
		return -1;
	}

	pthread_mutex_lock(&mydata_mutex);
	ret = bio_write (ks_ssl->ssl_bio, data, len, "tls_write_plaintext_const");
	pthread_mutex_unlock(&mydata_mutex);

	return ret;
}

int key_state_read_ciphertext (struct key_state_ssl *ks_ssl, char *buf, int size ,int maxlen)
{
	int ret = 0;
	if(ks_ssl == NULL){
		MM("## ERR: %s %d ##\n",__func__,__LINE__);
		return -1;
	}
	if(ks_ssl->ct_out == NULL){
		MM("## ERR: %s %d ##\n",__func__,__LINE__);
		return -1;
	}


	pthread_mutex_lock(&mydata_mutex);
	ret = bio_read (ks_ssl->ct_out, buf,size, maxlen, "tls_read_ciphertext");
	pthread_mutex_unlock(&mydata_mutex);
	return ret;
}

int key_state_write_ciphertext (struct key_state_ssl *ks_ssl, char *buf,int size)
{
	int ret = 0;
	if(ks_ssl == NULL){
		MM("## ERR: %s %d ##\n",__func__,__LINE__);
		return -1;
	}
	if(ks_ssl->ct_in == NULL){
		MM("## ERR: %s %d ##\n",__func__,__LINE__);
		return -1;
	}

	pthread_mutex_lock(&mydata_mutex);
	ret = bio_write (ks_ssl->ct_in, buf, size, "tls_write_ciphertext");
	pthread_mutex_unlock(&mydata_mutex);
	memset(buf,0x00,size);
	return ret;
}

int key_state_read_plaintext (struct key_state_ssl *ks_ssl, char *buf,int size, int maxlen)
{
	int ret = 0;
	if(ks_ssl == NULL){
		MM("## ERR: %s %d ##\n",__func__,__LINE__);
		return -1;
	}
	if(ks_ssl->ssl_bio == NULL){
		MM("## ERR: %s %d ##\n",__func__,__LINE__);
		return -1;
	}

	pthread_mutex_lock(&mydata_mutex);
	ret = bio_read (ks_ssl->ssl_bio, buf,size, maxlen, "tls_read_plaintext");
	pthread_mutex_unlock(&mydata_mutex);
	return ret;
}

const char * get_ssl_library_version(void)
{
	return SSLeay_version(SSLEAY_VERSION);
}
#endif


