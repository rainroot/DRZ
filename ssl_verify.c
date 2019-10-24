#include <rain_common.h>

void set_common_name (struct epoll_ptr_data *epd,char *common_name)
{

	struct ssl_state *ss=NULL;
	ss = (struct ssl_state *)epd->ss;

	if (ss->common_name != NULL)
	{
		sfree (ss->common_name,ss->common_name_length);
		ss->common_name = NULL;
#if 0
#ifdef ENABLE_PF
		session->common_name_hashval = 0;
#endif
#endif
	}
	if (common_name != NULL)
	{
		if(ss->common_name == NULL){
			ss->common_name = malloc (strlen(common_name)+1);
			memset(ss->common_name,0x00,strlen(common_name)+1);
			ss->common_name_length = strlen(common_name)+1;
		}
		snprintf(ss->common_name,strlen(common_name)+1,"%s",common_name);
#if 0
#ifdef ENABLE_PF
		{
			const uint32_t len = (uint32_t) strlen (common_name);
			if (len){
				ss->common_name_hashval = hash_func ((const uint8_t*)common_name, len+1, 0);
			}else{
				ss->common_name_hashval = 0;
			}
		}
#endif
#endif
	}
}


void string_mod_remap_name (char *str, const unsigned int restrictive_flags)
{
	if (compat_flag (COMPAT_FLAG_QUERY | COMPAT_NAMES) && !compat_flag (COMPAT_FLAG_QUERY | COMPAT_NO_NAME_REMAPPING)){
		string_mod (str, restrictive_flags, 0, '_');
	}else{
		string_mod (str, CC_PRINT, CC_CRLF, '_');
	}
}

void cert_hash_remember (struct epoll_ptr_data *epd,int error_depth,unsigned char *sha1_hash)
{

	struct ssl_state *ss=NULL;
	ss = (struct ssl_state *)epd->ss;

	if (error_depth >= 0 && error_depth < MAX_CERT_DEPTH)
	{
		if (ss->cert_hash_set == NULL){
			ss->cert_hash_set = malloc(sizeof(struct cert_hash_set));
			memset(ss->cert_hash_set,0x00,sizeof(struct cert_hash_set));
		}

		if (ss->cert_hash_set->ch[error_depth] == NULL){
			ss->cert_hash_set->ch[error_depth]= malloc(sizeof(struct cert_hash));
			memset(ss->cert_hash_set->ch[error_depth],0x00,sizeof(struct cert_hash));

		}

		{
			struct cert_hash *ch = ss->cert_hash_set->ch[error_depth];
			memcpy (ch->sha1_hash, sha1_hash, SHA_DIGEST_LENGTH);
		}
	}
}


result_t verify_peer_cert(struct options *opt, openvpn_x509_cert_t *peer_cert,char *subject, char *common_name)
{

	if(opt){}
	if(peer_cert){}
	if(subject){}
	if(common_name){}
#if 1
	//printf("########### NOT USER... ###### %s %d ###\n",__func__,__LINE__);
#else
	if (opt->ns_cert_type != NS_CERT_CHECK_NONE)
	{
		if (SUCCESS == x509_verify_ns_cert_type (peer_cert, opt->ns_cert_type))
		{
			MM("VERIFY OK: nsCertType=%s \n", print_nsCertType (opt->ns_cert_type));
		}
		else
		{
			MM("VERIFY nsCertType ERROR: %s, require nsCertType=%s \n", subject, print_nsCertType (opt->ns_cert_type));
			return FAILURE;
		}
	}

	if (opt->remote_cert_ku[0] != 0)
	{
		if (SUCCESS == x509_verify_cert_ku (peer_cert, opt->remote_cert_ku, MAX_PARMS))
		{
			MM("VERIFY KU OK\n");
		}
		else
		{
			MM("VERIFY KU ERROR\n");
			return FAILURE;
		}
	}

	if (opt->remote_cert_eku != NULL)
	{
		if (SUCCESS == x509_verify_cert_eku (peer_cert, opt->remote_cert_eku))
		{
			MM("VERIFY EKU OK\n");
		}
		else
		{
			MM("VERIFY EKU ERROR\n");
			return FAILURE;
		}
	}
	if (opt->verify_x509_type != VERIFY_X509_NONE)
	{
		if ( (opt->verify_x509_type == VERIFY_X509_SUBJECT_DN && strcmp (opt->verify_x509_name, subject) == 0)
			|| (opt->verify_x509_type == VERIFY_X509_SUBJECT_RDN && strcmp (opt->verify_x509_name, common_name) == 0)
			|| (opt->verify_x509_type == VERIFY_X509_SUBJECT_RDN_PREFIX && strncmp (opt->verify_x509_name, common_name,strlen (opt->verify_x509_name)) == 0)
		){
			MM("VERIFY X509NAME OK: %s \n", subject);
		}else{
			MM("VERIFY X509NAME ERROR: %s, must be %s \n",subject, opt->verify_x509_name);
			return FAILURE;
		}
	}
#endif
	return SUCCESS;
}


result_t verify_cert(struct epoll_ptr_data *epd, openvpn_x509_cert_t *cert, int cert_depth)
{
	result_t ret = FAILURE;
	char *subject = NULL;
	char common_name[TLS_USERNAME_LEN] = {0};


	struct main_data *md=NULL;
	md = (struct main_data *)epd->gl_var;

	struct ssl_state *ss=NULL;
	ss = (struct ssl_state *)epd->ss;


	struct options *opt=NULL;
	opt = md->opt;


	ss->verified = false;


	subject = x509_get_subject(cert);
	if (!subject)
	{
		MM("VERIFY ERROR: depth=%d, could not extract X509 subject string from certificate \n", cert_depth);
		goto cleanup;
	}

	string_mod_remap_name (subject, X509_NAME_CHAR_CLASS);
	string_replace_leading (subject, '-', '_');

	if (x509_get_username (common_name, TLS_USERNAME_LEN, opt->x509_username_field, cert) == false)
	{

		MM("## %s %d cert_depth %d ###############\n",__func__,__LINE__);

		if (!cert_depth)
		{
			MM("VERIFY ERROR: could not extract %s from X509 "
					"subject string ('%s') -- note that the username length is "
					"limited to %d characters",
					ss->x509_username_field,
					subject,
					TLS_USERNAME_LEN);
			goto cleanup;
		}
	}

	string_mod_remap_name (common_name, COMMON_NAME_CHAR_CLASS);

	if (cert_depth >= MAX_CERT_DEPTH)
	{
		MM("TLS Error: Convoluted certificate chain detected with depth [%d] greater than %d \n", cert_depth, MAX_CERT_DEPTH);
		goto cleanup;
	}

	if (cert_depth == 1 && opt->verify_hash)
	{
#if 0
		unsigned char *sha1_hash = x509_get_sha1_hash(cert);
		if (memcmp (sha1_hash, opt->verify_hash, SHA_DIGEST_LENGTH))
		{
			MM("TLS Error: level-1 certificate hash verification failed \n");
			goto cleanup;
		}
		if(sha1_hash != NULL){
			sfree(sha1_hash,SHA_DIGEST_LENGTH);
		}
#else
		char * ca_hash = NULL;
		const EVP_MD *sha256 = EVP_sha256();
		ca_hash = x509_get_sha256_fingerprint(cert);
		if (memcmp(ca_hash, opt->verify_hash, EVP_MD_size(sha256)))
		{
			MM("TLS Error: level-1 certificate hash verification failed \n");
			goto cleanup;
		}

#endif
	}

	if (cert_depth == 0){
		set_common_name (epd, common_name);
	}

	ss->verify_maxlevel = max_int (ss->verify_maxlevel, cert_depth);
#if 0
	/* export certificate values to the environment */
	verify_cert_set_env(opt->es, cert, cert_depth, subject, common_name
#ifdef ENABLE_X509_TRACK
			, opt->x509_track
#endif
			);

	/* export current untrusted IP */
	setenv_untrusted (session);
#endif

	if (cert_depth == 0 && SUCCESS != verify_peer_cert(opt, cert, subject, common_name)){
		goto cleanup;
	}
#if 0
	/* call --tls-verify plug-in(s), if registered */
	if (SUCCESS != verify_cert_call_plugin(opt->plugins, opt->es, cert_depth, cert, subject)){
		goto cleanup;
	}

	/* run --tls-verify script */
	if (opt->verify_command && SUCCESS != verify_cert_call_command(opt->verify_command, opt->es, cert_depth, cert, subject, opt->verify_export_cert)){
		goto cleanup;
	}

	/* check peer cert against CRL */
	if (opt->crl_file)
	{
		if (opt->ssl_flags & SSLF_CRL_VERIFY_DIR)
		{
			if (SUCCESS != verify_check_crl_dir(opt->crl_file, cert)){
				goto cleanup;
			}
		}
		else
		{
			if (SUCCESS != x509_verify_crl(opt->crl_file, cert, subject)){
				goto cleanup;
			}
		}
	}

#endif
	//MM("VERIFY OK:%s  depth=%d, %s \n", common_name,cert_depth, subject);
	ss->verified = true;
	ret = SUCCESS;
cleanup:

	if(subject != NULL){
		sfree(subject,256);
	}

	if (ret != SUCCESS)
	{
		tls_clear_error();
		ss->verified = false;
	}

	return ret;
}


