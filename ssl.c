#include <rain_common.h>

static struct user_pass passbuf;
static struct user_pass auth_user_pass;





#if 0
static const tls_cipher_name_pair tls_cipher_name_translation_table[] = {
	{"ADH-SEED-SHA", "TLS-DH-anon-WITH-SEED-CBC-SHA"},
	{"AES128-GCM-SHA256", "TLS-RSA-WITH-AES-128-GCM-SHA256"},
	{"AES128-SHA256", "TLS-RSA-WITH-AES-128-CBC-SHA256"},
	{"AES128-SHA", "TLS-RSA-WITH-AES-128-CBC-SHA"},
	{"AES256-GCM-SHA384", "TLS-RSA-WITH-AES-256-GCM-SHA384"},
	{"AES256-SHA256", "TLS-RSA-WITH-AES-256-CBC-SHA256"},
	{"AES256-SHA", "TLS-RSA-WITH-AES-256-CBC-SHA"},
	{"CAMELLIA128-SHA256", "TLS-RSA-WITH-CAMELLIA-128-CBC-SHA256"},
	{"CAMELLIA128-SHA", "TLS-RSA-WITH-CAMELLIA-128-CBC-SHA"},
	{"CAMELLIA256-SHA256", "TLS-RSA-WITH-CAMELLIA-256-CBC-SHA256"},
	{"CAMELLIA256-SHA", "TLS-RSA-WITH-CAMELLIA-256-CBC-SHA"},
	{"DES-CBC3-SHA", "TLS-RSA-WITH-3DES-EDE-CBC-SHA"},
	{"DES-CBC-SHA", "TLS-RSA-WITH-DES-CBC-SHA"},
	{"DH-DSS-SEED-SHA", "TLS-DH-DSS-WITH-SEED-CBC-SHA"},
	{"DHE-DSS-AES128-GCM-SHA256", "TLS-DHE-DSS-WITH-AES-128-GCM-SHA256"},
	{"DHE-DSS-AES128-SHA256", "TLS-DHE-DSS-WITH-AES-128-CBC-SHA256"},
	{"DHE-DSS-AES128-SHA", "TLS-DHE-DSS-WITH-AES-128-CBC-SHA"},
	{"DHE-DSS-AES256-GCM-SHA384", "TLS-DHE-DSS-WITH-AES-256-GCM-SHA384"},
	{"DHE-DSS-AES256-SHA256", "TLS-DHE-DSS-WITH-AES-256-CBC-SHA256"},
	{"DHE-DSS-AES256-SHA", "TLS-DHE-DSS-WITH-AES-256-CBC-SHA"},
	{"DHE-DSS-CAMELLIA128-SHA256", "TLS-DHE-DSS-WITH-CAMELLIA-128-CBC-SHA256"},
	{"DHE-DSS-CAMELLIA128-SHA", "TLS-DHE-DSS-WITH-CAMELLIA-128-CBC-SHA"},
	{"DHE-DSS-CAMELLIA256-SHA256", "TLS-DHE-DSS-WITH-CAMELLIA-256-CBC-SHA256"},
	{"DHE-DSS-CAMELLIA256-SHA", "TLS-DHE-DSS-WITH-CAMELLIA-256-CBC-SHA"},
	{"DHE-DSS-SEED-SHA", "TLS-DHE-DSS-WITH-SEED-CBC-SHA"},
	{"DHE-RSA-AES128-GCM-SHA256", "TLS-DHE-RSA-WITH-AES-128-GCM-SHA256"},
	{"DHE-RSA-AES128-SHA256", "TLS-DHE-RSA-WITH-AES-128-CBC-SHA256"},
	{"DHE-RSA-AES128-SHA", "TLS-DHE-RSA-WITH-AES-128-CBC-SHA"},
	{"DHE-RSA-AES256-GCM-SHA384", "TLS-DHE-RSA-WITH-AES-256-GCM-SHA384"},
	{"DHE-RSA-AES256-SHA256", "TLS-DHE-RSA-WITH-AES-256-CBC-SHA256"},
	{"DHE-RSA-AES256-SHA", "TLS-DHE-RSA-WITH-AES-256-CBC-SHA"},
	{"DHE-RSA-CAMELLIA128-SHA256", "TLS-DHE-RSA-WITH-CAMELLIA-128-CBC-SHA256"},
	{"DHE-RSA-CAMELLIA128-SHA", "TLS-DHE-RSA-WITH-CAMELLIA-128-CBC-SHA"},
	{"DHE-RSA-CAMELLIA256-SHA256", "TLS-DHE-RSA-WITH-CAMELLIA-256-CBC-SHA256"},
	{"DHE-RSA-CAMELLIA256-SHA", "TLS-DHE-RSA-WITH-CAMELLIA-256-CBC-SHA"},
	{"DHE-RSA-CHACHA20-POLY1305", "TLS-DHE-RSA-WITH-CHACHA20-POLY1305-SHA256"},
	{"DHE-RSA-SEED-SHA", "TLS-DHE-RSA-WITH-SEED-CBC-SHA"},
	{"DH-RSA-SEED-SHA", "TLS-DH-RSA-WITH-SEED-CBC-SHA"},
	{"ECDH-ECDSA-AES128-GCM-SHA256", "TLS-ECDH-ECDSA-WITH-AES-128-GCM-SHA256"},
	{"ECDH-ECDSA-AES128-SHA256", "TLS-ECDH-ECDSA-WITH-AES-128-CBC-SHA256"},
	{"ECDH-ECDSA-AES128-SHA", "TLS-ECDH-ECDSA-WITH-AES-128-CBC-SHA"},
	{"ECDH-ECDSA-AES256-GCM-SHA384", "TLS-ECDH-ECDSA-WITH-AES-256-GCM-SHA384"},
	{"ECDH-ECDSA-AES256-SHA256", "TLS-ECDH-ECDSA-WITH-AES-256-CBC-SHA256"},
	{"ECDH-ECDSA-AES256-SHA384", "TLS-ECDH-ECDSA-WITH-AES-256-CBC-SHA384"},
	{"ECDH-ECDSA-AES256-SHA", "TLS-ECDH-ECDSA-WITH-AES-256-CBC-SHA"},
	{"ECDH-ECDSA-CAMELLIA128-SHA256", "TLS-ECDH-ECDSA-WITH-CAMELLIA-128-CBC-SHA256"},
	{"ECDH-ECDSA-CAMELLIA128-SHA", "TLS-ECDH-ECDSA-WITH-CAMELLIA-128-CBC-SHA"},
	{"ECDH-ECDSA-CAMELLIA256-SHA256", "TLS-ECDH-ECDSA-WITH-CAMELLIA-256-CBC-SHA256"},
	{"ECDH-ECDSA-CAMELLIA256-SHA", "TLS-ECDH-ECDSA-WITH-CAMELLIA-256-CBC-SHA"},
	{"ECDH-ECDSA-DES-CBC3-SHA", "TLS-ECDH-ECDSA-WITH-3DES-EDE-CBC-SHA"},
	{"ECDH-ECDSA-DES-CBC-SHA", "TLS-ECDH-ECDSA-WITH-DES-CBC-SHA"},
	{"ECDH-ECDSA-RC4-SHA", "TLS-ECDH-ECDSA-WITH-RC4-128-SHA"},
	{"ECDHE-ECDSA-AES128-GCM-SHA256", "TLS-ECDHE-ECDSA-WITH-AES-128-GCM-SHA256"},
	{"ECDHE-ECDSA-AES128-SHA256", "TLS-ECDHE-ECDSA-WITH-AES-128-CBC-SHA256"},
	{"ECDHE-ECDSA-AES128-SHA384", "TLS-ECDHE-ECDSA-WITH-AES-128-CBC-SHA384"},
	{"ECDHE-ECDSA-AES128-SHA", "TLS-ECDHE-ECDSA-WITH-AES-128-CBC-SHA"},
	{"ECDHE-ECDSA-AES256-GCM-SHA384", "TLS-ECDHE-ECDSA-WITH-AES-256-GCM-SHA384"},
	{"ECDHE-ECDSA-AES128-SHA", "TLS-ECDHE-ECDSA-WITH-AES-128-CBC-SHA"},
	{"ECDHE-ECDSA-AES256-GCM-SHA384", "TLS-ECDHE-ECDSA-WITH-AES-256-GCM-SHA384"},
	{"ECDHE-ECDSA-AES256-SHA256", "TLS-ECDHE-ECDSA-WITH-AES-256-CBC-SHA256"},
	{"ECDHE-ECDSA-AES256-SHA384", "TLS-ECDHE-ECDSA-WITH-AES-256-CBC-SHA384"},
	{"ECDHE-ECDSA-AES256-SHA", "TLS-ECDHE-ECDSA-WITH-AES-256-CBC-SHA"},
	{"ECDHE-ECDSA-CAMELLIA128-SHA256", "TLS-ECDHE-ECDSA-WITH-CAMELLIA-128-CBC-SHA256"},
	{"ECDHE-ECDSA-CAMELLIA128-SHA", "TLS-ECDHE-ECDSA-WITH-CAMELLIA-128-CBC-SHA"},
	{"ECDHE-ECDSA-CAMELLIA256-SHA256", "TLS-ECDHE-ECDSA-WITH-CAMELLIA-256-CBC-SHA256"},
	{"ECDHE-ECDSA-CAMELLIA256-SHA", "TLS-ECDHE-ECDSA-WITH-CAMELLIA-256-CBC-SHA"},
	{"ECDHE-ECDSA-CHACHA20-POLY1305", "TLS-ECDHE-ECDSA-WITH-CHACHA20-POLY1305-SHA256"},
	{"ECDHE-ECDSA-DES-CBC3-SHA", "TLS-ECDHE-ECDSA-WITH-3DES-EDE-CBC-SHA"},
	{"ECDHE-ECDSA-DES-CBC-SHA", "TLS-ECDHE-ECDSA-WITH-DES-CBC-SHA"},
	{"ECDHE-ECDSA-RC4-SHA", "TLS-ECDHE-ECDSA-WITH-RC4-128-SHA"},
	{"ECDHE-RSA-AES128-GCM-SHA256", "TLS-ECDHE-RSA-WITH-AES-128-GCM-SHA256"},
	{"ECDHE-RSA-AES128-SHA256", "TLS-ECDHE-RSA-WITH-AES-128-CBC-SHA256"},
	{"ECDHE-RSA-AES128-SHA384", "TLS-ECDHE-RSA-WITH-AES-128-CBC-SHA384"},
	{"ECDHE-RSA-AES128-SHA", "TLS-ECDHE-RSA-WITH-AES-128-CBC-SHA"},
	{"ECDHE-RSA-AES256-GCM-SHA384", "TLS-ECDHE-RSA-WITH-AES-256-GCM-SHA384"},
	{"ECDHE-RSA-AES256-SHA256", "TLS-ECDHE-RSA-WITH-AES-256-CBC-SHA256"},
	{"ECDHE-RSA-AES256-SHA384", "TLS-ECDHE-RSA-WITH-AES-256-CBC-SHA384"},
	{"ECDHE-RSA-AES256-SHA", "TLS-ECDHE-RSA-WITH-AES-256-CBC-SHA"},
	{"ECDHE-RSA-CAMELLIA128-SHA256", "TLS-ECDHE-RSA-WITH-CAMELLIA-128-CBC-SHA256"},
	{"ECDHE-RSA-CAMELLIA128-SHA", "TLS-ECDHE-RSA-WITH-CAMELLIA-128-CBC-SHA"},
	{"ECDHE-RSA-CAMELLIA256-SHA256", "TLS-ECDHE-RSA-WITH-CAMELLIA-256-CBC-SHA256"},
	{"ECDHE-RSA-CAMELLIA256-SHA", "TLS-ECDHE-RSA-WITH-CAMELLIA-256-CBC-SHA"},
	{"ECDHE-RSA-CHACHA20-POLY1305", "TLS-ECDHE-RSA-WITH-CHACHA20-POLY1305-SHA256"},
	{"ECDHE-RSA-DES-CBC3-SHA", "TLS-ECDHE-RSA-WITH-3DES-EDE-CBC-SHA"},
	{"ECDHE-RSA-DES-CBC-SHA", "TLS-ECDHE-RSA-WITH-DES-CBC-SHA"},
	{"ECDHE-RSA-RC4-SHA", "TLS-ECDHE-RSA-WITH-RC4-128-SHA"},
	{"ECDH-RSA-AES128-GCM-SHA256", "TLS-ECDH-RSA-WITH-AES-128-GCM-SHA256"},
	{"ECDH-RSA-AES128-SHA256", "TLS-ECDH-RSA-WITH-AES-128-CBC-SHA256"},
	{"ECDH-RSA-AES128-SHA384", "TLS-ECDH-RSA-WITH-AES-128-CBC-SHA384"},
	{"ECDH-RSA-AES128-SHA", "TLS-ECDH-RSA-WITH-AES-128-CBC-SHA"},
	{"ECDH-RSA-AES256-GCM-SHA384", "TLS-ECDH-RSA-WITH-AES-256-GCM-SHA384"},
	{"ECDH-RSA-AES256-SHA256", "TLS-ECDH-RSA-WITH-AES-256-CBC-SHA256"},
	{"ECDH-RSA-AES256-SHA384", "TLS-ECDH-RSA-WITH-AES-256-CBC-SHA384"},
	{"ECDH-RSA-AES256-SHA", "TLS-ECDH-RSA-WITH-AES-256-CBC-SHA"},
	{"ECDH-RSA-CAMELLIA128-SHA256", "TLS-ECDH-RSA-WITH-CAMELLIA-128-CBC-SHA256"},
	{"ECDH-RSA-CAMELLIA128-SHA", "TLS-ECDH-RSA-WITH-CAMELLIA-128-CBC-SHA"},
	{"ECDH-RSA-CAMELLIA256-SHA256", "TLS-ECDH-RSA-WITH-CAMELLIA-256-CBC-SHA256"},
	{"ECDH-RSA-CAMELLIA256-SHA", "TLS-ECDH-RSA-WITH-CAMELLIA-256-CBC-SHA"},
	{"ECDH-RSA-DES-CBC3-SHA", "TLS-ECDH-RSA-WITH-3DES-EDE-CBC-SHA"},
	{"ECDH-RSA-DES-CBC-SHA", "TLS-ECDH-RSA-WITH-DES-CBC-SHA"},
	{"ECDH-RSA-RC4-SHA", "TLS-ECDH-RSA-WITH-RC4-128-SHA"},
	{"EDH-DSS-DES-CBC3-SHA", "TLS-DHE-DSS-WITH-3DES-EDE-CBC-SHA"},
	{"EDH-DSS-DES-CBC-SHA", "TLS-DHE-DSS-WITH-DES-CBC-SHA"},
	{"EDH-RSA-DES-CBC3-SHA", "TLS-DHE-RSA-WITH-3DES-EDE-CBC-SHA"},
	{"EDH-RSA-DES-CBC-SHA", "TLS-DHE-RSA-WITH-DES-CBC-SHA"},
	{"EXP-DES-CBC-SHA", "TLS-RSA-EXPORT-WITH-DES40-CBC-SHA"},
	{"EXP-EDH-DSS-DES-CBC-SHA", "TLS-DH-DSS-EXPORT-WITH-DES40-CBC-SHA"},
	{"EXP-EDH-RSA-DES-CBC-SHA", "TLS-DH-RSA-EXPORT-WITH-DES40-CBC-SHA"},
	{"EXP-RC2-CBC-MD5", "TLS-RSA-EXPORT-WITH-RC2-CBC-40-MD5"},
	{"EXP-RC4-MD5", "TLS-RSA-EXPORT-WITH-RC4-40-MD5"},
	{"NULL-MD5", "TLS-RSA-WITH-NULL-MD5"},
	{"NULL-SHA256", "TLS-RSA-WITH-NULL-SHA256"},
	{"NULL-SHA", "TLS-RSA-WITH-NULL-SHA"},
	{"PSK-3DES-EDE-CBC-SHA", "TLS-PSK-WITH-3DES-EDE-CBC-SHA"},
	{"PSK-AES128-CBC-SHA", "TLS-PSK-WITH-AES-128-CBC-SHA"},
	{"PSK-AES256-CBC-SHA", "TLS-PSK-WITH-AES-256-CBC-SHA"},
	{"PSK-RC4-SHA", "TLS-PSK-WITH-RC4-128-SHA"},
	{"RC4-MD5", "TLS-RSA-WITH-RC4-128-MD5"},
	{"RC4-SHA", "TLS-RSA-WITH-RC4-128-SHA"},
	{"SEED-SHA", "TLS-RSA-WITH-SEED-CBC-SHA"},
	{"SRP-DSS-3DES-EDE-CBC-SHA", "TLS-SRP-SHA-DSS-WITH-3DES-EDE-CBC-SHA"},
	{"SRP-DSS-AES-128-CBC-SHA", "TLS-SRP-SHA-DSS-WITH-AES-128-CBC-SHA"},
	{"SRP-DSS-AES-256-CBC-SHA", "TLS-SRP-SHA-DSS-WITH-AES-256-CBC-SHA"},
	{"SRP-RSA-3DES-EDE-CBC-SHA", "TLS-SRP-SHA-RSA-WITH-3DES-EDE-CBC-SHA"},
	{"SRP-RSA-AES-128-CBC-SHA", "TLS-SRP-SHA-RSA-WITH-AES-128-CBC-SHA"},
	{"SRP-RSA-AES-256-CBC-SHA", "TLS-SRP-SHA-RSA-WITH-AES-256-CBC-SHA"},
	{NULL, NULL}
};











tls_cipher_name_pair * tls_get_cipher_name_pair(const char *cipher_name, size_t len) {
	const tls_cipher_name_pair *pair = tls_cipher_name_translation_table;

	while (pair->openssl_name != NULL) {
		if ((strlen(pair->openssl_name) == len && 0 == memcmp(cipher_name, pair->openssl_name, len))
				|| (strlen(pair->iana_name) == len && 0 == memcmp(cipher_name, pair->iana_name, len)))
		{
			return pair;
		}
		pair++;
	}
	return NULL;
}
#endif


void strncpynt (char *dest, const char *src, size_t maxlen)
{
	strncpy (dest, src, maxlen);
	if (maxlen > 0){
		dest[maxlen - 1] = 0;
	}
}

int tls_version_min_parse(const char *vstr, const char *extra)
{
	const int max_version = tls_version_max();
	if (!strcmp(vstr, "1.0") && TLS_VER_1_0 <= max_version){
		return TLS_VER_1_0;
	}else if (!strcmp(vstr, "1.1") && TLS_VER_1_1 <= max_version){
		return TLS_VER_1_1;
	}else if (!strcmp(vstr, "1.2") && TLS_VER_1_2 <= max_version){
		return TLS_VER_1_2;
	}else if (extra && !strcmp(extra, "or-highest")){
		return max_version;
	}else{
		return TLS_VER_BAD;
	}
}


void ssl_set_auth_nocache (void)
{
	passbuf.nocache = true;
	auth_user_pass.nocache = true;
}

void ssl_set_auth_token (const char *token)
{
	set_auth_token (&auth_user_pass, token);
}

void set_auth_token (struct user_pass *up, const char *token)
{
	if (token && strlen(token) && up && up->defined && !up->nocache)
	{
		memset(&up->password,0x00,sizeof(up->password));
		strncpynt (up->password, token, USER_PASS_LEN);
	}
}


int ssl_handle(struct epoll_ptr_data *epd,char *data,int len,char *out)
{

	int ret=0;
	struct main_data *md=NULL;
	md = (struct main_data *)epd->gl_var;

	int kswc_ret = 0;
	int ksrc_ret = 0;
	int ksrp_ret = 0;
	int kswp_ret = 0;

	bool loop_en = true;

	char ctl_out[4096]={0,};

	//char *ctl_out = malloc(4096);
	//memset(ctl_out,0x00,4096);

	int ctl_ret = 0;
	if(len > 0){
		kswc_ret = key_state_write_ciphertext(epd->ss->sk[epd->ss->renego_keyid].ks_ssl,data,len);
		if(kswc_ret < 0){
			MM("## ERR : %s %d %d ##\n",__func__,__LINE__,kswc_ret);
			ret = -1;
		}
	}

	do{
		if(kswc_ret == 1){
			kswc_ret = 0;
			loop_en = true;
		}else{
			loop_en = false;
		}

		if(((epd->ss->sk[epd->ss->renego_keyid].state == S_GOT_KEY ) && (md->opt->mode == CLIENT)) || ((epd->ss->sk[epd->ss->renego_keyid].state == S_SENT_KEY) && (md->opt->mode == SERVER))){
			epd->ss->sk[epd->ss->renego_keyid].state = S_ACTIVE;
			epd->ss->renego_success = true;
			loop_en = true;
		}

		if((epd->ss->sk[epd->ss->renego_keyid].pwb_len == 0) && (((epd->ss->sk[epd->ss->renego_keyid].state == S_START) && (md->opt->mode == CLIENT)) || ((epd->ss->sk[epd->ss->renego_keyid].state == S_GOT_KEY) && (md->opt->mode == SERVER)))){
			if(key_method_2_write(epd) == false){
				ret = -1;
				MM("## ERR: %s %d %s %d ##\n",__func__,__LINE__,epd->name,ret);
				break;
			}else{
				epd->ss->sk[epd->ss->renego_keyid].state = S_SENT_KEY;
				loop_en = true;
			}
		}


		if(epd->ss->sk[epd->ss->renego_keyid].prb_len == 0){
			ksrp_ret = key_state_read_plaintext(epd->ss->sk[epd->ss->renego_keyid].ks_ssl,epd->ss->sk[epd->ss->renego_keyid].prb,2048,2048);
			if(ksrp_ret == -1){
				MM("## ERR: %s %d %s %d  renego_keyid %d  keyid %d ##\n",__func__,__LINE__,epd->name,ksrp_ret,epd->ss->renego_keyid,epd->ss->keyid);
				ret = -1;
				break;
			}
			if(ksrp_ret >  0){
				epd->ss->sk[epd->ss->renego_keyid].prb_len = ksrp_ret;
				if(epd->ss->sk[epd->ss->renego_keyid].state >= S_ACTIVE){
					ctl_ret = ctl_msg_process(epd,ctl_out);
					if(ctl_ret > 0){
						key_state_write_plaintext_const(epd->ss->sk[epd->ss->renego_keyid].ks_ssl,ctl_out,ctl_ret);
					}
					memset(epd->ss->sk[epd->ss->renego_keyid].prb,0x00,ksrp_ret);
					epd->ss->sk[epd->ss->renego_keyid].prb_len = 0;
				}
			}
#if 0
			if(ksrp_ret == 0 && epd->ss->sk[epd->ss->renego_keyid].state == S_INITIAL){
				break;
			}
#endif
		}


		if((epd->ss->sk[epd->ss->renego_keyid].prb_len > 0) && (((epd->ss->sk[epd->ss->renego_keyid].state == S_SENT_KEY) && (md->opt->mode == CLIENT)) || ((epd->ss->sk[epd->ss->renego_keyid].state == S_START) && (md->opt->mode == SERVER)))){
			if(key_method_2_read(epd) == false){
				ret = -1;
				MM("## ERR: %s %d %s %d ##\n",__func__,__LINE__,epd->name,ret);
				epd->ss->sk[epd->ss->renego_keyid].prb_len = 0;
				memset(epd->ss->sk[epd->ss->renego_keyid].prb,0x00,epd->ss->sk[epd->ss->renego_keyid].prb_len);
				break;
			}else{
				epd->ss->sk[epd->ss->renego_keyid].state = S_GOT_KEY;
				loop_en = true;
				epd->ss->sk[epd->ss->renego_keyid].prb_len = 0;
				memset(epd->ss->sk[epd->ss->renego_keyid].prb,0x00,epd->ss->sk[epd->ss->renego_keyid].prb_len);
			}
		}

		if(epd->ss->sk[epd->ss->renego_keyid].pwb_len > 0){
			kswp_ret = key_state_write_plaintext(epd->ss->sk[epd->ss->renego_keyid].ks_ssl,epd->ss->sk[epd->ss->renego_keyid].pwb,epd->ss->sk[epd->ss->renego_keyid].pwb_len);
			if(kswp_ret == -1 ){
				MM("## ERR: %s %d %s %d ##\n",__func__,__LINE__,epd->name,kswp_ret);
				ret = -1;
				break;
			}
			if(kswp_ret == 1){
				loop_en = true;
				memset(epd->ss->sk[epd->ss->renego_keyid].pwb,0x00,epd->ss->sk[epd->ss->renego_keyid].pwb_len);
				epd->ss->sk[epd->ss->renego_keyid].pwb_len = 0;
			}
		}

		if(epd->ss->sk[epd->ss->renego_keyid].state >= S_START){
			ksrc_ret = key_state_read_ciphertext(epd->ss->sk[epd->ss->renego_keyid].ks_ssl,out,100,100);
			if(ksrc_ret == -1){
				MM("## ERR: %s %d %s %d ##\n",__func__,__LINE__,epd->name,ksrc_ret);
				ret = -1;
				break;
			}
			if(ksrc_ret > 0){
				ret = ksrc_ret;
				break;
			}
		}
	}while(loop_en == true);

	//free(ctl_out);

	if(ret < 0){
		MM("## ERR: %s %d %d ##\n",__func__,__LINE__,ret);
	}
	return ret;
}


int pem_password_callback (char *buf, int size, int rwflag, void *u)
{
	MM("## %s %d ##\n",__func__,__LINE__);
	if(rwflag){}
	if(u){}
	if(size){}
	if (buf)
	{
#if 0
		pem_password_setup (NULL);
		strncpynt (buf, passbuf.password, size);
		purge_user_pass (&passbuf, false);
		return strlen (buf);
#endif
	}
	return 0;
}


void tls1_P_hash(const md_kt_t *md_kt,uint8_t *sec,int sec_len,uint8_t *seed,int seed_len,uint8_t *out,int olen)
{
#if 0
	int chunk=0;
	HMAC_CTX ctx;
	HMAC_CTX ctx_tmp;
	//uint8_t A1[MAX_HMAC_KEY_LENGTH];
	uint8_t *A1 = malloc(MAX_HMAC_KEY_LENGTH);
	memset(A1,0x00,MAX_HMAC_KEY_LENGTH);

	unsigned int A1_len;


	memset(&ctx,0x00,sizeof(HMAC_CTX));
	memset(&ctx_tmp,0x00,sizeof(HMAC_CTX));

	chunk = md_kt_size(md_kt);
	A1_len = md_kt_size(md_kt);

	hmac_ctx_init(&ctx,sec,sec_len, md_kt);
	hmac_ctx_init(&ctx_tmp,sec,sec_len, md_kt);

	hmac_ctx_update(&ctx,seed,seed_len);
	hmac_ctx_final(&ctx, A1);

	for (;;)
	{
		hmac_ctx_reset(&ctx);
		hmac_ctx_reset(&ctx_tmp);
		hmac_ctx_update(&ctx,A1,A1_len);
		hmac_ctx_update(&ctx_tmp,A1,A1_len);
		hmac_ctx_update(&ctx,seed,seed_len);

		if (olen > chunk)
		{
			hmac_ctx_final(&ctx, out);
			out+=chunk;
			olen-=chunk;
			hmac_ctx_final(&ctx_tmp, A1);
		}
		else
		{
			hmac_ctx_final(&ctx, A1);
			memcpy(out,A1,olen);
			break;
		}
	}
	hmac_ctx_cleanup(&ctx);
	hmac_ctx_cleanup(&ctx_tmp);
	free(A1);

#else
	int chunk=0;
	HMAC_CTX *ctx;
	HMAC_CTX *ctx_tmp;
	unsigned char *A1 = malloc(MAX_HMAC_KEY_LENGTH);
	memset(A1,0x00,MAX_HMAC_KEY_LENGTH);

	unsigned int A1_len;

	ctx = HMAC_CTX_new();
	ctx_tmp = HMAC_CTX_new();

	chunk = md_kt_size(md_kt);
	A1_len = md_kt_size(md_kt);

	hmac_ctx_init(ctx,sec, sec_len, md_kt);
	hmac_ctx_init(ctx_tmp,sec, sec_len, md_kt);

	hmac_ctx_update(ctx,seed,seed_len);
	hmac_ctx_final(ctx, A1);

	for (;;)
	{
		hmac_ctx_reset(ctx);
		hmac_ctx_reset(ctx_tmp);
		hmac_ctx_update(ctx,A1,A1_len);
		hmac_ctx_update(ctx_tmp,A1,A1_len);
		hmac_ctx_update(ctx,seed,seed_len);

		if (olen > chunk)
		{
			hmac_ctx_final(ctx, out);
			out+=chunk;
			olen-=chunk;
			hmac_ctx_final(ctx_tmp, A1);
		}
		else
		{
			hmac_ctx_final(ctx,A1);
			memcpy(out,A1,olen);
			break;
		}
	}
	HMAC_CTX_free(ctx);
	HMAC_CTX_free(ctx_tmp);

	hmac_ctx_cleanup(ctx_tmp);
	free(A1);


#endif
}




void tls1_PRF(char *label,int label_len,char *sec,int slen,char *out1,int olen)
{
	const md_kt_t *md5 = md_kt_get("MD5");
	const md_kt_t *sha1 = md_kt_get("SHA1");
	int len,i;
	uint8_t *S1,*S2;
	uint8_t *out2;

	out2 = malloc(olen);
	len=slen/2;
	S1=(uint8_t *)sec;
	S2=(uint8_t *)&(sec[len]);
	len+=(slen&1);

	tls1_P_hash(md5 ,S1,len,(uint8_t *)label,label_len,(uint8_t *)out1,olen);
	tls1_P_hash(sha1,S2,len,(uint8_t *)label,label_len,out2,olen);

	for (i=0; i<olen; i++){
		out1[i]^=out2[i];
	}
	free(out2);
}


bool generate_key_expansion(struct epoll_ptr_data *epd,bool server)
{
	//char master[48]={0,};

	char *master = malloc(48);
	memset(master,0x00,48);

	struct key2 key2;
	bool ret = false;
	int i=0;

	struct main_data *md = NULL;
	struct options *opt = NULL;
	md = (struct main_data *)epd->gl_var;
	opt = md->opt;

	struct key_source *server_key = &epd->ss->sk[epd->ss->renego_keyid].k2.server;
	struct key_source *client_key = &epd->ss->sk[epd->ss->renego_keyid].k2.client;

	int str_len = 0;
	int memidx = 0;
	int seed_len = (strlen(KEY_EXPANSION_ID " master secret")+sizeof(client_key->random1) + sizeof(server_key->random1) + (SID_SIZE*2));
	char *seed = malloc(seed_len);
	if(seed == NULL){
		MM("##ERR: %s %s[:%d] ##\n",__FILE__,__func__,__LINE__);	
		exit(0);
	}
	memset(seed,0x00,seed_len);

	str_len = strlen(KEY_EXPANSION_ID " master secret");
	memidx = 0;
	strncpy(seed+memidx,KEY_EXPANSION_ID " master secret",str_len);
	memidx += str_len;
	memcpy(seed+memidx,client_key->random1,sizeof(client_key->random1));
	memidx += sizeof(client_key->random1);
	memcpy(seed+memidx,server_key->random1,sizeof(server_key->random1));
	memidx += sizeof(server_key->random1);

	//tls1_PRF(seed,memidx,(char *)client_key->pre_master,sizeof(client_key->pre_master),master,sizeof(master));
	tls1_PRF(seed,memidx,(char *)client_key->pre_master,sizeof(client_key->pre_master),master,48);
	memset(seed,0x00,seed_len);

	str_len = strlen(KEY_EXPANSION_ID " key expansion");
	memidx = 0;
	strncpy(seed+memidx,KEY_EXPANSION_ID " key expansion",str_len);
	memidx += str_len;
	memcpy(seed+memidx,client_key->random2,sizeof(client_key->random2));
	memidx += sizeof(client_key->random2);
	memcpy(seed+memidx,server_key->random2,sizeof(server_key->random2));
	memidx += sizeof(server_key->random2);

	if(server == true){
		memcpy(seed+memidx,epd->ss->remote_session_id,SID_SIZE);
		memidx += SID_SIZE;
		memcpy(seed+memidx,md->session_id,SID_SIZE);
		memidx += SID_SIZE;
	}else{
		memcpy(seed+memidx,md->session_id,SID_SIZE);
		memidx += SID_SIZE;
		memcpy(seed+memidx,epd->ss->remote_session_id,SID_SIZE);
		memidx += SID_SIZE;
	}

	//tls1_PRF(seed,memidx,master,sizeof(master),(char *)key2.keys,sizeof(key2.keys));
	tls1_PRF(seed,memidx,master,48,(char *)key2.keys,sizeof(key2.keys));

	free(seed);

	key2.n = 2;
	for(i = 0 ; i < 2 ; ++i){
		fixup_key(&key2.keys[i],&md->key_type);
		if(!check_key(&key2.keys[i],&md->key_type)){
			MM("## ERR: %s %d ##\n",__func__,__LINE__);
			ret = false;
			break;
		}else{
			ret = true;
		}
	}	

	for(i = 0 ; i < (int)opt->core;i++){
		init_key_ctx (&epd->ss->sk[epd->ss->renego_keyid].key.encrypt,
				&key2.keys[(int)server],
				&md->key_type,
				OPENVPN_OP_ENCRYPT,
				"Data Channel Encrypt",i);

		init_key_ctx (&epd->ss->sk[epd->ss->renego_keyid].key.decrypt,
				&key2.keys[1-(int)server],
				&md->key_type,
				OPENVPN_OP_DECRYPT,
				"Data Channel Decrypt",i);
	}
	free(master);
	return ret;
}

bool key_method_2_read (struct epoll_ptr_data *epd)
{
	int memidx = 0;
	uint8_t key_method_flags=0;

	char *buff = epd->ss->sk[epd->ss->renego_keyid].prb;

	struct main_data *md=NULL;
	md = (struct main_data *)epd->gl_var;


	//char str[4096]={0,};
	char *str = malloc(4096);
	memset(str,0x00,4096);

	int strlen = 0;

	bool ret = false;

	memidx = 4;
	memcpy(&key_method_flags,buff+memidx,1);
	memidx += 1;

	if ((key_method_flags & KEY_METHOD_MASK) != 2){
		MM("## ERR: %s %d ##\n",__func__,__LINE__);
		return false;
	}

	if(md->opt->mode == CLIENT){
		struct key_source *k = &epd->ss->sk[epd->ss->renego_keyid].k2.server;
		memcpy(k->random1,buff+memidx,sizeof(k->random1));
		memidx += sizeof(k->random1);
		memcpy(k->random2,buff+memidx,sizeof(k->random2));
		memidx += sizeof(k->random2);

	}else if(md->opt->mode == SERVER){
		struct key_source *k = &epd->ss->sk[epd->ss->renego_keyid].k2.client;
		memcpy(k->pre_master,buff+memidx,sizeof(k->pre_master));
		memidx += sizeof(k->pre_master);
		memcpy(k->random1,buff+memidx,sizeof(k->random1));
		memidx += sizeof(k->random1);
		memcpy(k->random2,buff+memidx,sizeof(k->random2));
		memidx += sizeof(k->random2);
	}

	memcpy(&strlen,buff+memidx,2);
	memidx += 2;
	strlen = ntohs(strlen);

	memcpy(str,buff+memidx,strlen);
	memidx += strlen;

	if(md->opt->verify_user_pass_enable == true){
		// user pass check
	}else{
		epd->ss->sk[epd->ss->renego_keyid].authenticated = true;
	}

	if(epd->ss->sk[epd->ss->renego_keyid].authenticated == true){
		// verify_final_auth_checks
	}

	if(md->opt->mode == CLIENT){
		ret = generate_key_expansion(epd,false);
		if(ret == false){
			MM("## %s %d ##\n",__func__,__LINE__);
			exit(0);
		}
	}else{
		ret = true;
	}
	free(str);
	return ret;
}


bool key_method_2_write (struct epoll_ptr_data *epd)
{

	struct main_data *md=NULL;
	md = (struct main_data *)epd->gl_var;

	char *buff = epd->ss->sk[epd->ss->renego_keyid].pwb;
	int memidx = 0;
	uint8_t key_method_flags=0;

	int str_len = 0;
	int tstr_len = 0;

	char *opt_str = NULL;
	opt_str = malloc(OPTION_LINE_SIZE);
	memset(opt_str,0x00,OPTION_LINE_SIZE);

	bool ret = false;

	memset(epd->ss->sk[epd->ss->renego_keyid].pwb,0x00,epd->ss->sk[epd->ss->renego_keyid].pwb_len);

	memidx = 4;
	key_method_flags = (md->opt->key_method & KEY_METHOD_MASK);
	memcpy(buff+memidx,&key_method_flags,1);
	memidx += 1;

	if(md->opt->mode == SERVER){

		struct key_source *k = &epd->ss->sk[epd->ss->renego_keyid].k2.server;
		rand_bytes(k->random1,sizeof(k->random1));
		memcpy(buff+memidx,k->random1,sizeof(k->random1));
		memidx += sizeof(k->random1);

		rand_bytes(k->random2,sizeof(k->random2));
		memcpy(buff+memidx,k->random2,sizeof(k->random2));
		memidx += sizeof(k->random2);
		opt_str = options_string(epd,false,opt_str); //20161227 rainroot

	}else if(md->opt->mode == CLIENT){
		struct key_source *k = &epd->ss->sk[epd->ss->renego_keyid].k2.client;

		rand_bytes(k->pre_master,sizeof(k->pre_master));
		memcpy(buff+memidx,k->pre_master,sizeof(k->pre_master));
		memidx += sizeof(k->pre_master);

		rand_bytes(k->random1,sizeof(k->random1));
		memcpy(buff+memidx,k->random1,sizeof(k->random1));
		memidx += sizeof(k->random1);

		rand_bytes(k->random2,sizeof(k->random2));
		memcpy(buff+memidx,k->random2,sizeof(k->random2));
		memidx += sizeof(k->random2);
		opt_str = options_string(epd,false,opt_str);
	}

	str_len = strlen(opt_str) + 1;
	tstr_len = str_len;
	str_len = htons(str_len);

	memcpy(buff+memidx,&str_len,2);
	memidx += 2;

	memcpy(buff+memidx,opt_str,tstr_len);
	memidx += tstr_len;

	if(md->opt->verify_user_pass_enable == true){

	}else{
		memidx += 4;
		memidx += 4;
	}

	//push_peer_info(buf,session);

	if(md->opt->mode == SERVER){
		if(epd->ss->sk[epd->ss->renego_keyid].authenticated == true){
			ret = generate_key_expansion(epd,true);
			if(ret == false){
				MM("## %s %d ##\n",__func__,__LINE__);
				exit(0);
			}
		}
	}else{
		ret = true;
	}

	epd->ss->sk[epd->ss->renego_keyid].pwb_len = memidx;
	free(opt_str);
	return ret;
}

