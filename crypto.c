#include <rain_common.h>

void init_key_type (struct key_type *kt, const char *ciphername, const char *authname,int keysize,bool cfb_ofb_allowed)
{
	if (ciphername != NULL)
	{
		kt->cipher = cipher_kt_get (translate_cipher_name_from_openvpn(ciphername));
		//kt->cipher_length = cipher_kt_key_size ((EVP_CIPHER *)kt->cipher);
		kt->cipher_length = cipher_kt_key_size (kt->cipher);

		if (keysize > 0 && keysize <= MAX_CIPHER_KEY_LENGTH){
			kt->cipher_length = keysize;
		}

		{
			const unsigned int mode = cipher_kt_mode (kt->cipher);
			if (!(mode == OPENVPN_MODE_CBC || (cfb_ofb_allowed && (mode == OPENVPN_MODE_CFB || mode == OPENVPN_MODE_OFB)))){
				printf("### Cipher '%s' mode not supported ##\n", ciphername);
			}
		}
	}
	else
	{
		MM("## ******* WARNING *******: null cipher specified, no encryption will be used ##\n");
	}
	if (authname != NULL)
	{
		kt->digest = md_kt_get (authname);
		kt->hmac_length = md_kt_size (kt->digest);
	}
	else
	{
		MM("## ******* WARNING *******: null MAC specified, no authentication will be used ##\n");
	}
}

void init_key_ctx (struct key_ctx *ctx, struct key *key,const struct key_type *kt, int enc,const char *prefix,int idx)
{
	if(prefix){}
	if (kt->cipher != NULL && (kt->cipher_length > 0))
	{
		if(ctx->cipher[idx] != NULL){
			printf("####################################### ERROR %s %d ###################\n",__func__,__LINE__);
			exit(0);
		}
		//ctx->cipher[idx] = malloc(sizeof(cipher_ctx_t));
		//memset(ctx->cipher[idx],0x00,sizeof(cipher_ctx_t));
		ctx->cipher[idx] = cipher_ctx_new();
		cipher_ctx_init (ctx->cipher[idx],(uint8_t *)key->cipher, kt->cipher_length,kt->cipher, enc);

	}

	if (kt->digest != NULL && (kt->hmac_length > 0))
	{
		if(ctx->hmac[idx] != NULL){
			printf("####################################### ERROR %s %d ###################\n",__func__,__LINE__);
			exit(0);
		}
		//ctx->hmac[idx] = malloc(sizeof(hmac_ctx_t));
		//memset(ctx->hmac[idx],0x00,sizeof(hmac_ctx_t));
		ctx->hmac[idx] = hmac_ctx_new();
		hmac_ctx_init (ctx->hmac[idx], (uint8_t *)key->hmac, kt->hmac_length, kt->digest);
	}
}


void free_key_ctx (struct key_ctx *ctx,int idx)
{
	if (ctx->cipher[idx] != NULL)
	{
		//printf("### %s %d free cipher[%d] ##\n",__func__,__LINE__,idx);
		//cipher_ctx_cleanup(ctx->cipher[idx]);
		free(ctx->cipher[idx]);
		//sfree(ctx->cipher[idx],sizeof(cipher_ctx_t));
		ctx->cipher[idx] = NULL;
	}
	if (ctx->hmac[idx] != NULL)
	{
		//printf("### %s %d free hmac[%d] ##\n",__func__,__LINE__,idx);
		//hmac_ctx_cleanup(ctx->hmac[idx]);
		free(ctx->hmac[idx]);
		//sfree(ctx->hmac[idx],sizeof(hmac_ctx_t));
		ctx->hmac[idx] = NULL;
	}
}


bool key_is_zero (struct key *key, const struct key_type *kt)
{
	int i;
	for (i = 0; i < kt->cipher_length; ++i){
		if (key->cipher[i] != 0x00){
			return false;
		}
	}
	return true;
}

bool check_key (struct key *key, const struct key_type *kt)
{
	if (kt->cipher != NULL)
	{
		if (key_is_zero(key, kt)){
			return false;
		}

		{
			const int ndc = key_des_num_cblocks (kt->cipher);
			if (ndc){
				return key_des_check ((uint8_t *)key->cipher, kt->cipher_length, ndc);
			}else{
				return true;
			}
		}
	}
	return true;
}

void fixup_key (struct key *key, const struct key_type *kt)
{
	if (kt->cipher != NULL)
	{
		const int ndc = key_des_num_cblocks (kt->cipher);
		if (ndc){
			key_des_fixup ((uint8_t *)key->cipher, kt->cipher_length, ndc);
		}

	}
}

int data_decrypt(struct epoll_ptr_data *epd,char *buf,int buf_size,char *out,int keyid,int idx)
{
	int ret=0;
	int ret_hmac = 0;
	int ret_cipher = 0;
	struct key_ctx *ctx = NULL;
	struct main_data *md=NULL;
	md = (struct main_data *)epd->gl_var;

	int hmac_len=0;
	char local_hmac[MAX_HMAC_KEY_LENGTH]={0,};
	char local_cipher[4096]={0,};
	int toutlen=0;
	int outlen=0;

	ctx = &epd->ss->sk[keyid].key.decrypt;

	if(ctx->hmac[idx] != NULL){
		hmac_ctx_reset(ctx->hmac[idx]);
		hmac_len = hmac_ctx_size (ctx->hmac[idx]);

		if(buf_size-hmac_len > 0){
			hmac_ctx_update (ctx->hmac[idx],(uint8_t *)(buf+hmac_len),(buf_size-hmac_len));
			hmac_ctx_final (ctx->hmac[idx], (uint8_t *)local_hmac);
			if(memcmp(local_hmac,buf,hmac_len) != 0){

#if 0
				printf("## S %s %d ##\n",__func__,__LINE__);
				dump_print_hex(buf,buf_size);
				printf("## E %s %d ##\n",__func__,__LINE__);
#endif
				MM("## ERR: %s %d %s ERROR packet HMAC authentication failed  keyid : %d  epd->ss->keyid : %d idx %d \n",__func__,__LINE__,epd->name,keyid,epd->ss->keyid,idx);
				ret = -1;
			}else{
				ret_hmac = 1;
			}
		}else{
			ret = -1;
		}
	}

	if (ctx->cipher[idx] != NULL && ret == 0){
		unsigned int mode = cipher_ctx_mode (ctx->cipher[idx]);
		int iv_size = cipher_ctx_iv_length (ctx->cipher[idx]);
		char iv_buf[OPENVPN_MAX_IV_LENGTH]={0,};

		if (mode == OPENVPN_MODE_CBC){

		}else if (mode == OPENVPN_MODE_CFB || mode == OPENVPN_MODE_OFB){

		}else{

		}

		if (md->opt->use_iv == true)
		{
			memcpy (iv_buf,(buf+hmac_len), iv_size);
		}

		if (ctx->cipher[idx] != NULL && !cipher_ctx_reset (ctx->cipher[idx],(uint8_t *)iv_buf)){
			MM("## ERR: cipher init failed %s %d keyid : %d ##\n",__func__,__LINE__,keyid);
			ret = -1;
		}

		if (ctx->cipher[idx] != NULL && !cipher_ctx_update (ctx->cipher[idx],(uint8_t *)local_cipher, &toutlen,(uint8_t *)(buf+hmac_len+iv_size),(buf_size-hmac_len-iv_size))){
			MM("## ERR: cipher update failed %s %d keyid : %d \n",__func__,__LINE__,keyid);
			ret = -1;
		}
		outlen += toutlen;

		if (ctx->cipher[idx] != NULL && !cipher_ctx_final (ctx->cipher[idx],(uint8_t *)local_cipher+toutlen, &toutlen)){
			MM("## ERR: cipher final failed %s %d keyid : %d idx : %d  epd->name %s ##\n",__func__,__LINE__,keyid,idx,epd->name);
			ret = -1;
		}
		outlen += toutlen;
		ret_cipher = 1;
	}


	if(ret < 0){
		MM("### ERROR  %s %d ###\n",__func__,__LINE__);
	}else if((ret_hmac == 1) && (ret_cipher == 1)){
		memcpy(out,local_cipher,outlen);
		ret = outlen;
	}else if((ret_hmac == 0) && (ret_cipher == 1)){
		memcpy(out,local_cipher,outlen);
		ret = outlen;
	}else if((ret_hmac == 1) && (ret_cipher == 0)){
		memcpy(out,local_cipher,outlen);
		ret = outlen;
	}else if((ret_hmac == 0) && (ret_cipher == 0)){
		memcpy(out,buf,buf_size);
		ret = buf_size;
	}

	return ret;
}


int data_encrypt(struct epoll_ptr_data *epd,char *buf,int buf_size,char *out,int keyid,int idx)
{
	int ret=0;

	struct key_ctx *ctx = NULL;

	struct main_data *md=NULL;
	md = (struct main_data *)epd->gl_var;

	char local_cipher[4096]={0,};
	char local_hmac[4096]={0,};
	char *tmp_local_cipher=0;

	char iv_buf[OPENVPN_MAX_IV_LENGTH]={0,};

	unsigned int mode = 0;
	int iv_size = 0;
	int cipher_toutlen=0;
	int cipher_outlen=0;
	int hmac_len = 0;
	int ret_cipher=0;
	int ret_hmac=0;

	ctx = &epd->ss->sk[keyid].key.encrypt;
	if (ctx->cipher[idx] != NULL)
	{
		iv_size = cipher_ctx_iv_length (ctx->cipher[idx]);
		mode = cipher_ctx_mode (ctx->cipher[idx]);
		if (mode == OPENVPN_MODE_CBC)
		{
			if (md->opt->use_iv == true){
				rand_bytes((uint8_t *)iv_buf, iv_size);
			}
			tmp_local_cipher = local_cipher+iv_size;
		}else if (mode == OPENVPN_MODE_CFB || mode == OPENVPN_MODE_OFB){
		}else{
		}
		cipher_ctx_reset(ctx->cipher[idx],(uint8_t *)iv_buf);
		cipher_ctx_update (ctx->cipher[idx],(uint8_t *)tmp_local_cipher, &cipher_toutlen,(uint8_t *)buf,buf_size);
		cipher_outlen += cipher_toutlen;
		cipher_ctx_final(ctx->cipher[idx], (uint8_t *)(tmp_local_cipher+cipher_toutlen), &cipher_toutlen);
		cipher_outlen += cipher_toutlen;

		memcpy(local_cipher,iv_buf,iv_size);
		cipher_outlen += iv_size;
		ret_cipher=1;
	}

	if(ctx->hmac[idx] != NULL){
		hmac_len = hmac_ctx_size(ctx->hmac[idx]);
		hmac_ctx_reset (ctx->hmac[idx]);
		if(ctx->cipher[idx]){
			hmac_ctx_update (ctx->hmac[idx], (uint8_t *)local_cipher,cipher_outlen);
		}else{
			hmac_ctx_update (ctx->hmac[idx], (uint8_t *)buf,buf_size);
		}
		hmac_ctx_final (ctx->hmac[idx], (uint8_t *)local_hmac);
		ret_hmac=1;
	}

	if((ret_hmac == 1) && (ret_cipher == 1)){
		memcpy(out,local_hmac,hmac_len);
		memcpy(out+hmac_len,local_cipher,cipher_outlen);
		ret = hmac_len + cipher_outlen;
	}else if((ret_hmac == 0) && (ret_cipher == 1)){
		memcpy(out,local_hmac,hmac_len);
		memcpy(out+hmac_len,local_cipher,cipher_outlen);
		ret = hmac_len + cipher_outlen;
	}else if((ret_hmac == 1) && (ret_cipher == 0)){
		memcpy(out,local_hmac,hmac_len);
		memcpy(out+hmac_len,buf,buf_size);
		ret = hmac_len + buf_size;
	}else if((ret_hmac == 0) && (ret_cipher == 0)){
		memcpy(out,buf,buf_size);
		ret = buf_size;
	}else{
		ret = -1;
		MM("### ERROR  %s %d ###\n",__func__,__LINE__);
	}
	return ret;
}

char * keydirection2ascii (int kd, bool remote)
{
	if (kd == KEY_DIRECTION_BIDIRECTIONAL){
		return NULL;
	}else if (kd == KEY_DIRECTION_NORMAL){
		return remote ? "1" : "0";
	}else if (kd == KEY_DIRECTION_INVERSE){
		return remote ? "0" : "1";
	}else{
		MM("## ERR: %s %d ##\n",__func__,__LINE__);
	}
	return NULL;
}

