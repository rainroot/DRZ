#include <rain_common.h>


void do_alloc_route_list (struct options *opt)
{
	if (!opt->route_list){
		opt->route_list = new_route_list(opt->max_routes);
	}
	if (opt->routes_ipv6 && !opt->route_ipv6_list){
		opt->route_ipv6_list = new_route_ipv6_list(opt->max_routes);
	}
}


bool char_class (const unsigned char c, const unsigned int flags)
{
	if (!flags){
		return false;
	}
	if (flags & CC_ANY){
		return true;
	}

	if ((flags & CC_NULL) && c == '\0'){
		return true;
	}

	if ((flags & CC_ALNUM) && isalnum (c)){
		return true;
	}
	if ((flags & CC_ALPHA) && isalpha (c)){
		return true;
	}
	if ((flags & CC_ASCII) && isascii (c)){
		return true;
	}
	if ((flags & CC_CNTRL) && iscntrl (c)){
		return true;
	}
	if ((flags & CC_DIGIT) && isdigit (c)){
		return true;
	}
	if ((flags & CC_PRINT) && (c >= 32 && c != 127)){
		return true;
	}
	if ((flags & CC_PUNCT) && ispunct (c)){
		return true;
	}
	if ((flags & CC_SPACE) && isspace (c)){
		return true;
	}
	if ((flags & CC_XDIGIT) && isxdigit (c)){
		return true;
	}

	if ((flags & CC_BLANK) && (c == ' ' || c == '\t')){
		return true;
	}
	if ((flags & CC_NEWLINE) && c == '\n'){
		return true;
	}
	if ((flags & CC_CR) && c == '\r'){
		return true;
	}

	if ((flags & CC_BACKSLASH) && c == '\\'){
		return true;
	}
	if ((flags & CC_UNDERBAR) && c == '_'){
		return true;
	}
	if ((flags & CC_DASH) && c == '-'){
		return true;
	}
	if ((flags & CC_DOT) && c == '.'){
		return true;
	}
	if ((flags & CC_COMMA) && c == ','){
		return true;
	}
	if ((flags & CC_COLON) && c == ':'){
		return true;
	}
	if ((flags & CC_SLASH) && c == '/'){
		return true;
	}
	if ((flags & CC_SINGLE_QUOTE) && c == '\''){
		return true;
	}
	if ((flags & CC_DOUBLE_QUOTE) && c == '\"'){
		return true;
	}
	if ((flags & CC_REVERSE_QUOTE) && c == '`'){
		return true;
	}
	if ((flags & CC_AT) && c == '@'){
		return true;
	}
	if ((flags & CC_EQUAL) && c == '='){
		return true;
	}
	if ((flags & CC_LESS_THAN) && c == '<'){
		return true;
	}
	if ((flags & CC_GREATER_THAN) && c == '>'){
		return true;
	}
	if ((flags & CC_PIPE) && c == '|'){
		return true;
	}
	if ((flags & CC_QUESTION_MARK) && c == '?'){
		return true;
	}
	if ((flags & CC_ASTERISK) && c == '*'){
		return true;
	}

	return false;
}

bool char_inc_exc (const char c, const unsigned int inclusive, const unsigned int exclusive)
{
	return char_class (c, inclusive) && !char_class (c, exclusive);
}

bool string_class (const char *str, const unsigned int inclusive, const unsigned int exclusive)
{
	char c;
	while ((c = *str++))
	{
		if (!char_inc_exc (c, inclusive, exclusive)){
			return false;
		}
	}
	return true;
}

bool string_mod (char *str, unsigned int inclusive, unsigned int exclusive,char replace)
{
	char *in = str;
	bool ret = true;

	if(!str){
		MM("## ERR: %s %d ##\n",__func__,__LINE__);
	}

	while (true)
	{
		char c = *in++;
		if (c)
		{
			if (!char_inc_exc (c, inclusive, exclusive))
			{
				c = replace;
				ret = false;
			}
			if (c){
				*str++ = c;
			}
		}
		else
		{
			*str = '\0';
			break;
		} 
	}
	return ret;
}


bool string_mod_const(char *str,unsigned int inclusive, unsigned int exclusive,char replace,char *buf)
{

	if (str)
	{
		strcpy(buf,str);

		if(string_mod (buf, inclusive, exclusive, replace)){
			return true;
		}else{
			return false;
		}
	}else{
		return false;
	}
}


void string_replace_leading (char *str,char match,char replace)
{
	if(!(match != '\0')){
		MM("## ERR : %s %d ##\n",__func__,__LINE__);
	}
	while (*str)
	{
		if (*str == match){
			*str = replace;
		}else{
			break;
		}
		++str;
	}
}


int eng_init(){
	tls_init_lib();
	crypto_init_lib();
	return 0;
}


int init_ssl(struct tls_root_ctx *ctx,struct options *opt){

	if(opt->mode == SERVER){
		tls_ctx_server_new(ctx,opt->ssl_flags);
		tls_ctx_load_dh_params(ctx,opt->dh_file,opt->dh_file_inline);
	}else if(opt->mode == CLIENT){
		tls_ctx_client_new(ctx,opt->ssl_flags);
	}

	tls_ctx_set_options(ctx,opt->ssl_flags);
#if 0
	if(opt->pkcs12_file != NULL){
		tls_ctx_load_pkcs12(ctx,opt->pkcs12_file,opt->pkcs12_file_inline,opt->load_ca_file);
	}
#endif

	if(opt->cert_file != NULL){
		tls_ctx_load_cert_file(ctx,opt->cert_file,opt->cert_file_inline);
	}

	if(opt->priv_key_file != NULL){
		tls_ctx_load_priv_file(ctx,opt->priv_key_file,opt->priv_key_file_inline);
	}

	if(opt->ca_file != NULL){
		tls_ctx_load_ca(ctx,opt->ca_file,opt->ca_file_inline,opt->ca_path,opt->mode);
	}
#if 0
	if(opt->extra_certs_file){
		tls_ctx_load_extra_certs(ctx,opt->extra_certs_file,opt->extra_certs_file_inline);
	}
#endif

	return 0;

}


void do_up(){
	

	// route init


}
