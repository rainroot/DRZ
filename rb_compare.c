#include <rain_common.h>

int client_compare(void *ad, void *bd,void *rb_param)
{
	int ret = 0;
	struct user_data *aud = (struct user_data *)ad;
	struct user_data *bud = (struct user_data *)bd;

	uint32_t a=0;
	uint32_t b=0;

	if(rb_param){}

	if(aud != NULL && bud != NULL){
		a=aud->key;
		b=bud->key;
	}

	if (a > b) {
		ret = 1;
	}
	else if (b > a) {
		ret = -1;
	}
	return ret;
}




int uint32_compare(void *ad, void *bd,void *rb_param)
{
	int ret = 0;
	struct user_data *aud = (struct user_data *)ad;
	struct user_data *bud = (struct user_data *)bd;

	uint32_t a=0;
	uint32_t b=0;

	if(rb_param){}

	if(aud != NULL && bud != NULL){
		a=aud->key;
		b=bud->key;
	}

	if (((a ^ b) & bud->netmask) == 0){
		return 0;
	}

	if (a > b) {
		ret = 1;
	}
	else if (b > a) {
		ret = -1;
	}
	return ret;
}




int user_ip_compare(void *ad, void *bd,void *rb_param)
{
	int ret = 0;
	struct user_tree_data *aud = (struct user_tree_data *)ad;
	struct user_tree_data *bud = (struct user_tree_data *)bd;

	uint32_t a=0;
	uint32_t b=0;

	if(rb_param){}

	if(aud != NULL && bud != NULL){
		a=aud->key;
		b=bud->key;
	}
	if (a > b) {
		ret = 1;
	}
	else if (b > a) {
		ret = -1;
	}
	return ret;
}


int user_compare(void *ad, void *bd,void *rb_param)
{
	int ret = 0;
	struct user_data *aud = (struct user_data *)ad;
	struct user_data *bud = (struct user_data *)bd;

	uint32_t a=0;
	uint32_t b=0;

	if(rb_param){}

	if(aud != NULL && bud != NULL){
		a=aud->key;
		b=bud->key;
	}

	if (a > b) {
		ret = 1;
	}
	else if (b > a) {
		ret = -1;
	}
	return ret;
}


int ct_compare(void *ad, void *bd,void *rb_param)
{
	int ret = 0;
	struct user_data *aud = (struct user_data *)ad;
	struct user_data *bud = (struct user_data *)bd;

	uint32_t a=0;
	uint32_t b=0;

	if(rb_param){}

	if(aud != NULL && bud != NULL){
		a=aud->key;
		b=bud->key;
	}
	if (a > b) {
		ret = 1;
	}
	else if (b > a) {
		ret = -1;
	}
	return ret;
}

int ts_compare(void *ad, void *bd,void *rb_param)
{
	int ret = 0;
	struct user_data *aud = (struct user_data *)ad;
	struct user_data *bud = (struct user_data *)bd;

	uint32_t a=0;
	uint32_t b=0;

	if(rb_param){}

	if(aud != NULL && bud != NULL){
		a=aud->key;
		b=bud->key;
	}
	if (a > b) {
		ret = 1;
	}
	else if (b > a) {
		ret = -1;
	}
	return ret;
}

int ns_compare(void *ad, void *bd,void *rb_param)
{
	int ret = 0;
	struct user_data *aud = (struct user_data *)ad;
	struct user_data *bud = (struct user_data *)bd;

	uint32_t a=0;
	uint32_t b=0;

	if(rb_param){}

	if(aud != NULL && bud != NULL){
		a=aud->key;
		b=bud->key;
	}
	if (a > b) {
		ret = 1;
	}
	else if (b > a) {
		ret = -1;
	}
	return ret;
}


int packet_idx_compare(void *ad, void *bd,void *rb_param)
{
	int ret = 0;
	struct user_data *aud = (struct user_data *)ad;
	struct user_data *bud = (struct user_data *)bd;

	uint32_t a=0;
	uint32_t b=0;

	if(rb_param){}

	if(aud != NULL && bud != NULL){
		a=aud->key;
		b=bud->key;
	}
	if (a > b) {
		ret = 1;
	}
	else if (b > a) {
		ret = -1;
	}
	return ret;
}


