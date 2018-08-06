#include <rain_common.h>

int mp_compare(void *ad, void *bd,void *rb_param)
{
	int ret = 0;
	struct mempool_data *aud = (struct mempool_data *)ad;
	struct mempool_data *bud = (struct mempool_data *)bd;

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

void mp_free(void *ad, void *rb_param)
{
	if(rb_param){}
	free(ad);
}

struct mempool * mempool_create(unsigned int size,unsigned int count)
{
	unsigned int i = 0;
	char * data = NULL;
	struct mempool_data *mpd = NULL;

	struct mempool *mp = malloc(sizeof(struct mempool));
	memset(mp,0x00,sizeof(struct mempool));
	
	char *rb_ret = NULL;
	pthread_mutex_init(&mp->mp_tree_mutex,NULL);
	pthread_mutex_init(&mp->mp_idx_mutex,NULL);
	mp->mempool_tree = rb_create((void *)mp_compare,NULL,NULL,"mempool_tree");
	mp->size = size;
	
	if(count > MAX_MEMPOOL_CNT){
		mp->mp_max_idx = MAX_MEMPOOL_CNT;
	}else{
		mp->mp_max_idx = count;
	}


	for(i = 0 ; i < mp->mp_max_idx; i++){
		mpd = malloc(sizeof(struct mempool_data));
		if(mpd == NULL){
			printf("## ERR: EXIT  %s %d ##\n",__func__,__LINE__);
			exit(0);
		}
		memset(mpd,0x00,sizeof(struct mempool_data));

		data = malloc(mp->size);
		if(data == NULL){
			printf("## ERR: EXIT  %s %d ##\n",__func__,__LINE__);
			exit(0);
		}
		memset(data,0x00,mp->size);
		
		mpd->key		= i;
		//mpd->index	= i;
		mpd->data	= data;
		mpd->isuse	= false;

		pthread_mutex_lock(&mp->mp_tree_mutex);
		rb_ret = rb_insert(mp->mempool_tree,mpd);
		pthread_mutex_unlock(&mp->mp_tree_mutex);

		if(rb_ret == NULL){
			printf("## EXIT :  %s %d idx : %d ###\n",__func__,__LINE__,i);
			exit(0);
		}

		data = NULL;
		mpd = NULL;
	}
	return mp;
}

int mempool_remove(struct mempool *mp)
{
	int ret = 0;
	if(mp != NULL){

		pthread_mutex_destroy(&mp->mp_idx_mutex);
		pthread_mutex_destroy(&mp->mp_tree_mutex);
		rb_destroy(mp->mempool_tree,mp_free);
	}
	return ret;
}


struct mempool_data * mempool_get(struct mempool *mp)
{
	struct mempool_data *pmpd=NULL;

	unsigned int tmp_idx = 0;
	int break_ret = 0;
#if 0
	struct mempool_data *mpd=NULL;
	mpd=malloc(sizeof(struct mempool_data));
	memset(mpd,0x00,sizeof(struct mempool_data));
#else
	struct mempool_data mpd;
#endif

	while(1){
		//memset(&mpd,0x00,sizeof(struct mempool_data));

		pmpd=NULL;
		pthread_mutex_lock(&mp->mp_idx_mutex);
		//mpd->key = mp->mp_idx;
		mpd.key = mp->mp_idx;
		//pthread_mutex_unlock(&mp->mp_idx_mutex);

		pthread_mutex_lock(&mp->mp_tree_mutex);
		pmpd = rb_find(mp->mempool_tree,&mpd);
		if(pmpd != NULL){
#if 0
			if(pmpd->isuse == true && pmpd->pkt_type == CONTROL_PKT){
				long long now_mil = 0,ret_mil = 0;
				struct timeval now_tv;
				gettimeofday(&now_tv,NULL);
				now_mil = ((now_tv.tv_sec*1000) + (now_tv.tv_usec/1000));
				ret_mil = now_mil - pmpd->recv_mil;
				if(ret_mil > 10){
					MM("## ERR: %s %d CONTROL mempool %d  ##\n",__func__,__LINE__,ret_mil);
					pmpd->isuse = false;
				}
			}
#endif
			if(pmpd->isuse == false){
				pmpd->isuse = true;
				break_ret = 1;
			}else
			if(tmp_idx  > (mp->mp_max_idx * 2)){
				MM("## ERR: %s %d mempool FULL %d ##\n",__func__,__LINE__,mpd.key);
				pmpd=NULL;
				break_ret = 1;
				assert(1);
			}
		}else{
				MM("## ERR: %s %d mempool FULL %d  ##\n",__func__,__LINE__,mpd.key);
				assert(1);
		}
		pthread_mutex_unlock(&mp->mp_tree_mutex);

		//pthread_mutex_lock(&mp->mp_idx_mutex);
		mp->mp_idx++;
		if(mp->mp_idx >= mp->mp_max_idx){
			mp->mp_idx = 0;
		}
		pthread_mutex_unlock(&mp->mp_idx_mutex);

		if(break_ret == 1){
			break;
		}
		tmp_idx++;
	}
	//free(mpd);
	return pmpd;
}


int mempool_memset(struct mempool *mp,unsigned int key)
{
	int ret = 0;
	struct mempool_data *pmpd=NULL;
	struct mempool_data mpd;

	mpd.key = key;

	pthread_mutex_lock(&mp->mp_tree_mutex);
	pmpd = rb_find(mp->mempool_tree,&mpd);
	if(pmpd != NULL){
		//memset(pmpd->data,0x00,mp->size);
		pmpd->isuse = false;
		pmpd->pkt_type = NORMAL_PKT;
		pmpd->recv_mil = 0;
		ret = 1;
	}else{
		MM("## ERR: EXIT %s %d  %d ##\n",__func__,__LINE__,key);
		exit(0);
	}
	pthread_mutex_unlock(&mp->mp_tree_mutex);
	return ret;
}
