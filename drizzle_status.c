#include <rain_common.h>


int drizzle_status(struct main_data *md){
	int ret=0;
	struct options *opt=NULL;
	opt = md->opt;

	struct pth_timer_data *p_t_d=NULL;
	p_t_d =malloc(sizeof(struct pth_timer_data));
	if(p_t_d == NULL){
		printf("## ERR: EXIT %s %d ##\n",__func__,__LINE__);
		exit(0);
	}
	memset(p_t_d,0x00,sizeof(struct pth_timer_data));

	struct epoll_ptr_data *epd;
	epd = malloc(sizeof(struct epoll_ptr_data));
	if(epd == NULL){
		printf("## ERR: EXIT %s %d ##\n",__func__,__LINE__);
		exit(0);
	}
	memset(epd,0x00,sizeof(struct epoll_ptr_data));
	pthread_mutex_init(&epd->mutex,NULL);
	pthread_mutex_init(&epd->all_packet_cnt_mutex,NULL);
	pthread_mutex_init(&epd->send_idx_mutex,NULL);


	epd->t_fdd     = NULL;
	epd->p_fdd     = NULL;
	epd->n_fdd     = NULL;
	epd->tp_fdd    = NULL;
	epd->np_fdd    = NULL;
	epd->thd_mode  = THREAD_STATUS;

	epd->gl_var                = (void *)md;
	epd->in_handle_func        = NULL;
	epd->out_handle_func       = NULL;
	epd->pipe_in_handle_func   = NULL;
	epd->pipe_out_handle_func  = NULL;

	p_t_d->func       = rain_timer_start;
	p_t_d->start_func = (void *)drizzle_status_thd;
	p_t_d->sec        = 0;
	p_t_d->nsec       = 0;
	p_t_d->ptr        = (void *)epd;
	sprintf(p_t_d->name,"status_thread");
	sprintf(epd->name,"status_thread");

	//p_t_d->timer_status  = 1;
	rain_timer_init(p_t_d);
	return ret;
}

int drizzle_status_thd(struct pth_timer_data *p_t_d){
	struct epoll_ptr_data *epd = NULL;
	epd = (struct epoll_ptr_data *)p_t_d->ptr;
	struct main_data *md = NULL;
	md = (struct main_data *)epd->gl_var;
	struct options *opt=NULL;
	opt = md->opt;

	bool loop = true;

	while(loop){
		sleep(1);

#if 0
		pthread_mutex_lock(&epd->pc->ping_check_mutex);
		if(epd->pc->ping_f_last_time.tv_sec > 0){
			ping_time = (epd->pc->ping_l_last_time.tv_sec - epd->pc->ping_f_last_time.tv_sec);
			if(ping_time > (md->opt->keepalive_ping)){
				epd->pc->ready = true;
				MM("#################### true  %s %d LAST time = %d ####\n",__func__,__LINE__,ping_time);
				epd->stop = 1;
				loop = false;
			}else{
				if(epd->pc->ready == true){
					MM("#################### false  %s %d LAST time = %d ####\n",__func__,__LINE__,ping_time);
				}
				epd->pc->ready = false;
			}
		}
		if(epd->pc->ping_f_last_time.tv_sec != epd->pc->ping_l_last_time.tv_sec){
			epd->pc->ping_f_last_time.tv_sec = epd->pc->ping_l_last_time.tv_sec;
		}
		pthread_mutex_unlock(&epd->pc->ping_check_mutex);

#endif

		uint64_t T_pps = 0;
		uint64_t N_pps = 0;

		uint64_t T_TPT_idx   = 0;
		uint64_t TPT_idx     = 0;

		uint64_t T_NPT_idx   = 0;
		uint64_t NPT_idx     = 0;

		uint64_t TPT_count   = 0;
		uint64_t NPT_count   = 0;

		uint64_t ct_count = 0;
		uint64_t li_count = 0;
		uint64_t user_ip_count  = 0;
		uint64_t user_count  = 0;
		pthread_mutex_lock(&md->N_nis->nis_mutex);
		N_pps = md->N_nis->pps;
		md->N_nis->pps=0;
		pthread_mutex_unlock(&md->N_nis->nis_mutex);

		pthread_mutex_lock(&md->T_nis->nis_mutex);
		T_pps = md->T_nis->pps;
		md->T_nis->pps=0;
		pthread_mutex_unlock(&md->T_nis->nis_mutex);

		pthread_mutex_lock(&md->NPT_idx_mutex);
		NPT_idx = md->NPT_idx;
		pthread_mutex_unlock(&md->NPT_idx_mutex);

		pthread_mutex_lock(&md->T_NPT_idx_mutex);
		T_NPT_idx = md->T_NPT_idx;
		pthread_mutex_unlock(&md->T_NPT_idx_mutex);


		pthread_mutex_lock(&md->TPT_idx_mutex);
		TPT_idx = md->TPT_idx;
		pthread_mutex_unlock(&md->TPT_idx_mutex);

		pthread_mutex_lock(&md->T_TPT_idx_mutex);
		T_TPT_idx = md->T_TPT_idx;
		pthread_mutex_unlock(&md->T_TPT_idx_mutex);


		pthread_mutex_lock(&md->TPT_tree_mutex);
		TPT_count = md->TPT_idx_tree->rb_count;
		pthread_mutex_unlock(&md->TPT_tree_mutex);

		pthread_mutex_lock(&md->NPT_tree_mutex);
		NPT_count = md->NPT_idx_tree->rb_count;
		pthread_mutex_unlock(&md->NPT_tree_mutex);


		if(opt->mode == SERVER){
			pthread_mutex_lock(&md->li_mutex);
			li_count =  md->li->len;
			pthread_mutex_unlock(&md->li_mutex);

			pthread_mutex_lock(&md->opt->ct_tree_mutex);
			ct_count = md->opt->ct_tree->rb_count;
			pthread_mutex_unlock(&md->opt->ct_tree_mutex);

			pthread_mutex_lock(&md->opt->user_ip_tree_mutex);
			user_ip_count = md->opt->user_ip_tree->rb_count;
			pthread_mutex_unlock(&md->opt->user_ip_tree_mutex);

			pthread_mutex_lock(&md->opt->user_tree_mutex);
			user_count = md->opt->user_tree->rb_count;
			pthread_mutex_unlock(&md->opt->user_tree_mutex);

		}
#if 0
		printf("epd->name %s li_count %llx ct_tree rb_count %llx user_ip_count %llx user_count %llx TPT rb_count %llx NPT rb_count %llx T_pps: %llx N_pps: %llx  T_TPT_idx: %llx TPT_idx: %llx  T_NPT_idx: %llx NPT_idx: %llx ##\n",
				epd->name,
				(long long unsigned int)li_count,
				(long long unsigned int)ct_count,
				(long long unsigned int)user_ip_count,
				(long long unsigned int)user_count,
				(long long unsigned int)TPT_count,
				(long long unsigned int)NPT_count,
				(long long unsigned int)T_pps,
				(long long unsigned int)N_pps,
				(long long unsigned int)T_TPT_idx,
				(long long unsigned int)TPT_idx,
				(long long unsigned int)T_NPT_idx,
				(long long unsigned int)NPT_idx
				);
#endif

#if 1
		MM("epd->name %s li_count %llx ct_tree rb_count %llx user_ip_count %llx user_count %llx TPT rb_count %llx NPT rb_count %llx T_pps: %llx N_pps: %llx  T_TPT_idx: %llx TPT_idx: %llx  T_NPT_idx: %llx NPT_idx: %llx ##\n",
				epd->name,
				(long long unsigned int)li_count,
				(long long unsigned int)ct_count,
				(long long unsigned int)user_ip_count,
				(long long unsigned int)user_count,
				(long long unsigned int)TPT_count,
				(long long unsigned int)NPT_count,
				(long long unsigned int)T_pps,
				(long long unsigned int)N_pps,
				(long long unsigned int)T_TPT_idx,
				(long long unsigned int)TPT_idx,
				(long long unsigned int)T_NPT_idx,
				(long long unsigned int)NPT_idx
		  );
#endif

	}

}

