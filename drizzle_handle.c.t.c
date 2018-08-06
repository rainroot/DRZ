#include <rain_common.h>

uint8_t ping_data_cmp[] = {
  0x2a, 0x18, 0x7b, 0xf3, 0x64, 0x1e, 0xb4, 0xcb,
  0x07, 0xed, 0x2d, 0x0a, 0x98, 0x1f, 0xc7, 0x48
};

int dz_pthread_mutex_lock(pthread_mutex_t *mutex){
	int ret_mutex=0;
	ret_mutex = pthread_mutex_lock(mutex);
	if(ret_mutex < 0){
		MM("## ERR: %s %s[:%d] ##\n",__FILE__,__func__,__LINE__);
	}
	return ret_mutex;
}

int dz_pthread_mutex_unlock(pthread_mutex_t *mutex){
	int ret_mutex=0;
	ret_mutex = pthread_mutex_unlock(mutex);
	if(ret_mutex < 0){
		MM("## ERR: %s %s[:%d] ##\n",__FILE__,__func__,__LINE__);
	}
	return ret_mutex;
}
int dz_pthread_mutex_destroy(pthread_mutex_t *mutex)
{
	int ret_mutex = 0;
	ret_mutex = pthread_mutex_destroy(mutex);
	if(ret_mutex != 0){
		//MM("## ERR: EXIT %s %s[:%d] ret_mutex %d ##\n",__FILE__,__func__,__LINE__,ret_mutex);
		ret_mutex = -1;
		//exit(0);
	}
	return ret_mutex;
}

#if 0
int TPT_sync_handle(struct epoll_ptr_data *epd,unsigned int idx){
	int ret = 0;
	bool loop = true;
	struct epoll_ptr_data *pipe_epd=NULL;
	struct epoll_ptr_data *src_epd=NULL;
	struct main_data *md = NULL;
	struct options *opt = NULL;
	md = (struct main_data *)epd->gl_var;
	opt = md->opt;

	struct packet_idx_tree_data *get_pitd=NULL;
	struct packet_idx_tree_data tmp_pitd;

	struct user_data ct_ud;
	struct user_data *ct_pud = NULL;

	struct internal_header tmp_ih;
	memset((char *)&tmp_ih,0x00,sizeof(struct internal_header));

	bool packet_drop = false;

	struct timeval now_time;
	if(idx){}

	tmp_pitd.key = idx;
	pthread_mutex_lock(&md->NPT_tree_mutex);
	get_pitd = rb_find(md->NPT_idx_tree,(char *)&tmp_pitd);
	pthread_mutex_unlock(&md->NPT_tree_mutex);
	if(get_pitd != NULL){
		pipe_epd = md->tun_epd;

		pthread_mutex_lock(&pipe_epd->t_fdd->tun_w_mutex);
		ret = tun_send(
							pipe_epd->t_fdd->tun_wfd,
							(char *)get_pitd->normal_packet_data+A_INTERNAL_HEADER+B_OPENVPN_PDATA_HEADER,
							get_pitd->normal_packet_data_len-A_INTERNAL_HEADER-B_OPENVPN_PDATA_HEADER
						);
		pthread_mutex_unlock(&pipe_epd->t_fdd->tun_w_mutex);

		pthread_mutex_lock(&md->NPT_tree_mutex);
		char * ret_rb_delete = rb_delete(md->NPT_idx_tree,get_pitd,false,sizeof(struct packet_idx_tree_data));
		pthread_mutex_unlock(&md->NPT_tree_mutex);
		int mempool_idx = get_pitd->mempool_idx;
		mempool_memset(md->pitd_mp,mempool_idx);
	}
	return ret;
}

#else
int TPT_sync_handle(struct epoll_ptr_data *epd,unsigned int idx){
	int ret = 0;
	bool loop = true;
	struct epoll_ptr_data *pipe_epd=NULL;
	struct epoll_ptr_data *src_epd=NULL;
	struct main_data *md = NULL;
	struct options *opt = NULL;
	md = (struct main_data *)epd->gl_var;
	opt = md->opt;

	struct packet_idx_tree_data *get_pitd=NULL;
	struct packet_idx_tree_data tmp_pitd;

	struct user_data ct_ud;
	struct user_data *ct_pud = NULL;

	struct internal_header tmp_ih;
	memset((char *)&tmp_ih,0x00,sizeof(struct internal_header));

	bool packet_drop = false;

	bool send_ok = false;

	struct timeval now_time;
	if(idx){}

	int send_count = 0;

	while(loop){
		send_ok = true;
		memset(&now_time,0x00,sizeof(struct timeval));
		packet_drop = false;
		ct_pud   = NULL;
		get_pitd = NULL;
		loop	= false;
		memset((char *)&tmp_pitd,0x00,sizeof(struct packet_idx_tree_data));

		pthread_mutex_lock(&md->T_NPT_idx_mutex);
		tmp_pitd.key = md->T_NPT_idx;

		pthread_mutex_lock(&md->NPT_tree_mutex);
		get_pitd = rb_find(md->NPT_idx_tree,(char *)&tmp_pitd);
		pthread_mutex_unlock(&md->NPT_tree_mutex);
		if(get_pitd != NULL){

			pthread_mutex_lock(&get_pitd->pitd_mutex);
#if 1
			long long now_mil = 0, ret_mil = 0;
			struct timeval now_tv;
			gettimeofday(&now_tv,NULL);
			now_mil = ((now_tv.tv_sec*1000) + (now_tv.tv_usec/1000));
			ret_mil = now_mil - get_pitd->recv_mil;
			if(get_pitd->recv_mil == 0){
				loop = true;
				packet_drop = true;
				get_pitd->TPT_send_ok = SEND_OK_DONE;
			}else
			if(ret_mil > PKT_TIMEOUT){
				//MM("## %s %d %lld ##\n",__func__,__LINE__,ret_mil);
				//MM("## PKT_TIMEOUT  %s %d %lld ##\n",__func__,__LINE__,ret_mil);
				loop = true;
				packet_drop = true;
				get_pitd->TPT_send_ok = SEND_OK_DONE;
			}else

#endif
			{
				if(get_pitd->TPT_send_ok == SEND_OK){
					if(opt->mode == SERVER){
						ct_ud.key = get_pitd->src_fd;
						pthread_mutex_lock(&opt->ct_tree_mutex);
						ct_pud = rb_find(opt->ct_tree,(char *)&ct_ud);
						pthread_mutex_unlock(&opt->ct_tree_mutex);
						if(ct_pud != NULL && ct_pud->epd != NULL){
							src_epd = ct_pud->epd;
							pthread_mutex_lock(&src_epd->all_packet_cnt_mutex);
							if(src_epd->all_packet_cnt <= 0){
							}
							pthread_mutex_unlock(&src_epd->all_packet_cnt_mutex);
						}else{
							loop = true;
							packet_drop = true;
							get_pitd->TPT_send_ok = SEND_OK_DONE;
						}
					}

					if(get_pitd->packet_type == NETWORK_PACKET && packet_drop == false){
						if(get_pitd->NPT_packet_status == PACKET_DROP || get_pitd->TPT_packet_status == PACKET_DROP){
							loop = true;
							packet_drop = true;
							get_pitd->TPT_send_ok = SEND_OK_DONE;
						}else if(get_pitd->TPT_packet_status == PACKET_SEND ){
							if(epd->thd_mode == THREAD_PIPE_OUT_IN){
								pipe_epd = md->tun_epd;

								pthread_mutex_lock(&pipe_epd->t_fdd->tun_w_mutex);
								ret = tun_send(
										pipe_epd->t_fdd->tun_wfd,
										(char *)get_pitd->normal_packet_data+A_INTERNAL_HEADER+B_OPENVPN_PDATA_HEADER,
										get_pitd->normal_packet_data_len-A_INTERNAL_HEADER-B_OPENVPN_PDATA_HEADER
										);
								pthread_mutex_unlock(&pipe_epd->t_fdd->tun_w_mutex);
								if(ret == 0){
								}else{

									MM("## ERR: %s %s[:%d] %s %d ##\n",__FILE__,__func__,__LINE__,epd->name,ret);
								}
								loop = true;
								packet_drop = true;
								get_pitd->TPT_send_ok = SEND_OK_DONE;
							}
						}else{

							MM("## ERR: %s %s[:%d] %s %d ##\n",__FILE__,__func__,__LINE__,epd->name,ret);
							loop = true;
							packet_drop = true;
							get_pitd->TPT_send_ok = SEND_OK_DONE;
						}
					}
				}else{
					send_ok = false;
					send_count++;
				}
			}
			pthread_mutex_unlock(&get_pitd->pitd_mutex);
			pthread_mutex_unlock(&md->T_NPT_idx_mutex);

			pthread_mutex_lock(&md->T_NPT_idx_mutex);
			if(packet_drop == true){
				pthread_mutex_lock(&md->NPT_tree_mutex);
#ifdef MEMPOLL_ENABLE
				char * ret_rb_delete = rb_delete(md->NPT_idx_tree,get_pitd,false,sizeof(struct packet_idx_tree_data));
#else
				char * ret_rb_delete = rb_delete(md->NPT_idx_tree,get_pitd,true,sizeof(struct packet_idx_tree_data));
#endif
				if(ret_rb_delete != NULL){
					dz_pthread_mutex_destroy(&get_pitd->pitd_mutex);

#ifdef MEMPOLL_ENABLE
					int mempool_idx = get_pitd->mempool_idx;
					mempool_memset(md->pitd_mp,mempool_idx);
#endif
					if(md->T_NPT_idx == 0){
						md->T_NPT_idx = 1;
					}else{
						md->T_NPT_idx++;
					}

#if 1
					if(md->T_NPT_idx - 1 >= idx){
						loop = false;
					}
#endif

					if(opt->mode == SERVER){
						if((ct_pud != NULL && ct_pud->epd == NULL) || (src_epd == NULL)){
							pthread_mutex_lock(&opt->ct_tree_mutex);
							if(ct_pud != NULL){
								rb_delete(opt->ct_tree,ct_pud,true,sizeof(struct user_data));
							}
							pthread_mutex_unlock(&opt->ct_tree_mutex);
						}else if(src_epd != NULL){
							pthread_mutex_lock(&src_epd->all_packet_cnt_mutex);
							src_epd->all_packet_cnt--;
							pthread_mutex_unlock(&src_epd->all_packet_cnt_mutex);
						}
					}

					pthread_mutex_lock(&md->T_nis->nis_mutex);
					md->T_nis->pps++;
					pthread_mutex_unlock(&md->T_nis->nis_mutex);

					struct timeval now_tv;
					gettimeofday(&now_tv,NULL);
					md->T_NPT_last_mil = ((now_tv.tv_sec*1000) + (now_tv.tv_usec/1000));
				}
				pthread_mutex_unlock(&md->NPT_tree_mutex);
#if 0
				pthread_mutex_lock(&md->NPT_tree_mutex);
#ifdef MEMPOLL_ENABLE
				int mempool_idx = get_pitd->mempool_idx;
				char * ret_rb_delete = rb_delete(md->NPT_idx_tree,get_pitd,false,sizeof(struct packet_idx_tree_data));
				if(ret_rb_delete == NULL){

					tmp_pitd.key = get_pitd->key;

					get_pitd = rb_find(md->NPT_idx_tree,(char *)&tmp_pitd);
					if(get_pitd == NULL){
						printf("## ERR: EXIT  %s %d ############\n",__func__,__LINE__);
						exit(0);
					}else{

						printf("## ??????????  EXIT  %s %d %d ############\n",__func__,__LINE__,get_pitd->key);
						exit(0);

					}
				}
				mempool_memset(md->pitd_mp,mempool_idx);
#else
				rb_delete(md->NPT_idx_tree,get_pitd,true,sizeof(struct packet_idx_tree_data));
#endif
				pthread_mutex_unlock(&md->NPT_tree_mutex);
#endif
			}else{
#if 1
				long long now_mil = 0, ret_mil = 0;
				struct timeval now_tv;
				gettimeofday(&now_tv,NULL);
				now_mil = ((now_tv.tv_sec*1000) + (now_tv.tv_usec/1000));
				ret_mil = now_mil - md->T_NPT_last_mil;
				if(md->T_NPT_last_mil == 0){

				}else if(ret_mil > LOOP_TIMEOUT && md->NPT_idx_tree->rb_count > 0){
					MM("## LOOP_TIMEOUT  %s %d %lld ##\n",__func__,__LINE__,ret_mil);
					if(md->T_NPT_idx == 0){
						md->T_NPT_idx = 1;
					}else{
						md->T_NPT_idx++;
					}
					md->T_NPT_last_mil = 0;
				}

#if 1
				if(md->T_NPT_idx - 1 == idx){
					loop = false;
				}
#endif
#endif


#if 0
				if(md->T_NPT_idx == idx){
					loop = false;
				}
#endif
			}
			pthread_mutex_unlock(&md->T_NPT_idx_mutex);
		}else{
#if 0
			long long now_mil = 0, ret_mil = 0;
			struct timeval now_tv;
			gettimeofday(&now_tv,NULL);
			now_mil = ((now_tv.tv_sec*1000) + (now_tv.tv_usec/1000));
			ret_mil = now_mil - md->T_NPT_last_mil;
			if(md->T_NPT_last_mil == 0){

			}else if(ret_mil > LOOP_TIMEOUT && md->NPT_idx_tree->rb_count > 0){
				if(md->T_NPT_idx == 0){
					md->T_NPT_idx = 1;
				}else{
					md->T_NPT_idx++;
				}
				send_count++;
				md->T_NPT_last_mil = 0;
			}

#if 1
			if(md->T_NPT_idx - 1 == idx){
				loop = false;
			}
#endif
#endif

			send_count++;
			pthread_mutex_unlock(&md->T_NPT_idx_mutex);
		}

#if 1
		if(send_count > 100){
			loop = false;
		}
#endif
#if 0
		if(send_ok == false){
			if(send_count > 50){
				loop = false;
			}
		}
#endif


#if 1
		pthread_mutex_lock(&md->T_NPT_idx_mutex);
		if(md->T_NPT_idx > idx){
			loop = false;
		}
		pthread_mutex_unlock(&md->T_NPT_idx_mutex);
#endif
	}

	return ret;
}
#endif

int NPT_sync_handle(struct epoll_ptr_data *epd,unsigned int idx){
	int ret = 0;
	unsigned long data_send_idx = 0;
	bool loop = true;
	struct epoll_ptr_data *pipe_epd=NULL;
	struct main_data *md = NULL;
	struct options *opt = NULL;
	md = (struct main_data *)epd->gl_var;
	opt = md->opt;

	struct user_data ct_ud;
	struct user_data *ct_pud = NULL;

	struct packet_idx_tree_data *get_pitd=NULL;
	struct packet_idx_tree_data tmp_pitd;

	bool gitd_delete = false;

	struct internal_header tmp_ih;
	memset((char *)&tmp_ih,0x00,sizeof(struct internal_header));

	int send_count = 0;
	bool send_ok = false;
	tmp_pitd.key	= idx;
	pthread_mutex_lock(&md->TPT_tree_mutex);
	get_pitd 		= rb_find(md->TPT_idx_tree,(char *)&tmp_pitd);
	pthread_mutex_unlock(&md->TPT_tree_mutex);

	if(get_pitd != NULL){

		pthread_mutex_lock(&get_pitd->pitd_mutex);
#if 1
		long long now_mil = 0, ret_mil = 0;
		struct timeval now_tv;
		gettimeofday(&now_tv,NULL);
		now_mil = ((now_tv.tv_sec*1000) + (now_tv.tv_usec/1000));
		ret_mil = now_mil - get_pitd->recv_mil;

		if(ret_mil > PKT_TIMEOUT){
			//MM("## PKT_TIMEOUT  %s %d %lld ##\n",__func__,__LINE__,ret_mil);
			get_pitd->NPT_packet_status = PACKET_DROP;
			get_pitd->TPT_packet_status = PACKET_DROP;
			get_pitd->NPT_send_ok = SEND_OK;

		}else
#endif
		{
			if(get_pitd->encrypt_packet_data_len == 0){
				if(get_pitd->NPT_packet_status == PACKET_SEND){
					if(epd->thd_mode == THREAD_PIPE_IN_OUT){
						if(opt->mode == SERVER){
							ct_ud.key = get_pitd->dst_fd;
							pthread_mutex_lock(&opt->ct_tree_mutex);
							ct_pud = rb_find(opt->ct_tree,(char *)&ct_ud);
							pthread_mutex_unlock(&opt->ct_tree_mutex);
							if(ct_pud != NULL){
								pipe_epd = ct_pud->epd;
							}else{

								pipe_epd = NULL;
								get_pitd->NPT_packet_status = PACKET_DROP;
								get_pitd->TPT_packet_status = PACKET_DROP;
								get_pitd->NPT_send_ok = SEND_OK;
							}
						}else{
							pipe_epd = md->net_epd;
						}

						if(pipe_epd != NULL && pipe_epd->stop != 1){
							if(get_pitd->NPT_packet_status != PACKET_DROP && get_pitd->TPT_packet_status != PACKET_DROP){
								int data_ret=0;
								uint8_t op_key=0;
								int keyid = 0;

								if(pipe_epd->ss != NULL){
									keyid = pipe_epd->ss->keyid;

									data_send_idx = htonl(get_pitd->data_send_idx);
									memcpy(get_pitd->normal_packet_data+A_INTERNAL_HEADER+B_OPENVPN_PKT_SIZE+B_OPENVPN_KEYID_OPCODE,(char *)&data_send_idx,B_OPENVPN_PACKET_IDX);

									data_ret = data_encrypt(pipe_epd,
											(char *)get_pitd->normal_packet_data+A_INTERNAL_HEADER+B_OPENVPN_PKT_SIZE+B_OPENVPN_KEYID_OPCODE,
											get_pitd->normal_packet_data_len-A_INTERNAL_HEADER-B_OPENVPN_PKT_SIZE-B_OPENVPN_KEYID_OPCODE,
											(char *)get_pitd->encrypt_packet_data+A_INTERNAL_HEADER+B_OPENVPN_PKT_SIZE+B_OPENVPN_KEYID_OPCODE,
											keyid,
											epd->idx
											);

									if(data_ret == 0){
										MM("##ERR: %s %s[:%d] %s##\n",__FILE__,__func__,__LINE__,epd->name);
										exit(0);
									}

									if(data_ret > 0){
										op_key = (keyid | (P_DATA_V1 << P_OPCODE_SHIFT));
										memcpy(get_pitd->encrypt_packet_data+A_INTERNAL_HEADER+B_OPENVPN_PKT_SIZE,(char *)&op_key,B_OPENVPN_KEYID_OPCODE);

										get_pitd->encrypt_packet_data_len = data_ret + A_INTERNAL_HEADER + B_OPENVPN_PKT_SIZE + B_OPENVPN_KEYID_OPCODE;
										data_ret = htons(data_ret + B_OPENVPN_KEYID_OPCODE);
										memcpy(get_pitd->encrypt_packet_data+A_INTERNAL_HEADER,(char *)&data_ret,B_OPENVPN_PKT_SIZE);
										if(data_ret == 0 || data_ret-B_OPENVPN_KEYID_OPCODE == 0){
											MM("##ERR: %s %s[:%d] %s##\n",__FILE__,__func__,__LINE__,epd->name);
											exit(0);
										}

										get_pitd->NPT_packet_status = PACKET_F_SEND;
									}else{
										MM("##ERR: %s %s[:%d] %s##\n",__FILE__,__func__,__LINE__,epd->name);
									}

								}else{

									get_pitd->NPT_packet_status = PACKET_DROP;
									get_pitd->TPT_packet_status = PACKET_DROP;
									get_pitd->NPT_send_ok = SEND_OK;
								}
							}

						}else{
							get_pitd->NPT_packet_status = PACKET_DROP;
							get_pitd->TPT_packet_status = PACKET_DROP;
							get_pitd->NPT_send_ok = SEND_OK;
						}
					}

				}

			}else{
				MM("##ERR: %s %s[:%d] %s idx %d ##\n",__FILE__,__func__,__LINE__,epd->name,idx);
			}
		}
		pthread_mutex_unlock(&get_pitd->pitd_mutex);
	}else{
		//MM("##ERR: %s %s[:%d] %s idx %lld ##\n",__FILE__,__func__,__LINE__,epd->name,idx);
		//exit(0);
	}

	get_pitd = NULL;
	bool gogo = false;
	while(loop){
		get_pitd = NULL;
		gitd_delete = false;
		gogo = false;
		loop	= false;
		send_ok = true;
		memset((char *)&tmp_pitd,0x00,sizeof(struct packet_idx_tree_data));

		pthread_mutex_lock(&md->T_TPT_idx_mutex);
		tmp_pitd.key	= md->T_TPT_idx;

		pthread_mutex_lock(&md->TPT_tree_mutex);
		get_pitd = rb_find(md->TPT_idx_tree,(char *)&tmp_pitd);
		pthread_mutex_unlock(&md->TPT_tree_mutex);

		if(get_pitd != NULL){
			pthread_mutex_lock(&get_pitd->pitd_mutex);

			long long now_mil = 0, ret_mil = 0;
			struct timeval now_tv;
			gettimeofday(&now_tv,NULL);
			now_mil = ((now_tv.tv_sec*1000) + (now_tv.tv_usec/1000));
			ret_mil = now_mil - get_pitd->recv_mil;

			if(get_pitd->recv_mil == 0){
				pipe_epd = NULL;
				gitd_delete = true;
				get_pitd->NPT_send_ok = SEND_OK_DONE;
				loop = true;
			}else
			if(ret_mil > PKT_TIMEOUT){
				//MM("## PKT_TIMEOUT  %s %d %lld ##\n",__func__,__LINE__,ret_mil);
				pipe_epd = NULL;
				gitd_delete = true;
				get_pitd->NPT_send_ok = SEND_OK_DONE;
				loop = true;
			}else{


				if(get_pitd->NPT_send_ok == SEND_OK){
					if(get_pitd->packet_type == TUN_PACKET){
						gogo = true;
						if(gogo == true){
							if(get_pitd->NPT_packet_status == PACKET_DROP || get_pitd->TPT_packet_status == PACKET_DROP){
								loop = true;
								gitd_delete = true;
								get_pitd->NPT_send_ok = SEND_OK_DONE;
							}else if(get_pitd->NPT_packet_status == PACKET_F_SEND  && get_pitd->encrypt_packet_data_len > 0){
								if(epd->thd_mode == THREAD_PIPE_IN_OUT){
									loop = true;
									if(opt->mode == SERVER){
										ct_ud.key = get_pitd->dst_fd;
										pthread_mutex_lock(&opt->ct_tree_mutex);
										ct_pud = rb_find(opt->ct_tree,(char *)&ct_ud);
										pthread_mutex_unlock(&opt->ct_tree_mutex);
										if(ct_pud != NULL){
											pipe_epd = ct_pud->epd;
										}else{
											pipe_epd = NULL;
											gitd_delete = true;
											get_pitd->NPT_send_ok = SEND_OK_DONE;
											//printf("## %s %d ct_tree not found \n",__func__,__LINE__);
										}

									}else{
										pipe_epd = md->net_epd;
									}

									if(pipe_epd != NULL && pipe_epd->n_fdd != NULL){
											pthread_mutex_lock(&pipe_epd->n_fdd->net_w_mutex);
											ret = tcp_send(
													pipe_epd->n_fdd->net_wfd,
													(char *)get_pitd->encrypt_packet_data+A_INTERNAL_HEADER,
													get_pitd->encrypt_packet_data_len-A_INTERNAL_HEADER
													);
											pthread_mutex_unlock(&pipe_epd->n_fdd->net_w_mutex);
											if(ret == 0){
											}else if( ret < 0){
												//MM("# EXIT ### %s %d name %s key %08x data_send_idx %08x###\n",__func__,__LINE__,pipe_epd->name,tmp_pitd.key,get_pitd->data_send_idx);
												ret = 0;
											}
									}
									loop = true;
									gitd_delete = true;
									get_pitd->NPT_send_ok = SEND_OK_DONE;

								}
							}
						}
					}
				}else{
					send_ok = false;
					send_count++;
				}
			}

			pthread_mutex_unlock(&get_pitd->pitd_mutex);
			pthread_mutex_unlock(&md->T_TPT_idx_mutex);

			pthread_mutex_lock(&md->T_TPT_idx_mutex);
			if(gitd_delete == true){

				pthread_mutex_lock(&md->TPT_tree_mutex);
#ifdef MEMPOLL_ENABLE
				char * ret_rb_delete = rb_delete(md->TPT_idx_tree,get_pitd,false,sizeof(struct packet_idx_tree_data));
#else
				char * ret_rb_delete = rb_delete(md->TPT_idx_tree,get_pitd,true,sizeof(struct packet_idx_tree_data));
#endif
				pthread_mutex_unlock(&md->TPT_tree_mutex);

				if(ret_rb_delete != NULL){

					dz_pthread_mutex_destroy(&get_pitd->pitd_mutex);
#ifdef MEMPOLL_ENABLE
					unsigned int mempool_idx = get_pitd->mempool_idx;
					mempool_memset(md->pitd_mp,mempool_idx);
#endif

					if(md->T_TPT_idx == 0){
						md->T_TPT_idx = 1;
					}else{
						md->T_TPT_idx++;
					}
					//send_count++;
#if 1
					if(md->T_TPT_idx - 1 >= idx){
						loop = false;
					}
#endif
					pthread_mutex_lock(&md->N_nis->nis_mutex);
					md->N_nis->pps++;
					pthread_mutex_unlock(&md->N_nis->nis_mutex);

					struct timeval now_tv;
					gettimeofday(&now_tv,NULL);
					md->T_TPT_last_mil = ((now_tv.tv_sec*1000) + (now_tv.tv_usec/1000));


				}
#if 0
				pthread_mutex_lock(&md->TPT_tree_mutex);
				dz_pthread_mutex_destroy(&get_pitd->pitd_mutex);
#ifdef MEMPOLL_ENABLE
				unsigned int mempool_idx = get_pitd->mempool_idx;
				char * ret_rb_delete = rb_delete(md->TPT_idx_tree,get_pitd,false,sizeof(struct packet_idx_tree_data));
				if(ret_rb_delete == NULL){
					printf("## ERR: EXIT  %s %d %d ############\n",__func__,__LINE__,get_pitd->key);
					exit(0);
				}
				mempool_memset(md->pitd_mp,mempool_idx);
#else
				rb_delete(md->TPT_idx_tree,get_pitd,true,sizeof(struct packet_idx_tree_data));
#endif
				pthread_mutex_unlock(&md->TPT_tree_mutex);
#endif
			}else{
#if 1
				long long now_mil = 0, ret_mil = 0;
				struct timeval now_tv;
				gettimeofday(&now_tv,NULL);
				now_mil = ((now_tv.tv_sec*1000) + (now_tv.tv_usec/1000));
				ret_mil = now_mil - md->T_TPT_last_mil;
				if(md->T_TPT_last_mil == 0){

				}else if(ret_mil > LOOP_TIMEOUT && md->TPT_idx_tree->rb_count > 0){
					MM("## LOOP_TIMEOUT  %s %d %lld ##\n",__func__,__LINE__,ret_mil);
					if(md->T_TPT_idx == 0){
						md->T_TPT_idx = 1;
					}else{
						md->T_TPT_idx++;
					}
					md->T_TPT_last_mil = 0;

#if 1
					if(md->T_TPT_idx-1 == idx){
						loop = false;
					}
#endif

				}
#endif


#if 0
				if(md->T_TPT_idx == idx){
					loop = false;
				}
#endif
			}

			pthread_mutex_unlock(&md->T_TPT_idx_mutex);
		}else{
#if 0
				long long now_mil = 0, ret_mil = 0;
				struct timeval now_tv;
				gettimeofday(&now_tv,NULL);
				now_mil = ((now_tv.tv_sec*1000) + (now_tv.tv_usec/1000));
				ret_mil = now_mil - md->T_TPT_last_mil;
				if(md->T_TPT_last_mil == 0){

				}else if(ret_mil > LOOP_TIMEOUT && md->TPT_idx_tree->rb_count > 0){
					if(md->T_TPT_idx == 0){
						md->T_TPT_idx = 1;
					}else{
						md->T_TPT_idx++;
					}
					send_count++;
					md->T_TPT_last_mil = 0;

#if 1
					if(md->T_TPT_idx-1 == idx){
						loop = false;
					}
#endif

				}
#endif


			send_count++;
			pthread_mutex_unlock(&md->T_TPT_idx_mutex);
		}
#if 1
		if(send_count > 100){
			loop = false;
		}
#endif
#if 0
		if(send_ok == false){
			loop = false;
		}
#endif
#if 1
		pthread_mutex_lock(&md->T_TPT_idx_mutex);
		if(md->T_TPT_idx > idx){
			loop = false;
		}
		pthread_mutex_unlock(&md->T_TPT_idx_mutex);
#endif


	}
	return ret;
}

int tun_FD_recv_handle(struct epoll_ptr_data *epd)
{

	int ret = 0;
	int recv_len = 0;
	int ret_in_out=0;
	uint32_t packet_idx = 0;
	struct main_data *md = NULL;
	struct options *opt = NULL;
	struct internal_header *ih=NULL;
	struct packet_idx_tree_data *pitd=NULL;
	struct packet_idx_tree_data tmp_pitd;
	struct epoll_ptr_data *pipe_epd=NULL;

	md = (struct main_data *)epd->gl_var;
	opt = md->opt;
	int tun_type=0;
	char tmp_buff[2048]={0,};

	char * rb_i_ret = NULL;
	tun_type = dev_type_enum (opt->dev, opt->dev_type);

	struct mempool_data * mpd = mempool_get(md->pitd_mp);
	if(mpd == NULL){
		MM("## ERR: %s %d ##\n",__func__,__LINE__);
		//tun_rev(epd->t_fdd->tun_rfd,tmp_buff,1024);
		//exit(0);

		pthread_mutex_lock(&md->TPT_tree_mutex);
		pthread_mutex_lock(&md->T_TPT_idx_mutex);
		tmp_pitd.key = md->T_TPT_idx;
		pthread_mutex_unlock(&md->T_TPT_idx_mutex);
		pitd = rb_find(md->TPT_idx_tree,&tmp_pitd);
		pthread_mutex_unlock(&md->TPT_tree_mutex);

		if(pitd != NULL){
			ih = (struct internal_header *)pitd->normal_packet_data;

			pthread_mutex_lock(&md->work_in_out_mutex);
			if(md->in_out_idx == opt->core){
				md->in_out_idx = 0;
			}
			pipe_epd = md->work_in_out_epd[md->in_out_idx];
			md->in_out_idx++;
			pthread_mutex_unlock(&md->work_in_out_mutex);

			ret = pipe_SEND_handle(pipe_epd,(char *)ih,A_INTERNAL_HEADER);
			if(ret < 0){
				MM("## ERR: %s %s[:%d] %s RET: %d ##\n",__FILE__,__func__,__LINE__,epd->name,ret);
			}
		}else{
			MM("## ERR: %s %d %08x ##\n",__func__,__LINE__,tmp_pitd.key);
		}
	}else{

		pitd = (struct packet_idx_tree_data *)mpd->data;
		memset(pitd,0x00,sizeof(struct packet_idx_tree_data));
		pitd->mempool_idx = mpd->key;
		pthread_mutex_init(&pitd->pitd_mutex,NULL);
		recv_len = tun_rev(epd->t_fdd->tun_rfd,(char *)pitd->normal_packet_data+B_OPENVPN_PDATA_HEADER+A_INTERNAL_HEADER,sizeof(pitd->normal_packet_data));
		if(recv_len <=0){
			MM("## ERR: %s %s[:%d] %s ##\n",__FILE__,__func__,__LINE__,epd->name);

			dz_pthread_mutex_destroy(&pitd->pitd_mutex);
			mempool_memset(md->pitd_mp,pitd->mempool_idx);
			ret = -1;
		}else{

			struct timeval tv;
			gettimeofday(&tv,NULL);
			pitd->recv_mil = ((tv.tv_sec*1000) + (tv.tv_usec/1000));
			pitd->normal_packet_data_len	= recv_len+A_INTERNAL_HEADER+B_OPENVPN_PDATA_HEADER;

			ih = (struct internal_header *)pitd->normal_packet_data;
			ih->size				= htons(recv_len + A_INTERNAL_HEADER + B_OPENVPN_PDATA_HEADER);
			ih->fd				= htons(epd->t_fdd->tun_rfd);
			ih->packet_type 	= htonl(TUN_PACKET);


			if(tun_type == DEV_TYPE_TUN){
				ret_in_out = tunfd_route_tun_in_out(epd,pitd,ih);
			}else if(tun_type == DEV_TYPE_TAP){
				ret_in_out = tunfd_route_tap_in_out(epd,pitd,ih);
			}
			if(ret_in_out > 0){
				pthread_mutex_lock(&md->TPT_idx_mutex);


				mpd->pkt_type = DATA_PKT;
				mpd->recv_mil = pitd->recv_mil;

				packet_idx 		= (md->TPT_idx);
				ih->packet_idx	= htonl(packet_idx);

				if(md->TPT_idx == 0){
					md->TPT_idx = 1;
				}else{
					md->TPT_idx++;
				}
				pthread_mutex_unlock(&md->TPT_idx_mutex);

				pitd->key 							= packet_idx;
				pitd->src_fd 						= epd->t_fdd->tun_rfd;
				pitd->packet_type					= TUN_PACKET;
				pitd->TPT_send_ok					= SEND_OK;
				pitd->TPT_packet_status			= PACKET_SEND;

				pthread_mutex_lock(&md->TPT_tree_mutex);
				rb_i_ret = rb_insert(md->TPT_idx_tree,pitd);
				if(rb_i_ret == NULL){
					printf("## ERR; exit  %s %d #######################\n",__func__,__LINE__);
					exit(0);
				}
				pthread_mutex_unlock(&md->TPT_tree_mutex);

				pthread_mutex_lock(&md->work_in_out_mutex);
				if(md->in_out_idx == opt->core){
					md->in_out_idx = 0;
				}
				pipe_epd = md->work_in_out_epd[md->in_out_idx];
				md->in_out_idx++;
				pthread_mutex_unlock(&md->work_in_out_mutex);

				ret = pipe_SEND_handle(pipe_epd,(char *)ih,A_INTERNAL_HEADER);
				if(ret < 0){
					MM("## ERR: %s %s[:%d] %s RET: %d ##\n",__FILE__,__func__,__LINE__,epd->name,ret);
				}
			}else{
				dz_pthread_mutex_destroy(&pitd->pitd_mutex);
				mempool_memset(md->pitd_mp,pitd->mempool_idx);
				ret = -1;
			}
		}
	}
	return ret;
}

int net_FD_recv_handle(struct epoll_ptr_data *epd)
{
	int ret = 0;
	int recv_len = 0;
	uint16_t p_len = 0;
	uint32_t packet_idx = 0;
	struct main_data *md = NULL;
	struct options *opt = NULL;
	struct internal_header *ih=NULL;
	struct packet_idx_tree_data *pitd=NULL;
	struct packet_idx_tree_data tmp_pitd;
	struct epoll_ptr_data *pipe_epd=NULL;

	char * rb_i_ret = NULL;

	char tmp_buff[2048]={0,};

	md = (struct main_data *)epd->gl_var;
	opt = md->opt;

	struct mempool_data * mpd = mempool_get(md->pitd_mp);
	if(mpd == NULL){
		MM("## ERR: %s %d ##\n",__func__,__LINE__);

		pthread_mutex_lock(&md->NPT_tree_mutex);
		pthread_mutex_lock(&md->T_NPT_idx_mutex);
		tmp_pitd.key = md->T_NPT_idx;
		pthread_mutex_unlock(&md->T_NPT_idx_mutex);
		pitd = rb_find(md->NPT_idx_tree,&tmp_pitd);
		pthread_mutex_unlock(&md->NPT_tree_mutex);

		if(pitd != NULL){
			ih	= (struct internal_header *)pitd->encrypt_packet_data;
			pthread_mutex_lock(&md->work_out_in_mutex);
			if(md->out_in_idx == opt->core){
				md->out_in_idx = 0;
			}
			pipe_epd = md->work_out_in_epd[md->out_in_idx];
			md->out_in_idx++;
			pthread_mutex_unlock(&md->work_out_in_mutex);

			ret = pipe_SEND_handle(pipe_epd,(char *)ih,A_INTERNAL_HEADER);
			if(ret < 0){
				MM("## ERR: %s %s[:%d] %s RET: %d ##\n",__FILE__,__func__,__LINE__,epd->name,ret);
			}
		}else{
			MM("## ERR: %s %d %08x ##\n",__func__,__LINE__,tmp_pitd.key);
		}
	}else{
		//pthread_mutex_lock(&epd->n_fdd->net_r_mutex);
		recv_len = tcp_rev(epd->n_fdd->net_rfd,(char *)&p_len,sizeof(p_len));
		//pthread_mutex_unlock(&epd->n_fdd->net_r_mutex);
		if(recv_len <=0){
			//MM("## ERR: %s %s[:%d] %s ##\n",__FILE__,__func__,__LINE__,epd->name);
			ret = -1;

		}else{

			if(p_len > 0){
				pitd = (struct packet_idx_tree_data *)mpd->data;
				memset(pitd,0x00,sizeof(struct packet_idx_tree_data));
				pitd->mempool_idx = mpd->key;
				pthread_mutex_init(&pitd->pitd_mutex,NULL);
				memcpy(pitd->encrypt_packet_data+A_INTERNAL_HEADER,(char *)&p_len,A_INTERNAL_PKT_SIZE);

				//pthread_mutex_lock(&epd->n_fdd->net_r_mutex);
				recv_len = tcp_rev(epd->n_fdd->net_rfd,(char *)pitd->encrypt_packet_data+A_INTERNAL_HEADER+A_INTERNAL_PKT_SIZE,ntohs(p_len));
				//pthread_mutex_unlock(&epd->n_fdd->net_r_mutex);

				struct timeval tv;
				gettimeofday(&tv,NULL);
				pitd->recv_mil = ((tv.tv_sec*1000) + (tv.tv_usec/1000));
				mpd->recv_mil = pitd->recv_mil;

				if(recv_len <= 0){
					MM("## ERR: %s %s[:%d] %s ##\n",__FILE__,__func__,__LINE__,epd->name);

					dz_pthread_mutex_destroy(&pitd->pitd_mutex);
					mempool_memset(md->pitd_mp,pitd->mempool_idx);
					ret = -1;
				}else{
					recv_len += A_INTERNAL_PKT_SIZE;
					if(get_opcode((char *)pitd->encrypt_packet_data+A_INTERNAL_HEADER+A_INTERNAL_PKT_SIZE) != P_DATA_V1){
						char out[MAX_PKT_SIZE]={0,};
						int outlen=0;
						if(epd->stop != 1){
							ret = process(epd,(char *)pitd->encrypt_packet_data+A_INTERNAL_HEADER+A_INTERNAL_PKT_SIZE,recv_len-A_INTERNAL_PKT_SIZE,(char *)&out,(int *)&outlen);
							if(ret > 0){
								//MM("## EXIT  %s %s[:%d] %s %d ##\n",__FILE__,__func__,__LINE__,epd->name,get_opcode((char *)pitd->encrypt_packet_data+A_INTERNAL_HEADER+A_INTERNAL_PKT_SIZE));
								//exit(0);
							}else if(ret < 0){
								//MM("## EXIT  %s %s[:%d] %s %d ##\n",__FILE__,__func__,__LINE__,epd->name,get_opcode((char *)pitd->encrypt_packet_data+A_INTERNAL_HEADER+A_INTERNAL_PKT_SIZE));
								//exit(0);
							}
						}else{
							printf("## %s %d size %d %s ##\n",__func__,__LINE__,recv_len,epd->name);
						}
						dz_pthread_mutex_destroy(&pitd->pitd_mutex);
						mempool_memset(md->pitd_mp,pitd->mempool_idx);

					}else{

						mpd->pkt_type = DATA_PKT;
						pthread_mutex_lock(&epd->all_packet_cnt_mutex);
						epd->all_packet_cnt++;
						pthread_mutex_unlock(&epd->all_packet_cnt_mutex);

						ih 					= (struct internal_header *)pitd->encrypt_packet_data;
						ih->size			 	= htons(recv_len + A_INTERNAL_HEADER);
						ih->fd			 	= htons(epd->n_fdd->net_rfd);
						ih->packet_type 	= htonl(NETWORK_PACKET);

						pthread_mutex_lock(&md->NPT_idx_mutex);
						packet_idx 		 = (md->NPT_idx);
						ih->packet_idx	 = htonl(packet_idx);

						if(md->NPT_idx == 0){
							md->NPT_idx = 1;
						}else{
							md->NPT_idx++;
						}
						pthread_mutex_unlock(&md->NPT_idx_mutex);

						pitd->key 							= packet_idx;
						pitd->src_fd 						= epd->n_fdd->net_rfd;
						pitd->packet_type					= NETWORK_PACKET;
						pitd->encrypt_packet_data_len	= recv_len + A_INTERNAL_HEADER;
						pitd->NPT_send_ok					= SEND_OK;
						pitd->NPT_packet_status			= PACKET_SEND;

						pthread_mutex_lock(&md->NPT_tree_mutex);
						rb_i_ret = rb_insert(md->NPT_idx_tree,pitd);
						if(rb_i_ret == NULL){
							printf("## ERR; exit  %s %d #######################\n",__func__,__LINE__);
							exit(0);
						}
						pthread_mutex_unlock(&md->NPT_tree_mutex);

						pthread_mutex_lock(&md->work_out_in_mutex);
						if(md->out_in_idx == opt->core){
							md->out_in_idx = 0;
						}
						pipe_epd = md->work_out_in_epd[md->out_in_idx];
						md->out_in_idx++;
						pthread_mutex_unlock(&md->work_out_in_mutex);

						ret = pipe_SEND_handle(pipe_epd,(char *)ih,A_INTERNAL_HEADER);
						if(ret < 0){
							MM("## ERR: %s %s[:%d] %s RET: %d ##\n",__FILE__,__func__,__LINE__,epd->name,ret);
						}

					}
				}

			}
		}
	}
	return ret;
}

int pipe_RECV_handle(struct epoll_ptr_data *epd)
{

	int ret = 0;
	int in_out_ret=0;
	int out_in_ret=0;

	int tun_type = 0;
	int recv_len = 0;
	struct main_data *md = NULL;
	struct options *opt = NULL;

	struct internal_header ih;
	struct packet_idx_tree_data *get_pitd=NULL;
	struct packet_idx_tree_data tmp_pitd;

	bool packet_now_ping = false;

	md = (struct main_data *)epd->gl_var;
	opt = md->opt;
	tun_type = dev_type_enum (opt->dev, opt->dev_type);
	if(epd->thd_mode == THREAD_PIPE_IN_OUT){
		pthread_mutex_lock(&epd->tp_fdd->pipe_r_mutex);
		recv_len = pipe_rev(epd->tp_fdd->pipe_rfd,(char *)&ih,A_INTERNAL_HEADER);
		pthread_mutex_unlock(&epd->tp_fdd->pipe_r_mutex);
	}else if(epd->thd_mode == THREAD_PIPE_OUT_IN){
		pthread_mutex_lock(&epd->np_fdd->pipe_r_mutex);
		recv_len = pipe_rev(epd->np_fdd->pipe_rfd,(char *)&ih,A_INTERNAL_HEADER);
		pthread_mutex_unlock(&epd->np_fdd->pipe_r_mutex);
	}

	if(recv_len <= 0){
		MM("## ERR: %s %s[:%d] %s RET: %d ##\n",__FILE__,__func__,__LINE__,epd->name,recv_len);
		ret = -1;
	}else{

		memset((char *)&tmp_pitd,0x00,sizeof(struct packet_idx_tree_data));

		tmp_pitd.key = ntohl(ih.packet_idx);
		if(epd->thd_mode == THREAD_PIPE_IN_OUT){
			pthread_mutex_lock(&md->TPT_tree_mutex);
			get_pitd = rb_find(md->TPT_idx_tree,(char *)&tmp_pitd);
			pthread_mutex_unlock(&md->TPT_tree_mutex);

		}else if(epd->thd_mode == THREAD_PIPE_OUT_IN){
			pthread_mutex_lock(&md->NPT_tree_mutex);
			get_pitd = rb_find(md->NPT_idx_tree,(char *)&tmp_pitd);
			pthread_mutex_unlock(&md->NPT_tree_mutex);
		}

		if(get_pitd != NULL){
			if(tun_type == DEV_TYPE_TUN){
				if(epd->thd_mode == THREAD_PIPE_IN_OUT){
					NPT_sync_handle(epd,tmp_pitd.key);
				}else if(epd->thd_mode == THREAD_PIPE_OUT_IN){

					struct epoll_ptr_data *tmp_epd = NULL;
					struct user_data ct_ud;
					struct user_data *ct_pud = NULL;
					int data_ret = 0;
					int keyid = 0;

					if(opt->mode == SERVER){
						ct_ud.key = ntohs(ih.fd);						
						pthread_mutex_lock(&opt->ct_tree_mutex);
						ct_pud = rb_find(opt->ct_tree,(char *)&ct_ud);
						pthread_mutex_unlock(&opt->ct_tree_mutex);
						if(ct_pud != NULL){
							tmp_epd = ct_pud->epd;
						}
					}else if(opt->mode == CLIENT){
						tmp_epd = md->net_epd;
					}

					if(tmp_epd != NULL){

						keyid = get_keyid((char *)get_pitd->encrypt_packet_data+A_INTERNAL_HEADER+B_OPENVPN_PKT_SIZE);
						data_ret = data_decrypt(tmp_epd,
								(char *)get_pitd->encrypt_packet_data+A_INTERNAL_HEADER+B_OPENVPN_PKT_SIZE+B_OPENVPN_KEYID_OPCODE,
								get_pitd->encrypt_packet_data_len-A_INTERNAL_HEADER-B_OPENVPN_PKT_SIZE-B_OPENVPN_KEYID_OPCODE,
								(char *)get_pitd->normal_packet_data+A_INTERNAL_HEADER+B_OPENVPN_PKT_SIZE+B_OPENVPN_KEYID_OPCODE,
								keyid,
								epd->idx
								);

						if(data_ret < 0){

							MM("## ERR: %s %s[:%d] %s %d ##\n",__FILE__,__func__,__LINE__,epd->name,data_ret);

							get_pitd->NPT_send_ok 			= 0;
							get_pitd->NPT_packet_status 	= 0;
							get_pitd->TPT_send_ok 			= SEND_OK;
							get_pitd->TPT_packet_status 	= PACKET_DROP;
							get_pitd->ping_send = 0;

						}else{
							memcpy(get_pitd->normal_packet_data,
									get_pitd->encrypt_packet_data,
									A_INTERNAL_HEADER+B_OPENVPN_PKT_SIZE+B_OPENVPN_KEYID_OPCODE);

							get_pitd->normal_packet_data_len = data_ret + A_INTERNAL_HEADER+B_OPENVPN_PKT_SIZE+B_OPENVPN_KEYID_OPCODE;
							if((get_pitd->normal_packet_data_len - A_INTERNAL_HEADER - B_OPENVPN_PDATA_HEADER) == 16){
								if(memcmp(get_pitd->normal_packet_data+A_INTERNAL_HEADER+B_OPENVPN_PDATA_HEADER,ping_data_cmp,16) == 0){
									pthread_mutex_lock(&tmp_epd->pc->ping_check_mutex);
									//tmp_epd->pc->ping_check = true;
									gettimeofday(&tmp_epd->pc->ping_l_last_time,NULL);
									pthread_mutex_unlock(&tmp_epd->pc->ping_check_mutex);

									get_pitd->NPT_send_ok 			= 0;
									get_pitd->NPT_packet_status 	= 0;
									get_pitd->TPT_send_ok 			= SEND_OK;
									get_pitd->TPT_packet_status 	= PACKET_DROP;
									get_pitd->ping_send = 0;

									packet_now_ping = true;
								}else{
									packet_now_ping = false;
								}
							}else{
								packet_now_ping = false;
							}

							if(packet_now_ping == false){

								in_out_ret = tunfd_route_tun_out_in(epd,get_pitd,&ih);
								if(in_out_ret < 0){
									get_pitd->NPT_send_ok 			= 0;
									get_pitd->NPT_packet_status 	= 0;
									get_pitd->TPT_send_ok 			= SEND_OK;
									get_pitd->TPT_packet_status 	= PACKET_DROP;
									get_pitd->ping_send = 0;
									//MM("## ERR: %s %s[:%d] %s %d ##\n",__FILE__,__func__,__LINE__,epd->name,ret);
								}
							}else{
								get_pitd->NPT_send_ok 			= 0;
								get_pitd->NPT_packet_status 	= 0;
								get_pitd->TPT_send_ok 			= SEND_OK;
								get_pitd->TPT_packet_status 	= PACKET_DROP;
								get_pitd->ping_send = 0;
							}
							TPT_sync_handle(epd,ntohl(ih.packet_idx));
						}
					}
					else{
						get_pitd->NPT_send_ok = 0;
						get_pitd->NPT_packet_status = 0;
						get_pitd->TPT_send_ok = SEND_OK;
						get_pitd->TPT_packet_status = PACKET_DROP;
						get_pitd->ping_send = 0;
						TPT_sync_handle(epd,ntohl(ih.packet_idx));
#if 0

						in_out_ret = tunfd_route_tun_out_in(epd,get_pitd,&ih);
						if(in_out_ret < 0){
							get_pitd->NPT_send_ok = 0;
							get_pitd->NPT_packet_status = 0;
							get_pitd->TPT_send_ok = SEND_OK;
							get_pitd->TPT_packet_status = PACKET_DROP;
							get_pitd->ping_send = 0;
							//MM("## ERR: %s %s[:%d] %s %d ##\n",__FILE__,__func__,__LINE__,epd->name,ret);
						}else{
						}
							TPT_sync_handle(epd,ntohl(ih.packet_idx));
#endif
					}
				}
			}else if(tun_type == DEV_TYPE_TAP){
				if(epd->thd_mode == THREAD_PIPE_IN_OUT){
					NPT_sync_handle(epd,tmp_pitd.key);
				}else if(epd->thd_mode == THREAD_PIPE_OUT_IN){

					struct epoll_ptr_data *tmp_epd = NULL;
					struct user_data ct_ud;
					struct user_data *ct_pud = NULL;
					int data_ret = 0;
					int keyid = 0;

					if(opt->mode == SERVER){
						ct_ud.key = ntohs(ih.fd);						
						pthread_mutex_lock(&opt->ct_tree_mutex);
						ct_pud = rb_find(opt->ct_tree,(char *)&ct_ud);
						pthread_mutex_unlock(&opt->ct_tree_mutex);
						if(ct_pud != NULL){
							tmp_epd = ct_pud->epd;
						}
					}else if(opt->mode == CLIENT){
						tmp_epd = md->net_epd;
					}

					if(tmp_epd != NULL){

						keyid = get_keyid((char *)get_pitd->encrypt_packet_data+A_INTERNAL_HEADER+B_OPENVPN_PKT_SIZE);

						data_ret = data_decrypt(tmp_epd,
								(char *)get_pitd->encrypt_packet_data+A_INTERNAL_HEADER+B_OPENVPN_PKT_SIZE+B_OPENVPN_KEYID_OPCODE,
								get_pitd->encrypt_packet_data_len-A_INTERNAL_HEADER-B_OPENVPN_PKT_SIZE-B_OPENVPN_KEYID_OPCODE,
								(char *)get_pitd->normal_packet_data+A_INTERNAL_HEADER+B_OPENVPN_PKT_SIZE+B_OPENVPN_KEYID_OPCODE,
								keyid,
								epd->idx
								);

						if(data_ret < 0){
							MM("## ERR: %s %s[:%d] %s %d ##\n",__FILE__,__func__,__LINE__,epd->name,data_ret);

							get_pitd->NPT_send_ok = 0;
							get_pitd->NPT_packet_status = 0;
							get_pitd->TPT_send_ok = SEND_OK;
							get_pitd->TPT_packet_status = PACKET_DROP;
							get_pitd->ping_send = 0;

						}else{
							memcpy(get_pitd->normal_packet_data,
									get_pitd->encrypt_packet_data,
									A_INTERNAL_HEADER+B_OPENVPN_PKT_SIZE+B_OPENVPN_KEYID_OPCODE);

							get_pitd->normal_packet_data_len = data_ret + A_INTERNAL_HEADER+B_OPENVPN_PKT_SIZE+B_OPENVPN_KEYID_OPCODE;
							if((get_pitd->normal_packet_data_len - A_INTERNAL_HEADER - B_OPENVPN_PDATA_HEADER) == 16){
								if(memcmp(get_pitd->normal_packet_data+A_INTERNAL_HEADER+B_OPENVPN_PDATA_HEADER,ping_data_cmp,16) == 0){
									pthread_mutex_lock(&tmp_epd->pc->ping_check_mutex);
									tmp_epd->pc->ping_check = true;
									pthread_mutex_unlock(&tmp_epd->pc->ping_check_mutex);
#if 0
									if(tmp_epd->ss->keyid != keyid && opt->mode == SERVER){
										if(tmp_epd->ss->renego_keyid == keyid){
											pthread_mutex_lock(&tmp_epd->ss->ping_keyid_change_mutex);
											tmp_epd->ss->ping_keyid_change = true;
											pthread_mutex_unlock(&tmp_epd->ss->ping_keyid_change_mutex);
										}
									}
#endif
									get_pitd->NPT_send_ok = 0;
									get_pitd->NPT_packet_status = 0;
									get_pitd->TPT_send_ok = SEND_OK;
									get_pitd->TPT_packet_status = PACKET_DROP;
									get_pitd->ping_send = 0;


									packet_now_ping = true;
								}else{
									packet_now_ping = false;
								}
							}else{
								packet_now_ping = false;
							}

							if(packet_now_ping == false){
								out_in_ret = tunfd_route_tap_out_in(epd,get_pitd,&ih);
								if(out_in_ret < 0){
									get_pitd->NPT_send_ok = 0;
									get_pitd->NPT_packet_status = 0;
									get_pitd->TPT_send_ok = SEND_OK;
									get_pitd->TPT_packet_status = PACKET_DROP;
									get_pitd->ping_send = 0;
									//MM("## ERR: %s %s[:%d] %s %d ##\n",__FILE__,__func__,__LINE__,epd->name,ret);
								}
							}else{
							}
							TPT_sync_handle(epd,ntohl(ih.packet_idx));
						}
					}
					else{
						get_pitd->NPT_send_ok = 0;
						get_pitd->NPT_packet_status = 0;
						get_pitd->TPT_send_ok = SEND_OK;
						get_pitd->TPT_packet_status = PACKET_DROP;
						get_pitd->ping_send = 0;
						TPT_sync_handle(epd,ntohl(ih.packet_idx));
#if 0

						in_out_ret = tunfd_route_tap_out_in(epd,get_pitd,&ih);
						if(in_out_ret < 0){
							get_pitd->NPT_send_ok = 0;
							get_pitd->NPT_packet_status = 0;
							get_pitd->TPT_send_ok = SEND_OK;
							get_pitd->TPT_packet_status = PACKET_DROP;
							get_pitd->ping_send = 0;
							//MM("## ERR: %s %s[:%d] %s %d ##\n",__FILE__,__func__,__LINE__,epd->name,ret);
						}else{
						}
							TPT_sync_handle(epd,ntohl(ih.packet_idx));
#endif
					}
				}
			}
		}
		ret = recv_len;
	}
	return ret;
}

int pipe_SEND_handle(struct epoll_ptr_data *epd,char *write_buff,int write_len)
{
	int ret=0;
	int getfd=0;
	if(epd->thd_mode == THREAD_PIPE_IN_OUT){
		getfd = epd->tp_fdd->pipe_wfd;
		pthread_mutex_lock(&epd->tp_fdd->pipe_w_mutex);
		ret = pipe_send(getfd,write_buff,write_len);
		pthread_mutex_unlock(&epd->tp_fdd->pipe_w_mutex);
	}else if(epd->thd_mode == THREAD_PIPE_OUT_IN ){
		getfd = epd->np_fdd->pipe_wfd;
		pthread_mutex_lock(&epd->np_fdd->pipe_w_mutex);
		ret = pipe_send(getfd,write_buff,write_len);
		pthread_mutex_unlock(&epd->np_fdd->pipe_w_mutex);
	}

	if(ret < 0){
		MM("## ERR: %s %s[:%d] %s FD: %d  RET: %d ##\n",__FILE__,__func__,__LINE__,epd->name,getfd,ret);
	}

	return ret;
}


extern uint8_t ping_data;

int ping_SEND_handle(struct epoll_ptr_data *epd)
{
	int ret = 0;
	struct main_data *md = NULL;
	md = (struct main_data *)epd->gl_var;

	struct options *opt = NULL;
	opt = md->opt;
	struct packet_idx_tree_data *pitd=NULL;
	struct internal_header *hih=NULL;
	uint32_t packet_idx = 0;

	char * rb_i_ret = NULL;
	struct epoll_ptr_data *pipe_epd=NULL;
	int ret_in_out=0;
	int tun_type;
	tun_type = dev_type_enum (opt->dev, opt->dev_type);


#ifdef MEMPOLL_ENABLE
	struct mempool_data * mpd = mempool_get(md->pitd_mp);
	if(mpd == NULL){
		MM("## ERR: %s %d ##\n",__func__,__LINE__);
		//exit(0);
	}else{

		pitd = (struct packet_idx_tree_data *)mpd->data;
		memset(pitd,0x00,sizeof(struct packet_idx_tree_data));
		pitd->mempool_idx = mpd->key;
#else
		pitd = malloc(sizeof(struct packet_idx_tree_data));
		if(pitd == NULL){
			printf("## %s %d ##\n",__func__,__LINE__);
			exit(0);
		}
		memset(pitd,0x00,sizeof(struct packet_idx_tree_data));
#endif

		pthread_mutex_init(&pitd->pitd_mutex,NULL);
		hih = (struct internal_header *)pitd->normal_packet_data;
		hih->size        = htons(PING_DATA_SIZE + A_INTERNAL_HEADER);
		hih->fd          = htons(epd->n_fdd->net_rfd);
		hih->ping_send	  = htons(1);
		hih->packet_type = htonl(TUN_PACKET);

		pitd->normal_packet_data_len   = PING_DATA_SIZE+A_INTERNAL_HEADER+B_OPENVPN_PDATA_HEADER;
		memcpy(pitd->normal_packet_data+A_INTERNAL_HEADER+B_OPENVPN_PDATA_HEADER,(char *)&ping_data,PING_DATA_SIZE);

		if(tun_type == DEV_TYPE_TUN){
			ret_in_out = tunfd_route_tun_in_out(epd,pitd,hih);
		}else if(tun_type == DEV_TYPE_TAP){
			ret_in_out = tunfd_route_tap_in_out(epd,pitd,hih);
		}
		if(ret_in_out > 0){

			struct timeval tv;
			gettimeofday(&tv,NULL);
			pitd->recv_mil = ((tv.tv_sec*1000) + (tv.tv_usec/1000));

#ifdef MEMPOLL_ENABLE
			mpd->pkt_type = DATA_PKT;
			mpd->recv_mil = pitd->recv_mil;
#endif
			pthread_mutex_lock(&epd->all_packet_cnt_mutex);
			epd->all_packet_cnt++;
			pthread_mutex_unlock(&epd->all_packet_cnt_mutex);


			pthread_mutex_lock(&md->TPT_idx_mutex);
			packet_idx      = (md->TPT_idx);
			hih->packet_idx = htonl(packet_idx);

			if(md->TPT_idx == 0){
				md->TPT_idx = 1;
			}else{
				md->TPT_idx++;
			}

			pthread_mutex_unlock(&md->TPT_idx_mutex);
			pitd->key					= packet_idx;
			pitd->src_fd				= epd->n_fdd->net_rfd;
			pitd->packet_type			= TUN_PACKET;
			pitd->ping_send			= htons(1);
			pitd->TPT_send_ok			= SEND_OK;
			pitd->TPT_packet_status	= PACKET_SEND;

			pthread_mutex_lock(&md->TPT_tree_mutex);
			rb_i_ret = rb_insert(md->TPT_idx_tree,pitd);
			if(rb_i_ret == NULL){
				printf("## ERR; exit  %s %d #######################\n",__func__,__LINE__);
				exit(0);
			}
			pthread_mutex_unlock(&md->TPT_tree_mutex);

			pthread_mutex_lock(&md->work_in_out_mutex);
			if(md->in_out_idx == opt->core){
				md->in_out_idx = 0;
			}
			pipe_epd = md->work_in_out_epd[md->in_out_idx];
			md->in_out_idx++;
			pthread_mutex_unlock(&md->work_in_out_mutex);

			ret = pipe_SEND_handle(pipe_epd,(char *)hih,A_INTERNAL_HEADER);
			if(ret < 0){
				MM("## ERR: %s %s[:%d] %s RET: %d ##\n",__FILE__,__func__,__LINE__,epd->name,ret);
			}
		}else{
			dz_pthread_mutex_destroy(&pitd->pitd_mutex);
#ifdef MEMPOLL_ENABLE
			mempool_memset(md->pitd_mp,pitd->mempool_idx);
#else
			free(pitd);
#endif
		}

	}
	return ret;
}


int ALL_SEND_handle(struct epoll_ptr_data *epd,int fd,char *data,int len)
{
	int ret = 0;
	struct main_data *md = NULL;
	md = (struct main_data *)epd->gl_var;
	struct options *opt = NULL;
	opt = md->opt;
	struct packet_idx_tree_data *pitd=NULL;
	struct internal_header *hih=NULL;
	uint32_t packet_idx = 0;
	int ret_in_out=0;
	int tun_type;
	char * rb_i_ret = NULL;
	tun_type = dev_type_enum (opt->dev, opt->dev_type);


#ifdef MEMPOLL_ENABLE
	struct mempool_data * mpd = mempool_get(md->pitd_mp);
	if(mpd == NULL){
		MM("## ERR: %s %d ##\n",__func__,__LINE__);
		//exit(0);
	}else{

		pitd = (struct packet_idx_tree_data *)mpd->data;
		memset(pitd,0x00,sizeof(struct packet_idx_tree_data));
		pitd->mempool_idx = mpd->key;
#else
		pitd = malloc(sizeof(struct packet_idx_tree_data ));
		if(pitd == NULL){
			printf("## %s %d ##\n",__func__,__LINE__);
			exit(0);
		}
		memset(pitd,0x00,sizeof(struct packet_idx_tree_data));
#endif

		pthread_mutex_init(&pitd->pitd_mutex,NULL);
		hih = (struct internal_header *)pitd->normal_packet_data;
		hih->size       = htons(len + A_INTERNAL_HEADER + B_OPENVPN_PDATA_HEADER);
		hih->fd         = htons(fd);
		hih->ping_send	= htons(0);
		hih->packet_type = htonl(TUN_PACKET);

		pitd->normal_packet_data_len    = len+A_INTERNAL_HEADER+B_OPENVPN_PDATA_HEADER;
		memcpy(pitd->normal_packet_data+A_INTERNAL_HEADER+B_OPENVPN_PDATA_HEADER,data,len);

		if(tun_type == DEV_TYPE_TUN){
			ret_in_out = tunfd_route_tun_in_out(epd,pitd,hih);
		}else if(tun_type == DEV_TYPE_TAP){
			ret_in_out = tunfd_route_tap_in_out(epd,pitd,hih);
		}
		if(ret_in_out > 0){

			struct timeval tv;
			gettimeofday(&tv,NULL);
			pitd->recv_mil = ((tv.tv_sec*1000) + (tv.tv_usec/1000));

#ifdef MEMPOLL_ENABLE
			mpd->pkt_type = DATA_PKT;
			mpd->recv_mil = pitd->recv_mil;
#endif
			pthread_mutex_lock(&epd->all_packet_cnt_mutex);
			epd->all_packet_cnt++;
			pthread_mutex_unlock(&epd->all_packet_cnt_mutex);

			pthread_mutex_lock(&md->TPT_idx_mutex);
			packet_idx      = (md->TPT_idx);
			hih->packet_idx  = htonl(packet_idx);
			if(md->TPT_idx == 0){
				md->TPT_idx = 1;
			}else{
				md->TPT_idx++;
			}
			pthread_mutex_unlock(&md->TPT_idx_mutex);

			pitd->key 							= packet_idx;
			pitd->src_fd            		= fd;
			pitd->packet_type					= TUN_PACKET;
			pitd->ping_send					= htons(0);
			pitd->TPT_send_ok					= SEND_OK;
			pitd->TPT_packet_status			= PACKET_SEND;

			pthread_mutex_lock(&md->TPT_tree_mutex);
			rb_i_ret = rb_insert(md->TPT_idx_tree,pitd);
			if(rb_i_ret == NULL ){
				printf("## ERR; exit  %s %d #######################\n",__func__,__LINE__);
				exit(0);
			}
			pthread_mutex_unlock(&md->TPT_tree_mutex);

			struct epoll_ptr_data *pipe_epd=NULL;
			pthread_mutex_lock(&md->work_in_out_mutex);
			if(md->in_out_idx == opt->core){
				md->in_out_idx = 0;
			}
			pipe_epd = md->work_in_out_epd[md->in_out_idx];
			md->in_out_idx++;
			pthread_mutex_unlock(&md->work_in_out_mutex);

			ret = pipe_SEND_handle(pipe_epd,(char *)hih,A_INTERNAL_HEADER);
			if(ret < 0){
				MM("## ERR: %s %s[:%d] %s RET: %d ##\n",__FILE__,__func__,__LINE__,epd->name,ret);
			}

		}else{
			dz_pthread_mutex_destroy(&pitd->pitd_mutex);
#ifdef MEMPOLL_ENABLE
			mempool_memset(md->pitd_mp,pitd->mempool_idx);
#else
			free(pitd);
#endif
		}

	}
	return ret;
}
