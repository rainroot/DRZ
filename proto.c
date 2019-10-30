#include <rain_common.h>

#if 1
char ping_data[] = {
  0x2a, 0x18, 0x7b, 0xf3, 0x64, 0x1e, 0xb4, 0xcb,
  0x07, 0xed, 0x2d, 0x0a, 0x98, 0x1f, 0xc7, 0x48
};
#endif

int get_size(char *x){
        return (((0xff & x[0])<< 8) | (0xff & x[1]));
}

int get_opcode(char *x){
        return (x[0] >> P_OPCODE_SHIFT);
}

int get_keyid(char *x){
        return (x[0] & 0x7);
}

int get_pktid(char *x){
        return (x[9] & 0xff);
}

int get_idx(char *x,int y){
        if(y == 0){
                return (0xff&x[10]) << 24 | (0xff&x[11]) << 16 | (0xff&x[12])<<8 | (0xff&x[13]);
        }else{
                return (0xff&x[10+8+(4*y)]) << 24 | (0xff&x[11+8+(4*y)]) << 16 | (0xff&x[12+8+(4*y)])<<8 | (0xff&x[13+8+(4*y)]);
        }
}

int get_recv_local_packet_id(char *x,int y){
        return  (0xff&x[10+(4*(y-1))]) << 24 | (0xff&x[11+(4*(y-1))]) << 16 | (0xf &x[12+(4*(y-1))])<<8 | (0xff&x[13+(4*(y-1))]);
}

int loop_process(struct epoll_ptr_data *epd){
	struct main_data *md=NULL;
	md = (struct main_data *)epd->gl_var;
	bool loop_en = true;

	int memidx = 0;
	int ssl_send_idx = 0;
	uint8_t op_key;
	uint8_t key_idx;

	int ssl_ret = 0;	
	int tout_len = 0;
	int ret = 0;

#if 1
	char ret_out[4096]={0,};
	char out[4096]={0,};
#endif

#if 0
	char *ret_out = malloc(4096);
	memset(ret_out,0x00,4096);

	char *out = malloc(4096);
	memset(out,0x00,4096);
#endif
	int write_ret=0;


	while(loop_en == true){
		loop_en = false;
		ssl_ret = 0;

		ssl_ret = ssl_handle(epd,NULL,0,ret_out);
		if(ssl_ret < 0){
			MM("## ERR: %s %d ##\n",__func__,__LINE__);
			//ret = -1;
		}else if(ssl_ret > 0){
			loop_en = true;	
			memidx = 2;
			op_key = (epd->ss->renego_keyid | (P_CONTROL_V1 << P_OPCODE_SHIFT));
			memcpy(out+memidx,&op_key,1);
			memidx += 1;

			memcpy(out+memidx,md->session_id,SID_SIZE);
			memidx += SID_SIZE;

			key_idx = 1;
			memcpy(out+memidx,&key_idx,1);
			memidx += 1;

			memidx += 4;

			memcpy(out+memidx,epd->ss->remote_session_id,SID_SIZE);
			memidx += SID_SIZE;

			pthread_mutex_lock(&epd->pii->ssl_send_idx_mutex);
			epd->pii->ssl_send_idx++;
			ssl_send_idx = htonl(epd->pii->ssl_send_idx);
			pthread_mutex_unlock(&epd->pii->ssl_send_idx_mutex);

			memcpy(out+memidx,&ssl_send_idx,4);
			memidx += 4;

			memcpy(out+memidx,ret_out,ssl_ret);
			memidx += ssl_ret;

			tout_len = memidx;
			memidx -= 2;

			memidx = htons(memidx);
			memcpy(out,&memidx,2);

			if(epd->n_fdd != NULL){
				pthread_mutex_lock(&epd->n_fdd->net_w_mutex);
#if 0
					printf("## S ## %s %d ##\n",__func__,__LINE__);
					dump_print_hex(out,tout_len);
					printf("## E ## %s %d ##\n",__func__,__LINE__);
#endif
				write_ret = tcp_send(epd->n_fdd->net_wfd,out,tout_len);
				pthread_mutex_unlock(&epd->n_fdd->net_w_mutex);
			}else{
				MM("## ERR: %s %d ##\n",__func__,__LINE__);
				printf("## ERR: %s %d ##\n",__func__,__LINE__);
				write_ret = -1;
			}
			if(write_ret < 0){
				printf("## ERR: %s %d ##\n",__func__,__LINE__);
				MM("## ERR: %s %d ##\n",__func__,__LINE__);
				ret = -1;
				break;
			}else{
				ret = 0;
			}
			memset(out,0x00,tout_len);
		}
	}
#if 0
	free(ret_out);
	free(out);
#endif
	return ret;
}



int process(struct epoll_ptr_data *epd,char *data,int len,char *out,int *out_len)
{
	struct main_data *md=NULL;
	md = (struct main_data *)epd->gl_var;

	int opcode=0;
	int keyid =0;
	int pktid = 0;
	int memidx = 0;
	int ssl_send_idx = 0;
	int ssl_recv_idx = 0;
	int hdr_len = 0;
	uint8_t op_key;
	uint8_t key_idx;

	int ssl_ret = 0;	
	int tout_len = 0;
	int ret = 0;
#if 0
	char *ret_out = malloc(4096);
	memset(ret_out,0x00,4096);

	char *tmp_buff = malloc(4096);
	memset(tmp_buff,0x00,4096);
#endif
#if 1
	char ret_out[4096]={0,};
	char tmp_buff[4096]={0,};
#endif

	int write_ret=0;

	int t_renego_keyid=0;
	if((data != NULL) && (len != 0)){
		opcode = get_opcode(data);
	}

	if(epd->ss->renego_again == true){
		printf("############ %s %d #############################\n",__func__,__LINE__);
		epd->ss->renego_again = false;
		t_renego_keyid = epd->ss->renego_keyid;
		if(t_renego_keyid == 7){
			t_renego_keyid=1;
		}else{
			t_renego_keyid++;
		}

		memidx = 2;
		op_key = (t_renego_keyid | (P_CONTROL_SOFT_RESET_V1 << P_OPCODE_SHIFT));
		memcpy(tmp_buff+memidx,&op_key,1);
		memidx += 1;

		memcpy(tmp_buff+memidx,md->session_id,SID_SIZE);
		memidx += SID_SIZE;

		key_idx = 0;
		memcpy(tmp_buff+memidx,&key_idx,1);
		memidx += 1;

		memidx += 4;

		tout_len = memidx;
		memidx -= 2;
		memidx = htons(memidx);
		memcpy(tmp_buff,&memidx,2);

		if(epd->n_fdd != NULL){
			pthread_mutex_lock(&epd->n_fdd->net_w_mutex);
#if 0
					printf("## S ## %s %d ##\n",__func__,__LINE__);
					dump_print_hex(tmp_buff,tout_len);
					printf("## E ## %s %d ##\n",__func__,__LINE__);
#endif
			write_ret = tcp_send(epd->n_fdd->net_wfd,tmp_buff,tout_len);
			pthread_mutex_unlock(&epd->n_fdd->net_w_mutex);
		}else{
			MM("## ERR: %s %d ##\n",__func__,__LINE__);
			write_ret = -1;
		}
		if(write_ret < 0){
			MM("## ERR: %s %d ##\n",__func__,__LINE__);
			ret = -1;
		}else{
			ret = 0;
		}

	}else if(opcode == P_CONTROL_SOFT_RESET_V1){

		printf("############ %s %d #############################\n",__func__,__LINE__);
		int t_keyid = 0;
		keyid = get_keyid(data);
		pktid = get_pktid(data);
		if(keyid == 0){
			t_keyid = 7;
		}else if(keyid == 1){
			t_keyid = 7;
		}else{
			t_keyid = keyid - 1;
		}

		if(epd->ss->sk[t_keyid].state != S_NORMAL_OP && epd->ss->sk[t_keyid].state != 0 ){
			printf("############ %s %d !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!! #############################\n",__func__,__LINE__);
			ret = 0;
		}else{

			pthread_mutex_lock(&epd->keynego_mutex);
			epd->keynego = true;
			pthread_mutex_unlock(&epd->keynego_mutex);

			key_state_ssl_remove(epd,false);

			pthread_mutex_lock(&epd->pii->ssl_send_idx_mutex);
			epd->pii->ssl_recv_idx = get_idx(data,pktid);
			pthread_mutex_unlock(&epd->pii->ssl_send_idx_mutex);

			epd->ss->renego_keyid = keyid;

			epd->ss->sk[epd->ss->renego_keyid].state = S_INITIAL;
			epd->ss->sk[epd->ss->renego_keyid].state = S_PRE_START;
			epd->ss->sk[epd->ss->renego_keyid].state = S_START;

#if 1 //rainroot 20170105
			if(epd->ss != NULL && epd->ss->sk[epd->ss->renego_keyid].ks_ssl == NULL){
				epd->ss->sk[epd->ss->renego_keyid].ks_ssl = malloc(sizeof(struct key_state_ssl));
				memset(epd->ss->sk[epd->ss->renego_keyid].ks_ssl,0x00,sizeof(struct key_state_ssl));
			}
			epd->ss->sk[epd->ss->renego_keyid].authenticated = false;

			if(epd->ss != NULL && epd->ss->sk[epd->ss->renego_keyid].prb == NULL){
#if 0
				printf("# epd : %08x  epd->ss %08x  epd->ss->sk[epd->ss->renego_keyid].prb %08x , renego_keyid  %d keyid %d \n",
						epd,
						epd->ss,
						epd->ss->sk[epd->ss->renego_keyid].prb,
						epd->ss->renego_keyid,
						keyid
						);
#endif
				//epd->ss->sk[epd->ss->renego_keyid].prb = calloc(1,TLS_CHANNEL_BUF_SIZE);
				epd->ss->sk[epd->ss->renego_keyid].prb = malloc(TLS_CHANNEL_BUF_SIZE);
				memset(epd->ss->sk[epd->ss->renego_keyid].prb,0x00,TLS_CHANNEL_BUF_SIZE);
			}
			epd->ss->sk[epd->ss->renego_keyid].prb_len = 0;

			if(epd->ss->sk[epd->ss->renego_keyid].pwb == NULL){
				//epd->ss->sk[epd->ss->renego_keyid].pwb = calloc(1,TLS_CHANNEL_BUF_SIZE);
				epd->ss->sk[epd->ss->renego_keyid].pwb = malloc(TLS_CHANNEL_BUF_SIZE);
				memset(epd->ss->sk[epd->ss->renego_keyid].pwb,0x00,TLS_CHANNEL_BUF_SIZE);
			}
			epd->ss->sk[epd->ss->renego_keyid].pwb_len = 0;
#endif
			pthread_mutex_lock(&epd->pii->ssl_send_idx_mutex);
			epd->pii->ssl_send_idx=0;
			pthread_mutex_unlock(&epd->pii->ssl_send_idx_mutex);

			if(md->opt->mode == SERVER){
				key_state_ssl_init(epd,epd->ss->sk[epd->ss->renego_keyid].ks_ssl,md->ctx,SERVER);
			}else{
		printf("############ %s %d #############################\n",__func__,__LINE__);
				key_state_ssl_init(epd,epd->ss->sk[epd->ss->renego_keyid].ks_ssl,md->ctx,CLIENT);

				memidx = 2;
				op_key = (epd->ss->renego_keyid | (P_CONTROL_SOFT_RESET_V1 << P_OPCODE_SHIFT));
				memcpy(tmp_buff+memidx,&op_key,1);
				memidx += 1;

				memcpy(tmp_buff+memidx,md->session_id,SID_SIZE);
				memidx += SID_SIZE;

				key_idx = 0;
				memcpy(tmp_buff+memidx,&key_idx,1);
				memidx += 1;

				memidx += 4;

				tout_len = memidx;
				memidx -= 2;
				memidx = htons(memidx);
				memcpy(tmp_buff,&memidx,2);

				if(epd->n_fdd != NULL){
					pthread_mutex_lock(&epd->n_fdd->net_w_mutex);
#if 0
					printf("## S ## %s %d ##\n",__func__,__LINE__);
					dump_print_hex(tmp_buff,tout_len);
					printf("## E ## %s %d ##\n",__func__,__LINE__);
#endif
					write_ret = tcp_send(epd->n_fdd->net_wfd,tmp_buff,tout_len);
					pthread_mutex_unlock(&epd->n_fdd->net_w_mutex);
				}else{
					MM("## ERR: %s %d ##\n",__func__,__LINE__);
					write_ret = -1;
				}
				if(write_ret < 0){
					MM("## ERR: %s %d ##\n",__func__,__LINE__);
					ret = -1;
				}else{
					ret = 0;
				}
			}
#if 1 //rainroot 20170330

			if(md->opt->mode == SERVER){

				ssl_ret = ssl_handle(epd,NULL,0,ret_out);
				if(ssl_ret < 0){
					MM("## ERR: %s %d ##\n",__func__,__LINE__);
					//ret = -1;
				}else if(ssl_ret > 0){

					memidx = 2;
					op_key = (epd->ss->renego_keyid | (P_CONTROL_V1 << P_OPCODE_SHIFT));
					memcpy(out+memidx,&op_key,1);
					memidx += 1;

					memcpy(out+memidx,md->session_id,SID_SIZE);
					memidx += SID_SIZE;

					key_idx = 1;
					memcpy(out+memidx,&key_idx,1);
					memidx += 1;

					pthread_mutex_lock(&epd->pii->ssl_send_idx_mutex);
					ssl_recv_idx = htonl(epd->pii->ssl_recv_idx);
					pthread_mutex_unlock(&epd->pii->ssl_send_idx_mutex);
					memcpy(out+memidx,&ssl_recv_idx,4);
					memidx += 4;

					memcpy(out+memidx,epd->ss->remote_session_id,SID_SIZE);
					memidx += SID_SIZE;

					pthread_mutex_lock(&epd->pii->ssl_send_idx_mutex);
					ssl_send_idx = htonl(epd->pii->ssl_send_idx);
					pthread_mutex_unlock(&epd->pii->ssl_send_idx_mutex);
					memcpy(out+memidx,&ssl_send_idx,4);
					memidx += 4;

					memcpy(out+memidx,ret_out,ssl_ret);
					memidx += ssl_ret;

					*out_len = memidx;
					tout_len = memidx;
					memidx -= 2;

					memidx = htons(memidx);
					memcpy(out,&memidx,2);

					if(epd->n_fdd != NULL){
						pthread_mutex_lock(&epd->n_fdd->net_w_mutex);
#if 0
					printf("## S ## %s %d ##\n",__func__,__LINE__);
					dump_print_hex(out,tout_len);
					printf("## E ## %s %d ##\n",__func__,__LINE__);
#endif
						write_ret = tcp_send(epd->n_fdd->net_wfd,out,tout_len);
						pthread_mutex_unlock(&epd->n_fdd->net_w_mutex);
					}else{
						MM("## ERR: %s %d ##\n",__func__,__LINE__);
						write_ret = -1;
					}
					if(write_ret < 0){
						MM("## ERR: %s %d ##\n",__func__,__LINE__);
						ret = -1;
					}else{
						ret = 0;
					}
					memset(out,0x00,tout_len);
				}else{

					if(ret >= 0){
						memidx = 2;
						op_key = (epd->ss->renego_keyid | (P_ACK_V1 << P_OPCODE_SHIFT));
						memcpy(out+memidx,&op_key,1);
						memidx += 1;

						memcpy(out+memidx,md->session_id,SID_SIZE);
						memidx += SID_SIZE;

						key_idx = 1;
						memcpy(out+memidx,&key_idx,1);
						memidx += 1;

						pthread_mutex_lock(&epd->pii->ssl_send_idx_mutex);
						ssl_recv_idx = htonl(epd->pii->ssl_recv_idx);
						pthread_mutex_unlock(&epd->pii->ssl_send_idx_mutex);
						memcpy(out+memidx,&ssl_recv_idx,4);
						memidx += 4;

						memcpy(out+memidx,epd->ss->remote_session_id,SID_SIZE);
						memidx += SID_SIZE;

						*out_len = memidx;
						tout_len = memidx;
						memidx -= 2;

						memidx = htons(memidx);
						memcpy(out,&memidx,2);
						if(epd->n_fdd != NULL){
							pthread_mutex_lock(&epd->n_fdd->net_w_mutex);
#if 0
					printf("## S ## %s %d ##\n",__func__,__LINE__);
					dump_print_hex(out,tout_len);
					printf("## E ## %s %d ##\n",__func__,__LINE__);
#endif
							write_ret = tcp_send(epd->n_fdd->net_wfd,out,tout_len);
							pthread_mutex_unlock(&epd->n_fdd->net_w_mutex);
						}else{
							MM("## ERR: %s %d ##\n",__func__,__LINE__);
							write_ret = -1;
						}
						if(write_ret < 0){
							MM("## ERR: %s %d ##\n",__func__,__LINE__);
							ret = -1;
						}else{
							ret = 0;
						}
						memset(out,0x00,tout_len);
					}
				}

			}
#endif
		}
	}else if(opcode != 0){
		keyid = get_keyid(data);
		pktid = get_pktid(data);

		pthread_mutex_lock(&epd->pii->ssl_send_idx_mutex);
		epd->pii->ssl_recv_idx = get_idx(data,pktid);
		pthread_mutex_unlock(&epd->pii->ssl_send_idx_mutex);

		if(opcode == P_CONTROL_HARD_RESET_CLIENT_V2 || opcode == P_CONTROL_HARD_RESET_SERVER_V2){
		printf("############ %s %d #############################\n",__func__,__LINE__);
			memcpy(epd->ss->remote_session_id,data+1,SID_SIZE);

#if 1
			if(epd->ss->sk[epd->ss->renego_keyid].ks_ssl == NULL){
				epd->ss->sk[epd->ss->renego_keyid].ks_ssl = malloc(sizeof(struct key_state_ssl));
				memset(epd->ss->sk[epd->ss->renego_keyid].ks_ssl,0x00,sizeof(struct key_state_ssl));
			}
			epd->ss->sk[epd->ss->renego_keyid].authenticated = false;

			if(epd->ss->sk[epd->ss->renego_keyid].prb == NULL){
				//epd->ss->sk[epd->ss->renego_keyid].prb = calloc(1,TLS_CHANNEL_BUF_SIZE);
				epd->ss->sk[epd->ss->renego_keyid].prb = malloc(TLS_CHANNEL_BUF_SIZE);
				memset(epd->ss->sk[epd->ss->renego_keyid].prb,0x00,TLS_CHANNEL_BUF_SIZE);
			}
			epd->ss->sk[epd->ss->renego_keyid].prb_len = 0;

			if(epd->ss->sk[epd->ss->renego_keyid].pwb == NULL){
				epd->ss->sk[epd->ss->renego_keyid].pwb = malloc(TLS_CHANNEL_BUF_SIZE);
				//epd->ss->sk[epd->ss->renego_keyid].pwb = calloc(1,TLS_CHANNEL_BUF_SIZE);
				memset(epd->ss->sk[epd->ss->renego_keyid].pwb,0x00,TLS_CHANNEL_BUF_SIZE);
			}
			epd->ss->sk[epd->ss->renego_keyid].pwb_len = 0;
#endif
			epd->ss->sk[epd->ss->renego_keyid].state = S_INITIAL;

			if(opcode == P_CONTROL_HARD_RESET_CLIENT_V2){
		printf("############ %s %d #############################\n",__func__,__LINE__);
				memidx = 2;
				op_key = (epd->ss->renego_keyid | (P_CONTROL_HARD_RESET_SERVER_V2 << P_OPCODE_SHIFT));
				memcpy(out+memidx,&op_key,1);
				memidx += 1;

				memcpy(out+memidx,md->session_id,SID_SIZE);
				memidx += SID_SIZE;

				key_idx = 1;
				memcpy(out+memidx,&key_idx,1);
				memidx += 1;

				memidx += 4;

				memcpy(out+memidx,epd->ss->remote_session_id,SID_SIZE);
				memidx += SID_SIZE;

				pthread_mutex_lock(&epd->pii->ssl_send_idx_mutex);
				ssl_send_idx = htonl(epd->pii->ssl_send_idx);
				pthread_mutex_unlock(&epd->pii->ssl_send_idx_mutex);

				memcpy(out+memidx,&ssl_send_idx,4);
				memidx += 4;

				*out_len = memidx;
				tout_len = memidx;
				memidx -= 2;
				memidx = htons(memidx);
				memcpy(out,&memidx,2);

				if(epd->n_fdd != NULL){
					pthread_mutex_lock(&epd->n_fdd->net_w_mutex);
#if 0
					printf("## S ## %s %d ##\n",__func__,__LINE__);
					dump_print_hex(out,tout_len);
					printf("## E ## %s %d ##\n",__func__,__LINE__);
#endif
					write_ret = tcp_send(epd->n_fdd->net_wfd,out,tout_len);
					pthread_mutex_unlock(&epd->n_fdd->net_w_mutex);
				}else{
					MM("## ERR: %s %d ##\n",__func__,__LINE__);
					write_ret = -1;
				}
				if(write_ret < 0){
					MM("## ERR: %s %d ##\n",__func__,__LINE__);
					ret = -1;
				}else{
					ret = 0;
				}
				memset(out,0x00,tout_len);

				epd->ss->sk[epd->ss->renego_keyid].state = S_PRE_START;
				epd->ss->sk[epd->ss->renego_keyid].state = S_START;

				key_state_ssl_init(epd,epd->ss->sk[epd->ss->renego_keyid].ks_ssl,md->ctx,SERVER);

			}else if(opcode == P_CONTROL_HARD_RESET_SERVER_V2){
		printf("############ %s %d #############################\n",__func__,__LINE__);

				epd->ss->sk[epd->ss->renego_keyid].state = S_PRE_START;
				epd->ss->sk[epd->ss->renego_keyid].state = S_START;

				key_state_ssl_init(epd,epd->ss->sk[epd->ss->renego_keyid].ks_ssl,md->ctx,CLIENT);


				if(pktid > 0){
					hdr_len = 10 + (pktid*4) + 8 + 4;
				}else{
					hdr_len = 10 + 4;
				}
#if 1 //nono
				ssl_ret = ssl_handle(epd,NULL,0,ret_out);
				if(ssl_ret < 0){
					MM("## ERR: %s %d ##\n",__func__,__LINE__);
					//ret = -1;
				}else if(ssl_ret > 0){
					memidx = 2;
					op_key = (epd->ss->renego_keyid | (P_CONTROL_V1 << P_OPCODE_SHIFT));
					memcpy(out+memidx,&op_key,1);
					memidx += 1;

					memcpy(out+memidx,md->session_id,SID_SIZE);
					memidx += SID_SIZE;

					key_idx = 1;
					memcpy(out+memidx,&key_idx,1);
					memidx += 1;

					memidx += 4;

					memcpy(out+memidx,epd->ss->remote_session_id,SID_SIZE);
					memidx += SID_SIZE;


					pthread_mutex_lock(&epd->pii->ssl_send_idx_mutex);
					epd->pii->ssl_send_idx++;
					ssl_send_idx = htonl(epd->pii->ssl_send_idx);
					pthread_mutex_unlock(&epd->pii->ssl_send_idx_mutex);

					memcpy(out+memidx,&ssl_send_idx,4);
					memidx += 4;

					memcpy(out+memidx,ret_out,ssl_ret);
					memidx += ssl_ret;

					*out_len = memidx;
					tout_len = memidx;
					memidx -= 2;

					memidx = htons(memidx);
					memcpy(out,&memidx,2);

					if(epd->n_fdd != NULL){
						pthread_mutex_lock(&epd->n_fdd->net_w_mutex);
#if 0
					printf("## S ## %s %d ##\n",__func__,__LINE__);
					dump_print_hex(out,tout_len);
					printf("## E ## %s %d ##\n",__func__,__LINE__);
#endif
						write_ret = tcp_send(epd->n_fdd->net_wfd,out,tout_len);
						pthread_mutex_unlock(&epd->n_fdd->net_w_mutex);
					}else{
						MM("## ERR: %s %d ##\n",__func__,__LINE__);
						write_ret = -1;
					}
					if(write_ret < 0){
						MM("## ERR: %s %d ##\n",__func__,__LINE__);
						ret = -1;
					}else{
						ret = 0;
					}
					memset(out,0x00,tout_len);

				}
#endif //nono
				memidx = 2;
				op_key = (epd->ss->renego_keyid | (P_ACK_V1 << P_OPCODE_SHIFT));
				memcpy(out+memidx,&op_key,1);
				memidx += 1;

				memcpy(out+memidx,md->session_id,SID_SIZE);
				memidx += SID_SIZE;

				key_idx = 1;
				memcpy(out+memidx,&key_idx,1);
				memidx += 1;

				pthread_mutex_lock(&epd->pii->ssl_send_idx_mutex);
				ssl_recv_idx = htonl(epd->pii->ssl_recv_idx);
				pthread_mutex_unlock(&epd->pii->ssl_send_idx_mutex);

				memcpy(out+memidx,&ssl_recv_idx,4);
				memidx += 4;

				memcpy(out+memidx,epd->ss->remote_session_id,SID_SIZE);
				memidx += SID_SIZE;

				*out_len = memidx;
				tout_len = memidx;
				memidx -= 2;

				memidx = htons(memidx);
				memcpy(out,&memidx,2);
				if(epd->n_fdd != NULL){
					pthread_mutex_lock(&epd->n_fdd->net_w_mutex);
#if 0
					printf("## S ## %s %d ##\n",__func__,__LINE__);
					dump_print_hex(out,tout_len);
					printf("## E ## %s %d ##\n",__func__,__LINE__);
#endif
					write_ret = tcp_send(epd->n_fdd->net_wfd,out,tout_len);
					pthread_mutex_unlock(&epd->n_fdd->net_w_mutex);
				}else{
					MM("## ERR: %s %d ##\n",__func__,__LINE__);
					write_ret = -1;
				}
				if(write_ret < 0){
					MM("## ERR: %s %d ##\n",__func__,__LINE__);
					ret = -1;
				}else{
					ret = 0;
				}
				memset(out,0x00,tout_len);

			}

		}else if(opcode == P_CONTROL_V1){

			keyid = get_keyid(data);
			pktid = get_pktid(data);
			if(pktid > 0){
				hdr_len = 10 + (pktid*4) + 8 + 4;
			}else{
				hdr_len = 10 + 4;
			}

			ssl_ret = ssl_handle(epd,data+hdr_len,len-hdr_len,ret_out);
			if(ssl_ret < 0){
				MM("## ERR: %s %d ##\n",__func__,__LINE__);
				ret = -1;
			}else if(ssl_ret > 0){

				memidx = 2;
				op_key = (epd->ss->renego_keyid | (P_CONTROL_V1 << P_OPCODE_SHIFT));
				memcpy(out+memidx,&op_key,1);
				memidx += 1;

				memcpy(out+memidx,md->session_id,SID_SIZE);
				memidx += SID_SIZE;

				key_idx = 1;
				memcpy(out+memidx,&key_idx,1);
				memidx += 1;

				memidx += 4;

				memcpy(out+memidx,epd->ss->remote_session_id,SID_SIZE);
				memidx += SID_SIZE;


				pthread_mutex_lock(&epd->pii->ssl_send_idx_mutex);
				epd->pii->ssl_send_idx++;
				ssl_send_idx = htonl(epd->pii->ssl_send_idx);
				pthread_mutex_unlock(&epd->pii->ssl_send_idx_mutex);

				memcpy(out+memidx,&ssl_send_idx,4);
				memidx += 4;


				memcpy(out+memidx,ret_out,ssl_ret);
				memidx += ssl_ret;

				*out_len = memidx;
				tout_len = memidx;
				memidx -= 2;

				memidx = htons(memidx);
				memcpy(out,&memidx,2);

				if(epd->n_fdd != NULL){
					pthread_mutex_lock(&epd->n_fdd->net_w_mutex);
#if 0
					printf("## S ## %s %d ##\n",__func__,__LINE__);
					dump_print_hex(out,tout_len);
					printf("## E ## %s %d ##\n",__func__,__LINE__);
#endif
					write_ret = tcp_send(epd->n_fdd->net_wfd,out,tout_len);
					pthread_mutex_unlock(&epd->n_fdd->net_w_mutex);
				}else{
					MM("## ERR: %s %d ##\n",__func__,__LINE__);
					write_ret = -1;
				}
				if(write_ret < 0){
					MM("## ERR: %s %d ##\n",__func__,__LINE__);
					ret = -1;
				}else{
					ret = 0;
				}
				memset(out,0x00,tout_len);

			}
			if(ret >= 0){
				memidx = 2;
				op_key = (epd->ss->renego_keyid | (P_ACK_V1 << P_OPCODE_SHIFT));
				memcpy(out+memidx,&op_key,1);
				memidx += 1;

				memcpy(out+memidx,md->session_id,SID_SIZE);
				memidx += SID_SIZE;

				key_idx = 1;
				memcpy(out+memidx,&key_idx,1);
				memidx += 1;

				pthread_mutex_lock(&epd->pii->ssl_send_idx_mutex);
				ssl_recv_idx = htonl(epd->pii->ssl_recv_idx);
				pthread_mutex_unlock(&epd->pii->ssl_send_idx_mutex);

				memcpy(out+memidx,&ssl_recv_idx,4);
				memidx += 4;

				memcpy(out+memidx,epd->ss->remote_session_id,SID_SIZE);
				memidx += SID_SIZE;

				*out_len = memidx;
				tout_len = memidx;
				memidx -= 2;

				memidx = htons(memidx);
				memcpy(out,&memidx,2);

				if(epd->n_fdd != NULL){
					pthread_mutex_lock(&epd->n_fdd->net_w_mutex);
#if 0
					printf("## S ## %s %d ##\n",__func__,__LINE__);
					dump_print_hex(out,tout_len);
					printf("## E ## %s %d ##\n",__func__,__LINE__);
#endif
					write_ret = tcp_send(epd->n_fdd->net_wfd,out,tout_len);
					pthread_mutex_unlock(&epd->n_fdd->net_w_mutex);
				}else{
					MM("## ERR: %s %d ##\n",__func__,__LINE__);
					write_ret = -1;
				}
				if(write_ret < 0){
					MM("## ERR: %s %d ##\n",__func__,__LINE__);
					ret = -1;
				}else{
					ret = 0;
				}
				memset(out,0x00,tout_len);
			}
			loop_process(epd);
		}else if(opcode == P_ACK_V1){
			loop_process(epd);
		}
	}else{
		if(epd->ss->sk[epd->ss->renego_keyid].state == S_INITIAL){
			memidx = 2;
			op_key = (epd->ss->renego_keyid | (P_CONTROL_HARD_RESET_CLIENT_V2 << P_OPCODE_SHIFT));
			memcpy(tmp_buff+memidx,&op_key,1);
			memidx += 1;

			memcpy(tmp_buff+memidx,md->session_id,SID_SIZE);
			memidx += SID_SIZE;

			key_idx = 0;
			memcpy(tmp_buff+memidx,&key_idx,1);
			memidx += 1;

			memidx += 4;

			tout_len = memidx;
			memidx -= 2;
			memidx = htons(memidx);
			memcpy(tmp_buff,&memidx,2);

			if(epd->n_fdd != NULL){
				pthread_mutex_lock(&epd->n_fdd->net_w_mutex);
#if 0
					printf("## S ## %s %d ##\n",__func__,__LINE__);
					dump_print_hex(tmp_buff,tout_len);
					printf("## E ## %s %d ##\n",__func__,__LINE__);
#endif
				write_ret = tcp_send(epd->n_fdd->net_wfd,tmp_buff,tout_len);
				pthread_mutex_unlock(&epd->n_fdd->net_w_mutex);
			}else{
				MM("## ERR: %s %d ##\n",__func__,__LINE__);
				write_ret = -1;
			}
			if(write_ret < 0){
				MM("## ERR: %s %d ##\n",__func__,__LINE__);
				ret = -1;
			}else{
				ret = 0;
			}
			epd->ss->sk[epd->ss->renego_keyid].state = S_PRE_START;
		}
#if 0	
		loop_process(epd);
#endif
#if 1
		if((ret >=0) && (data == NULL && len == 0 ) && (epd->ps->push_request == false) && (epd->ss->sk[epd->ss->keyid].authenticated == true)){
			loop_process(epd);
		}
#endif
	}
	//free(ret_out);
	//free(tmp_buff);
	return ret;
}
