#include <rain_common.h>

int tunfd_route_tun_out_in(struct epoll_ptr_data *epd,struct packet_idx_tree_data *get_pitd,struct internal_header *ih)
{
	int ret = -1;
	int all_send_ret = 0;
	struct main_data *md = NULL;
	struct options *opt  = NULL;
	struct iphdr *iph=NULL;
	struct user_data ud;
	struct user_data *pud=NULL;
	struct epoll_ptr_data *pipe_epd=NULL;
	//char *normal_packet_data = NULL;
	//int normal_packet_data_len = 0;
	uint32_t key = 0;

	md = (struct main_data *)epd->gl_var;
	opt = md->opt;

	key = ntohl(ih->packet_idx);
	if(get_pitd != NULL){
		iph = (struct iphdr *)(get_pitd->normal_packet_data + A_INTERNAL_HEADER + B_OPENVPN_PDATA_HEADER);
		if(md->opt->mode == SERVER){
			if(iph->version == 4){
#if 0
				if(md->opt->client_config_dir == NULL){
					if(iph->saddr != 0x0){

					}
				}
#endif

				if(iph->daddr != 0x0){
					unsigned int daddr = ntohl(iph->daddr);
					memcpy(&ud.key,&daddr,4);

					pthread_mutex_lock(&opt->user_tree_mutex);
					pud = (struct user_data *)rb_find(opt->user_tree,(void *)&ud);
					pthread_mutex_unlock(&opt->user_tree_mutex);

					if(pud == NULL){
						pipe_epd	= md->tun_epd;
						if(pipe_epd != NULL && pipe_epd->t_fdd != NULL){
							pthread_mutex_lock(&get_pitd->pitd_mutex);
							get_pitd->dst_fd 					= pipe_epd->t_fdd->tun_wfd;
							get_pitd->NPT_packet_status 	= 0;
							get_pitd->NPT_send_ok       	= 0;
							get_pitd->TPT_packet_status 	= PACKET_SEND;
							get_pitd->TPT_send_ok       	= SEND_OK;
							pthread_mutex_unlock(&get_pitd->pitd_mutex);
							ret = 1;
						}else{
							ret = -1;
						}
					}else{
						/* option --> client-to-client enable...  */
						int normal_packet_data_len = 0;
						char *normal_packet_data = NULL;

                  normal_packet_data_len = get_pitd->normal_packet_data_len-A_INTERNAL_HEADER-B_OPENVPN_PDATA_HEADER;
                  normal_packet_data = malloc(normal_packet_data_len);
                  memset(normal_packet_data,0x00,normal_packet_data_len);
                  memcpy(normal_packet_data,get_pitd->normal_packet_data+A_INTERNAL_HEADER+B_OPENVPN_PDATA_HEADER,normal_packet_data_len);						
						ALL_SEND_handle(epd,get_pitd->src_fd,normal_packet_data,normal_packet_data_len);
						free(normal_packet_data);
						ret = -1;
					}
				}else{
					ret = -1;
				}
			}else{
				ret = -1;
			}
		}else if(md->opt->mode == CLIENT){
			if(iph->version == 4){
				pipe_epd = md->tun_epd;
				if(pipe_epd != NULL && pipe_epd->t_fdd != NULL){
					pthread_mutex_lock(&get_pitd->pitd_mutex);
					get_pitd->dst_fd 					= pipe_epd->t_fdd->tun_wfd;
					get_pitd->NPT_packet_status 	= 0;
					get_pitd->NPT_send_ok       	= 0;
					get_pitd->TPT_packet_status 	= PACKET_SEND;
					get_pitd->TPT_send_ok       	= SEND_OK;
					pthread_mutex_unlock(&get_pitd->pitd_mutex);
					ret = 1;
				}else{
					ret = -1;
				}
			}else{
				ret = -1;
			}
		}else{
			ret = -1;
		}
	}else{
		ret = -1;
	}
	if(ret == -1){
		pthread_mutex_lock(&get_pitd->pitd_mutex);
		get_pitd->NPT_packet_status 	= 0;
		get_pitd->NPT_send_ok       	= 0;
		get_pitd->TPT_packet_status 	= PACKET_DROP;
		get_pitd->TPT_send_ok       	= SEND_OK;
		pthread_mutex_unlock(&get_pitd->pitd_mutex);
	}

	TPT_sync_handle(epd,key);
	return ret;
}


int tunfd_route_tun_in_out(struct epoll_ptr_data *epd,struct packet_idx_tree_data *get_pitd,struct internal_header *ih)
{
	int ret = -1;
	struct main_data *md = NULL;
	struct options *opt  = NULL;
	struct iphdr *iph=NULL;
	struct user_data ud;
	struct user_data *pud=NULL;
	struct epoll_ptr_data *pipe_epd=NULL;

	md = (struct main_data *)epd->gl_var;
	opt = md->opt;

	if(get_pitd != NULL){
		if(ntohs(ih->ping_send) == 1){
			if(opt->mode == SERVER){
				struct user_data ct_ud;
				struct user_data *ct_pud = NULL;
				ct_ud.key = ntohs(ih->fd);
				pthread_mutex_lock(&opt->ct_tree_mutex);
				ct_pud = rb_find(opt->ct_tree,(char *)&ct_ud);
				pthread_mutex_unlock(&opt->ct_tree_mutex);
				if(ct_pud != NULL){
					pipe_epd = ct_pud->epd;
					pthread_mutex_lock(&get_pitd->pitd_mutex);
					if(pipe_epd == NULL || pipe_epd->n_fdd == NULL || pipe_epd->ss == NULL || pipe_epd->pc == NULL || pipe_epd->pii == NULL || pipe_epd->ps == NULL){

						pthread_mutex_lock(&opt->ct_tree_mutex);
						if(ct_pud != NULL){
							rb_delete(opt->ct_tree,ct_pud,true,sizeof(struct user_data));
						}
						pthread_mutex_unlock(&opt->ct_tree_mutex);
						ret = -1;
					}else{

						if(pipe_epd->stop == 0){
							int net_wfd = pipe_epd->n_fdd->net_wfd;
							get_pitd->dst_fd 					= net_wfd;
							get_pitd->TPT_packet_status 	= 0;
							get_pitd->TPT_send_ok   		= 0;
							get_pitd->NPT_packet_status 	= PACKET_SEND;
							get_pitd->NPT_send_ok   		= SEND_OK;
							get_pitd->net_epd 				= pipe_epd;

							pthread_mutex_lock(&pipe_epd->pii->data_send_idx_mutex);
							pthread_mutex_lock(&md->TPT_idx_mutex);
							get_pitd->key = md->TPT_idx;
							if(md->TPT_idx == 0){
								md->TPT_idx = 1;
							}else{
							   md->TPT_idx++;
							}
							pthread_mutex_unlock(&md->TPT_idx_mutex);
							pipe_epd->pii->data_send_idx++;
							if(pipe_epd->pii->data_send_idx == 0){
								pipe_epd->pii->data_send_idx = 1;
							}
							get_pitd->data_send_idx = pipe_epd->pii->data_send_idx;
							pthread_mutex_unlock(&pipe_epd->pii->data_send_idx_mutex);
							ret = 1;
						}else{
							ret = -1;
						}
					}
					pthread_mutex_unlock(&get_pitd->pitd_mutex);
				}else{
					ret = -1;
				}
			}else if(opt->mode == CLIENT){
				pipe_epd = md->net_epd;

				pthread_mutex_lock(&get_pitd->pitd_mutex);
				if(pipe_epd == NULL || pipe_epd->n_fdd == NULL || pipe_epd->ss == NULL || pipe_epd->pc == NULL || pipe_epd->pii == NULL || pipe_epd->ps == NULL){
					ret = -1;
				}else{
					if(pipe_epd->stop == 0){
						int net_wfd = pipe_epd->n_fdd->net_wfd;
						get_pitd->dst_fd 					= net_wfd;
						get_pitd->TPT_packet_status 	= 0;
						get_pitd->TPT_send_ok   		= 0;
						get_pitd->NPT_packet_status 	= PACKET_SEND;
						get_pitd->NPT_send_ok   		= SEND_OK;
						get_pitd->net_epd 				= pipe_epd;

						pthread_mutex_lock(&pipe_epd->pii->data_send_idx_mutex);
						pthread_mutex_lock(&md->TPT_idx_mutex);
						get_pitd->key = md->TPT_idx;
						if(md->TPT_idx == 0){
							md->TPT_idx = 1;
						}else{
							md->TPT_idx++;
						}
						pthread_mutex_unlock(&md->TPT_idx_mutex);
						pipe_epd->pii->data_send_idx++;
						if(pipe_epd->pii->data_send_idx == 0){
							pipe_epd->pii->data_send_idx = 1;
						}
						get_pitd->data_send_idx = pipe_epd->pii->data_send_idx;
						pthread_mutex_unlock(&pipe_epd->pii->data_send_idx_mutex);
						ret = 1;
					}else{
						ret = -1;
					}
				}
				pthread_mutex_unlock(&get_pitd->pitd_mutex);
			}

		}else{

			iph = (struct iphdr *)(get_pitd->normal_packet_data + A_INTERNAL_HEADER + B_OPENVPN_PDATA_HEADER);
			if(md->opt->mode == SERVER){
				if(iph->version == 4){
#if 0
					if(md->opt->client_config_dir == NULL){
						if(iph->saddr != 0x0){

						}
					}
#endif
					if(iph->daddr != 0x0){
						unsigned int daddr = ntohl(iph->daddr);
						memcpy(&ud.key,&daddr,4);

						pthread_mutex_lock(&opt->user_tree_mutex);
						pud = (struct user_data *)rb_find(opt->user_tree,(void *)&ud);
						pthread_mutex_unlock(&opt->user_tree_mutex);

						if(pud == NULL){

							//printf("##################### test %s %d ##%08x########################\n",__func__,__LINE__,daddr);
							ret = -1;
						}else{
							pipe_epd = pud->epd;
							pthread_mutex_lock(&get_pitd->pitd_mutex);
							if(pipe_epd == NULL || pipe_epd->n_fdd == NULL || pipe_epd->ss == NULL || pipe_epd->pc == NULL || pipe_epd->pii == NULL || pipe_epd->ps == NULL){

								pthread_mutex_lock(&opt->user_tree_mutex);
								rb_delete(opt->user_tree,pud,true,sizeof(struct user_data));
								pthread_mutex_unlock(&opt->user_tree_mutex);

								ret = -1;
							}else{

								bool ready = false;
								pthread_mutex_lock(&pipe_epd->pc->ping_check_mutex);
								if(pipe_epd->pc->ready == true){
									ready = true;
								}else{
									ready = false;
								}
								pthread_mutex_unlock(&pipe_epd->pc->ping_check_mutex);

								if(ready == false){
									if(pipe_epd->stop == 0){
										int net_wfd = pipe_epd->n_fdd->net_wfd;
										get_pitd->dst_fd 					= net_wfd;
										get_pitd->TPT_packet_status 	= 0;
										get_pitd->TPT_send_ok   		= 0;
										get_pitd->NPT_packet_status 	= PACKET_SEND;
										get_pitd->NPT_send_ok   		= SEND_OK;
										get_pitd->net_epd 				= pipe_epd;

										pthread_mutex_lock(&pipe_epd->pii->data_send_idx_mutex);
										pthread_mutex_lock(&md->TPT_idx_mutex);
										get_pitd->key = md->TPT_idx;
										if(md->TPT_idx == 0){
											md->TPT_idx = 1;
										}else{
											md->TPT_idx++;
										}
										pthread_mutex_unlock(&md->TPT_idx_mutex);
										pipe_epd->pii->data_send_idx++;
										if(pipe_epd->pii->data_send_idx == 0){
											pipe_epd->pii->data_send_idx = 1;
										}
										get_pitd->data_send_idx = pipe_epd->pii->data_send_idx;
										pthread_mutex_unlock(&pipe_epd->pii->data_send_idx_mutex);
										ret = 1;

									}else{
										ret = -1;
									}
								}else{
									ret = -1;
								}
							}
							pthread_mutex_unlock(&get_pitd->pitd_mutex);
						}
					}else{
						ret = -1;
					}
				}else{
					ret = -1;
				}
			}else if(md->opt->mode == CLIENT){
				if(iph->version == 4){
					pipe_epd = md->net_epd;

					pthread_mutex_lock(&get_pitd->pitd_mutex);
					if(pipe_epd == NULL || pipe_epd->n_fdd == NULL || pipe_epd->ss == NULL || pipe_epd->pc == NULL || pipe_epd->pii == NULL || pipe_epd->ps == NULL){
						ret = -1;
					}else{
						if(pipe_epd->stop == 0){
							int net_wfd = pipe_epd->n_fdd->net_wfd;
							get_pitd->dst_fd 					= net_wfd;
							get_pitd->TPT_packet_status 	= 0;
							get_pitd->TPT_send_ok   		= 0;
							get_pitd->NPT_packet_status 	= PACKET_SEND;
							get_pitd->NPT_send_ok   		= SEND_OK;
							get_pitd->net_epd 				= pipe_epd;
							pthread_mutex_lock(&pipe_epd->pii->data_send_idx_mutex);
							pthread_mutex_lock(&md->TPT_idx_mutex);
							get_pitd->key = md->TPT_idx;
							if(md->TPT_idx == 0){
								md->TPT_idx = 1;
							}else{
								md->TPT_idx++;
							}
							pthread_mutex_unlock(&md->TPT_idx_mutex);
							pipe_epd->pii->data_send_idx++;
							if(pipe_epd->pii->data_send_idx == 0){
								pipe_epd->pii->data_send_idx = 1;
							}
							get_pitd->data_send_idx = pipe_epd->pii->data_send_idx;
							pthread_mutex_unlock(&pipe_epd->pii->data_send_idx_mutex);
							ret = 1;
						}else{
							ret = -1;
						}
					}
					pthread_mutex_unlock(&get_pitd->pitd_mutex);
				}else{
					ret = -1;
				}
			}else{
				ret = -1;
			}
		}
	}else{
		ret = -1;
	}

	if(ret == -1){
		pthread_mutex_lock(&get_pitd->pitd_mutex);
		get_pitd->TPT_packet_status 	= 0;
		get_pitd->TPT_send_ok   		= 0;
		get_pitd->NPT_packet_status 	= PACKET_DROP;
		get_pitd->NPT_send_ok   		= SEND_OK;
		pthread_mutex_unlock(&get_pitd->pitd_mutex);
	}

	return ret;
}

int tunfd_route_tap_out_in(struct epoll_ptr_data *epd,struct packet_idx_tree_data *get_pitd,struct internal_header *ih)
{
	int ret = -1;
	int p_ret = 0;
	struct options *opt = NULL;
	struct main_data *md = NULL;
	struct iphdr *iph	= NULL;
	struct openvpn_arp *arp = NULL;
	struct ether_header *eth_hdr = NULL;
	struct epoll_ptr_data *pipe_epd=NULL;
	struct epoll_ptr_data *tun_epd = NULL;
	struct user_data ct_ud;
	struct user_data *ct_pud = NULL;
	struct user_data ud;
	struct user_data *pud = NULL;
	char *normal_packet_data   = NULL;
	int normal_packet_data_len = 0;
	uint32_t key = 0;

	struct list_data *now=NULL;
	md = (struct main_data *)epd->gl_var;
	opt = md->opt;

	key = ntohl(ih->packet_idx);
	tun_epd = md->tun_epd;
	if(get_pitd != NULL){
		eth_hdr = (struct ether_header *)(get_pitd->normal_packet_data + A_INTERNAL_HEADER + B_OPENVPN_PDATA_HEADER);
		if(md->opt->mode == SERVER){
			switch(htons(eth_hdr->ether_type)){
				case 0x0800:
					iph = (struct iphdr *)(get_pitd->normal_packet_data + A_INTERNAL_HEADER + B_OPENVPN_PDATA_HEADER + sizeof(struct ether_header));
#if 0
					ct_ud.key = get_pitd->src_fd;
					pthread_mutex_lock(&opt->ct_tree_mutex);
					ct_pud = rb_find(opt->ct_tree,(char *)&ct_ud);
					pthread_mutex_unlock(&opt->ct_tree_mutex);
					if(ct_pud != NULL){
						memset(&ud,0x00,sizeof(struct user_data));
						memcpy(&ud.key,&iph->saddr,4);
						pthread_mutex_lock(&opt->user_tree_mutex);	
						pud = rb_find(opt->user_tree,(char *)&ud);
						pthread_mutex_unlock(&opt->user_tree_mutex);
						if(pud == NULL){
							if(ct_pud->epd == NULL || ct_pud->epd->n_fdd == NULL){
								pthread_mutex_lock(&opt->ct_tree_mutex);
								if(ct_pud != NULL){
									rb_delete(opt->ct_tree,ct_pud,true,sizeof(struct user_data));
								}
								pthread_mutex_unlock(&opt->ct_tree_mutex);
							}else{
								pud = malloc(sizeof(struct user_data));
								memcpy((char *)&pud->key,(char *)&iph->saddr,4);
								pud->epd = ct_pud->epd;
								pthread_mutex_lock(&opt->user_tree_mutex);	
								rb_insert(opt->user_tree,pud);
								pthread_mutex_unlock(&opt->user_tree_mutex);
							}
						}else{
							if(ct_pud->epd != pud->epd){
								pthread_mutex_lock(&opt->user_tree_mutex);
								rb_delete(opt->user_tree,pud,true,sizeof(struct user_data));
								pthread_mutex_unlock(&opt->user_tree_mutex);
								pud = malloc(sizeof(struct user_data));
								memcpy((char *)&pud->key,(char *)&iph->saddr,4);
								pud->epd = ct_pud->epd;
								pthread_mutex_lock(&opt->user_tree_mutex);	
								rb_insert(opt->user_tree,pud);
								pthread_mutex_unlock(&opt->user_tree_mutex);
							}
						}
					}
					else{
						MM("### %s[:%d] ERR : EPD NOT found .. fd : %d ##\n",__func__,__LINE__,get_pitd->src_fd);
					}
#endif
					memset(&ud,0x00,sizeof(struct user_data));
					memcpy(&ud.key,&iph->daddr,4);
					pthread_mutex_lock(&opt->user_tree_mutex);
					pud = rb_find(opt->user_tree,&ud);
					pthread_mutex_unlock(&opt->user_tree_mutex);

					pthread_mutex_lock(&get_pitd->pitd_mutex);
					if(pud != NULL){
						normal_packet_data_len = get_pitd->normal_packet_data_len-A_INTERNAL_HEADER-B_OPENVPN_PDATA_HEADER;
						normal_packet_data = malloc(normal_packet_data_len);
						memset(normal_packet_data,0x00,normal_packet_data_len);
						memcpy(normal_packet_data,get_pitd->normal_packet_data+A_INTERNAL_HEADER+B_OPENVPN_PDATA_HEADER,normal_packet_data_len);
						p_ret = ALL_SEND_handle(epd,get_pitd->src_fd,normal_packet_data,normal_packet_data_len);
						if(p_ret < 0){
							MM("##ERR: %s %s[:%d] S %s D %s  RET: %d ##\n",__FILE__,__func__,__LINE__,epd->name,tun_epd->name,p_ret);
						}
						free(normal_packet_data);
						ret = -1;
					}else{
						ret = 1;
					}
					pthread_mutex_unlock(&get_pitd->pitd_mutex);

					break;
				case 0x0806:
					arp = (struct openvpn_arp *)(get_pitd->normal_packet_data + A_INTERNAL_HEADER + B_OPENVPN_PDATA_HEADER + sizeof(struct ether_header));
					if((htons(arp->arp_command) == ARP_REPLY) || (htons(arp->arp_command) == GARP_REPLY)){
						ct_ud.key = get_pitd->src_fd;
						pthread_mutex_lock(&opt->ct_tree_mutex);
						ct_pud = rb_find(opt->ct_tree,(char *)&ct_ud);
						pthread_mutex_unlock(&opt->ct_tree_mutex);
						if(ct_pud != NULL){

							memset(&ud,0x00,sizeof(struct user_data));
							memcpy(&ud.key,&arp->ip_src,4);
							pthread_mutex_lock(&opt->user_tree_mutex);	
							pud = rb_find(opt->user_tree,(char *)&ud);
							pthread_mutex_unlock(&opt->user_tree_mutex);
							if(pud == NULL){
#if 0
								printf("## ARP REPLY Insert %s %d %s %03d %03d %03d %03d ##\n",__func__,__LINE__,ct_pud->epd->name,
										(0xff & arp->ip_src[0]),
										(0xff & arp->ip_src[1]),
										(0xff & arp->ip_src[2]),
										(0xff & arp->ip_src[3])
										);
#endif

								if(ct_pud->epd == NULL || ct_pud->epd->n_fdd == NULL){
									pthread_mutex_lock(&opt->ct_tree_mutex);
									if(ct_pud != NULL){
										rb_delete(opt->ct_tree,ct_pud,true,sizeof(struct user_data));
									}
									pthread_mutex_unlock(&opt->ct_tree_mutex);
								}else{
									pud = malloc(sizeof(struct user_data));
									memcpy((char *)&pud->key,(char *)&arp->ip_src,4);
									pud->epd = ct_pud->epd;
									pthread_mutex_lock(&opt->user_tree_mutex);	
									rb_insert(opt->user_tree,pud);
									pthread_mutex_unlock(&opt->user_tree_mutex);
								}
							}else{
								if(ct_pud->epd != pud->epd){
									pthread_mutex_lock(&opt->user_tree_mutex);	
									rb_delete(opt->user_tree,pud,true,sizeof(struct user_data));
									pthread_mutex_unlock(&opt->user_tree_mutex);

#if 0
									printf("## ARP REPLY Insert %s %d %s %03d %03d %03d %03d ##\n",__func__,__LINE__,ct_pud->epd->name,
											(0xff & arp->ip_src[0]),
											(0xff & arp->ip_src[1]),
											(0xff & arp->ip_src[2]),
											(0xff & arp->ip_src[3])
											);
#endif
									pud = malloc(sizeof(struct user_data));
									memcpy((char *)&pud->key,(char *)&arp->ip_src,4);
									pud->epd = ct_pud->epd;
									pthread_mutex_lock(&opt->user_tree_mutex);	
									rb_insert(opt->user_tree,pud);
									pthread_mutex_unlock(&opt->user_tree_mutex);
								}
							}

						}
						else{
							MM("### %s[:%d] ERR : EPD NOT found .. fd : %d ##\n",__func__,__LINE__,get_pitd->src_fd);
						}



						memcpy(&ud.key,&arp->ip_dest,4);

						pthread_mutex_lock(&opt->user_tree_mutex);
						pud = rb_find(opt->user_tree,&ud);
						pthread_mutex_unlock(&opt->user_tree_mutex);

						pthread_mutex_lock(&get_pitd->pitd_mutex);
						if(pud != NULL){
							normal_packet_data_len 	= get_pitd->normal_packet_data_len-A_INTERNAL_HEADER-B_OPENVPN_PDATA_HEADER;
							normal_packet_data 		= malloc(normal_packet_data_len);
							memset(normal_packet_data,0x00,normal_packet_data_len);
							memcpy(normal_packet_data,get_pitd->normal_packet_data+A_INTERNAL_HEADER+B_OPENVPN_PDATA_HEADER,normal_packet_data_len);
							p_ret = ALL_SEND_handle(epd,get_pitd->src_fd,normal_packet_data,normal_packet_data_len);
							if(p_ret < 0){
								MM("##ERR: %s %s[:%d] S %s D %s  RET: %d ##\n",__FILE__,__func__,__LINE__,epd->name,tun_epd->name,p_ret);
							}
							ret = -1;
						}else{
							ret = 1;
						}
						pthread_mutex_unlock(&get_pitd->pitd_mutex);
						free(normal_packet_data);

					}else{
						ct_ud.key = get_pitd->src_fd;
						pthread_mutex_lock(&opt->ct_tree_mutex);
						ct_pud = rb_find(opt->ct_tree,(char *)&ct_ud);
						pthread_mutex_unlock(&opt->ct_tree_mutex);
						if(ct_pud != NULL){
							memset(&ud,0x00,sizeof(struct user_data));
							memcpy(&ud.key,&arp->ip_src,4);
							pthread_mutex_lock(&opt->user_tree_mutex);	
							pud = rb_find(opt->user_tree,(char *)&ud);
							pthread_mutex_unlock(&opt->user_tree_mutex);

							if(pud != NULL){
								if(ct_pud->epd != pud->epd){
									pthread_mutex_lock(&opt->user_tree_mutex);	
									rb_delete(opt->user_tree,pud,true,sizeof(struct user_data));
									pthread_mutex_unlock(&opt->user_tree_mutex);
#if 0
									printf("## ARP REQUEST Insert %s %d %s %03d %03d %03d %03d ##\n",__func__,__LINE__,ct_pud->epd->name,
											(0xff & arp->ip_src[0]),
											(0xff & arp->ip_src[1]),
											(0xff & arp->ip_src[2]),
											(0xff & arp->ip_src[3])
											);
#endif

									pud = malloc(sizeof(struct user_data));
									memcpy((char *)&pud->key,(char *)&arp->ip_src,4);
									pud->epd = ct_pud->epd;
									pthread_mutex_lock(&opt->user_tree_mutex);	
									rb_insert(opt->user_tree,pud);
									pthread_mutex_unlock(&opt->user_tree_mutex);
								}
							}else{

#if 0
								MM("## ARP REQUEST Insert %s %d %s %03d %03d %03d %03d ##\n",__func__,__LINE__,ct_pud->epd->name,
										(0xff & arp->ip_src[0]),
										(0xff & arp->ip_src[1]),
										(0xff & arp->ip_src[2]),
										(0xff & arp->ip_src[3])
										);
#endif
								pud = malloc(sizeof(struct user_data));
								memcpy((char *)&pud->key,(char *)&arp->ip_src,4);
								pud->epd = ct_pud->epd;
								pthread_mutex_lock(&opt->user_tree_mutex);	
								rb_insert(opt->user_tree,pud);
								pthread_mutex_unlock(&opt->user_tree_mutex);
							}
#if 0
							pthread_mutex_lock(&md->print_mutex);
							printf("## ARP REQUEST src IP  %s %d %s %03d %03d %03d %03d ##\n",__func__,__LINE__,epd->name,
									(0xff & arp->ip_src[0]),
									(0xff & arp->ip_src[1]),
									(0xff & arp->ip_src[2]),
									(0xff & arp->ip_src[3])
									);
							printf("## ARP REQUEST dest IP  %s %d %s %03d %03d %03d %03d ##\n",__func__,__LINE__,epd->name,
									(0xff & arp->ip_dest[0]),
									(0xff & arp->ip_dest[1]),
									(0xff & arp->ip_dest[2]),
									(0xff & arp->ip_dest[3])
									);
							pthread_mutex_unlock(&md->print_mutex);
#endif



							memset(&ud,0x00,sizeof(struct user_data));
							memcpy(&ud.key,&arp->ip_dest,4);
							pthread_mutex_lock(&opt->user_tree_mutex);	
							pud = rb_find(opt->user_tree,&ud);
							pthread_mutex_unlock(&opt->user_tree_mutex);

							pthread_mutex_lock(&get_pitd->pitd_mutex);
							normal_packet_data_len = get_pitd->normal_packet_data_len-A_INTERNAL_HEADER-B_OPENVPN_PDATA_HEADER;
							normal_packet_data = malloc(normal_packet_data_len);
							memset(normal_packet_data,0x00,normal_packet_data_len);
							memcpy(normal_packet_data,get_pitd->normal_packet_data+A_INTERNAL_HEADER+B_OPENVPN_PDATA_HEADER,normal_packet_data_len);
							if(pud != NULL){
#if 1
								int i=0;
								pthread_mutex_lock(&md->li_mutex);
								for(i=0,now = md->li->next; now; now=now->next,i++){
									if(now == NULL){
										MM("## %s %s[:%d] S %s D NULL ##\n",__FILE__,__func__,__LINE__,epd->name);
										break;
									}

									pud = (struct user_data *)now->data;
									if(pud != NULL && pud->epd != NULL){
										pipe_epd = pud->epd;

										if(pipe_epd == NULL){
											MM("## %s %s[:%d] S %s D NULL ##\n",__FILE__,__func__,__LINE__,epd->name);
											del_list(md->li,now);
											continue;
										}


										if(pipe_epd == NULL || pipe_epd->n_fdd == NULL || pipe_epd->ss == NULL || pipe_epd->pc == NULL || pipe_epd->pii == NULL || pipe_epd->ps == NULL){
											MM("## %s %s[:%d] S %s D NULL ##\n",__FILE__,__func__,__LINE__,epd->name);
											del_list(md->li,now);
											continue;
										}

										if(get_pitd->src_fd == pipe_epd->n_fdd->net_wfd){
											MM("## %s %s[:%d] S %s D NULL ##\n",__FILE__,__func__,__LINE__,epd->name);
											continue;
										}

										ALL_SEND_handle(epd,get_pitd->src_fd,normal_packet_data,normal_packet_data_len);

									}else{
										del_list(md->li,now);
										continue;
									}
								}
								pthread_mutex_unlock(&md->li_mutex);
#endif
								ret = -1;
							}else{
								ret = 1;
							}
							pthread_mutex_unlock(&get_pitd->pitd_mutex);

#if 0

							p_ret = ALL_SEND_handle(epd,get_pitd->src_fd,normal_packet_data,normal_packet_data_len);
							if(p_ret < 0){
								MM("##ERR: %s %s[:%d] S %s D %s  RET: %d ##\n",__FILE__,__func__,__LINE__,epd->name,tun_epd->name,p_ret);
							}
#endif
							free(normal_packet_data);
						}else{
							ret = -1;
							MM("###ERR: %s %s[:%d] %s  EPD NOT found .. fd : %d ##\n",__FILE__,__func__,__LINE__,epd->name,get_pitd->src_fd);
						}
					}
					break;
				default:
					ret = -1;
					break;

			}
			if(ret == 1){
				pthread_mutex_lock(&get_pitd->pitd_mutex);
				get_pitd->dst_fd 					= tun_epd->t_fdd->tun_rfd;
				get_pitd->NPT_packet_status 	= 0;
				get_pitd->NPT_send_ok   		= 0;
				get_pitd->TPT_packet_status 	= PACKET_SEND;
				get_pitd->TPT_send_ok       	= SEND_OK;
				pthread_mutex_unlock(&get_pitd->pitd_mutex);
			}
			if(ret == -1){
				pthread_mutex_lock(&get_pitd->pitd_mutex);
				get_pitd->dst_fd 					= 0;
				get_pitd->NPT_packet_status 	= 0;
				get_pitd->NPT_send_ok       	= 0;
				get_pitd->TPT_packet_status 	= PACKET_DROP;
				get_pitd->TPT_send_ok       	= SEND_OK;
				pthread_mutex_unlock(&get_pitd->pitd_mutex);
			}
			if(ret == 0){
				printf("## ERR: EXIT %s %d %d ####\n",__func__,__LINE__,ret);
				exit(0);
			}
			TPT_sync_handle(epd,key);

		}else if(md->opt->mode == CLIENT){

			switch(htons(eth_hdr->ether_type)){
				case 0x0800:
				case 0x0806:
					pthread_mutex_lock(&get_pitd->pitd_mutex);
					get_pitd->dst_fd 					= tun_epd->t_fdd->tun_rfd;
					get_pitd->NPT_packet_status 	= 0;
					get_pitd->NPT_send_ok   		= 0;
					get_pitd->TPT_packet_status 	= PACKET_SEND;
					get_pitd->TPT_send_ok       	= SEND_OK;
					pthread_mutex_unlock(&get_pitd->pitd_mutex);
					TPT_sync_handle(epd,key);

					break;
				default:
					pthread_mutex_lock(&get_pitd->pitd_mutex);
					get_pitd->dst_fd 					= 0;
					get_pitd->NPT_packet_status 	= 0;
					get_pitd->NPT_send_ok   		= 0;
					get_pitd->TPT_packet_status 	= PACKET_DROP;
					get_pitd->TPT_send_ok   		= SEND_OK;
					pthread_mutex_unlock(&get_pitd->pitd_mutex);
					TPT_sync_handle(epd,key);

					break;
			}
		}
	}
	return ret;
}


int tunfd_route_tap_in_out(struct epoll_ptr_data *epd,struct packet_idx_tree_data *get_pitd,struct internal_header *ih)
{
	int ret = -1;
	int i = 0;
	struct iphdr *iph=NULL;
	struct openvpn_arp *arp = NULL;
	struct ether_header *eth_hdr=NULL;
	struct epoll_ptr_data *pipe_epd=NULL;
	struct user_data ud;
	struct user_data *pud=NULL;
	struct main_data *md=NULL;

	struct options *opt = NULL;

	struct list_data *now=NULL;
	char *normal_packet_data   = NULL;
	int normal_packet_data_len = 0;

	md = (struct main_data *)epd->gl_var;
	opt = md->opt;

	if(get_pitd != NULL){
		if(ntohs(ih->ping_send) == 1){
			if(opt->mode == SERVER){
				struct user_data ct_ud;
				struct user_data *ct_pud = NULL;
				ct_ud.key = ntohs(ih->fd);
				pthread_mutex_lock(&opt->ct_tree_mutex);
				ct_pud = rb_find(opt->ct_tree,(char *)&ct_ud);
				pthread_mutex_unlock(&opt->ct_tree_mutex);
				if(ct_pud != NULL){
					pipe_epd = ct_pud->epd;
				}else{
					ret = -1;
				}
			}else if(opt->mode == CLIENT){
				pipe_epd = md->net_epd;
			}

			pthread_mutex_lock(&get_pitd->pitd_mutex);
			if(pipe_epd == NULL || pipe_epd->n_fdd == NULL || pipe_epd->ss == NULL || pipe_epd->pc == NULL || pipe_epd->pii == NULL || pipe_epd->ps == NULL){
				pthread_mutex_lock(&opt->ct_tree_mutex);
				if(pud != NULL){
					rb_delete(opt->ct_tree,pud,true,sizeof(struct user_data));
				}
				pthread_mutex_unlock(&opt->ct_tree_mutex);
				ret = -1;
			}else{
				if(pipe_epd->stop == 0){
					int net_wfd = pipe_epd->n_fdd->net_wfd;
					get_pitd->dst_fd 					= net_wfd;
					get_pitd->TPT_packet_status 	= 0;
					get_pitd->TPT_send_ok   		= 0;
					get_pitd->NPT_packet_status 	= PACKET_SEND;
					get_pitd->NPT_send_ok   		= SEND_OK;
					get_pitd->net_epd 				= pipe_epd;

					pthread_mutex_lock(&pipe_epd->pii->data_send_idx_mutex);
#if 1
					pthread_mutex_lock(&md->TPT_idx_mutex);
					get_pitd->key = md->TPT_idx;
					if(md->TPT_idx == 0){
						md->TPT_idx = 1;
					}else{
						md->TPT_idx++;
					}
					pthread_mutex_unlock(&md->TPT_idx_mutex);
#endif
					pipe_epd->pii->data_send_idx++;
					if(pipe_epd->pii->data_send_idx == 0){
						pipe_epd->pii->data_send_idx = 1;
					}
					get_pitd->data_send_idx = pipe_epd->pii->data_send_idx;
#if 0
					pud = NULL;
					pud = malloc(sizeof(struct user_data));
					pud->key = get_pitd->data_send_idx;
					pud->epd = pipe_epd;
					pud->pitd = get_pitd;

					pthread_mutex_lock(&pipe_epd->nit->net_idx_tree_mutex);	
					rb_insert(pipe_epd->nit->net_idx_tree,pud);
					pthread_mutex_unlock(&pipe_epd->nit->net_idx_tree_mutex);	
#endif
					pthread_mutex_unlock(&pipe_epd->pii->data_send_idx_mutex);
					ret = 1;

				}else{
					ret = -1;
				}
			}
			pthread_mutex_unlock(&get_pitd->pitd_mutex);
		}else{
			eth_hdr = (struct ether_header *)(get_pitd->normal_packet_data + A_INTERNAL_HEADER + B_OPENVPN_PDATA_HEADER);
			if(md->opt->mode == SERVER){
				switch(htons(eth_hdr->ether_type)){
					case 0x0800:
						iph =(struct iphdr *)(get_pitd->normal_packet_data + A_INTERNAL_HEADER + B_OPENVPN_PDATA_HEADER + sizeof(struct ether_header));
						memset(&ud,0x00,sizeof(struct user_data));
						memcpy(&ud.key,&iph->daddr,4);
						pthread_mutex_lock(&opt->user_tree_mutex);
						pud = rb_find(opt->user_tree,&ud);
						pthread_mutex_unlock(&opt->user_tree_mutex);
						if(pud != NULL){
							pipe_epd = pud->epd;

							pthread_mutex_lock(&get_pitd->pitd_mutex);
							if(pipe_epd == NULL || pipe_epd->n_fdd == NULL || pipe_epd->ss == NULL || pipe_epd->pc == NULL || pipe_epd->pii == NULL || pipe_epd->ps == NULL){
								pthread_mutex_lock(&opt->user_tree_mutex);
								rb_delete(opt->user_tree,pud,true,sizeof(struct user_data));
								pthread_mutex_unlock(&opt->user_tree_mutex);
								ret = -1;
							}else{
								if(pipe_epd->stop == 0){
									int net_wfd = pipe_epd->n_fdd->net_wfd;

									get_pitd->dst_fd 					= net_wfd;
									get_pitd->TPT_packet_status 	= 0;
									get_pitd->TPT_send_ok   		= 0;
									get_pitd->NPT_packet_status 	= PACKET_SEND;
									get_pitd->NPT_send_ok   		= SEND_OK;
									get_pitd->net_epd 				= pipe_epd;


									pthread_mutex_lock(&pipe_epd->pii->data_send_idx_mutex);
#if 1
									pthread_mutex_lock(&md->TPT_idx_mutex);
									get_pitd->key = md->TPT_idx;
									if(md->TPT_idx == 0){
										md->TPT_idx = 1;
									}else{
										md->TPT_idx++;
									}
									pthread_mutex_unlock(&md->TPT_idx_mutex);
#endif
									pipe_epd->pii->data_send_idx++;
									if(pipe_epd->pii->data_send_idx == 0){
										pipe_epd->pii->data_send_idx = 1;
									}
									get_pitd->data_send_idx = pipe_epd->pii->data_send_idx;
#if 0
									pud = NULL;
									pud = malloc(sizeof(struct user_data));
									pud->key = get_pitd->data_send_idx;
									pud->epd = pipe_epd;
									pud->pitd = get_pitd;

									pthread_mutex_lock(&pipe_epd->nit->net_idx_tree_mutex);	
									rb_insert(pipe_epd->nit->net_idx_tree,pud);
									pthread_mutex_unlock(&pipe_epd->nit->net_idx_tree_mutex);	
#endif
									pthread_mutex_unlock(&pipe_epd->pii->data_send_idx_mutex);

									ret = 1;

								}else{
									ret = -1;
								}
							}
							pthread_mutex_unlock(&get_pitd->pitd_mutex);
						}else{
							ret = -1;
						}
						break;
					case 0x0806:
						arp = (struct openvpn_arp *)(get_pitd->normal_packet_data + A_INTERNAL_HEADER + B_OPENVPN_PDATA_HEADER + sizeof(struct ether_header));
						if((htons(arp->arp_command) == ARP_REPLY) || (htons(arp->arp_command) == GARP_REPLY)){
							memset(&ud,0x00,sizeof(struct user_data));
							memcpy(&ud.key,&arp->ip_dest,4);

							pthread_mutex_lock(&opt->user_tree_mutex);
							pud = rb_find(opt->user_tree,&ud);
							pthread_mutex_unlock(&opt->user_tree_mutex);
							if(pud != NULL){
								pipe_epd = pud->epd;

								pthread_mutex_lock(&get_pitd->pitd_mutex);
								if(pipe_epd == NULL || pipe_epd->n_fdd == NULL || pipe_epd->ss == NULL || pipe_epd->pc == NULL || pipe_epd->pii == NULL || pipe_epd->ps == NULL){
									pthread_mutex_lock(&opt->user_tree_mutex);
									rb_delete(opt->user_tree,pud,true,sizeof(struct user_data));
									pthread_mutex_unlock(&opt->user_tree_mutex);
									ret = -1;
								}else{

									if(pipe_epd->stop == 0){
										int net_wfd = pipe_epd->n_fdd->net_wfd;
										get_pitd->dst_fd 					= net_wfd;
										get_pitd->TPT_packet_status 	= 0;
										get_pitd->TPT_send_ok   		= 0;
										get_pitd->NPT_packet_status 	= PACKET_SEND;
										get_pitd->NPT_send_ok   		= SEND_OK;
										get_pitd->net_epd 				= pipe_epd;

										pthread_mutex_lock(&pipe_epd->pii->data_send_idx_mutex);
#if 1
										pthread_mutex_lock(&md->TPT_idx_mutex);
										get_pitd->key = md->TPT_idx;
										if(md->TPT_idx == 0){
											md->TPT_idx = 1;
										}else{
											md->TPT_idx++;
										}
										pthread_mutex_unlock(&md->TPT_idx_mutex);
#endif

										pipe_epd->pii->data_send_idx++;
										if(pipe_epd->pii->data_send_idx == 0){
											pipe_epd->pii->data_send_idx = 1;
										}
										get_pitd->data_send_idx = pipe_epd->pii->data_send_idx;
#if 0
										pud = NULL;
										pud = malloc(sizeof(struct user_data));
										pud->key = get_pitd->data_send_idx;
										pud->epd = pipe_epd;
										pud->pitd = get_pitd;

										pthread_mutex_lock(&pipe_epd->nit->net_idx_tree_mutex);	
										rb_insert(pipe_epd->nit->net_idx_tree,pud);
										pthread_mutex_unlock(&pipe_epd->nit->net_idx_tree_mutex);	
#endif
										pthread_mutex_unlock(&pipe_epd->pii->data_send_idx_mutex);
										ret = 1;

									}else{
										ret = -1;
									}
								}
								pthread_mutex_unlock(&get_pitd->pitd_mutex);
							}else{
								ret = -1;
							}
						}else{

							memset(&ud,0x00,sizeof(struct user_data));
							memcpy(&ud.key,&arp->ip_dest,4);
#if 0
pthread_mutex_lock(&md->print_mutex);
			printf("## ARP REQUEST src  IP %s %d %s %03d %03d %03d %03d ##\n",
										__func__,__LINE__,epd->name,
										(0xff & arp->ip_src[0]),
										(0xff & arp->ip_src[1]),
										(0xff & arp->ip_src[2]),
										(0xff & arp->ip_src[3])
										);
			printf("## ARP REQUEST dest IP %s %d %s %03d %03d %03d %03d # %08x #\n",
										__func__,__LINE__,epd->name,
										(0xff & arp->ip_dest[0]),
										(0xff & arp->ip_dest[1]),
										(0xff & arp->ip_dest[2]),
										(0xff & arp->ip_dest[3]),
										ud.key
										);

pthread_mutex_unlock(&md->print_mutex);

#endif
							pthread_mutex_lock(&opt->user_tree_mutex);
							pud = rb_find(opt->user_tree,(void *)&ud);
							pthread_mutex_unlock(&opt->user_tree_mutex);
							if(pud != NULL){



#if 0
pthread_mutex_lock(&md->print_mutex);
			printf("## ARP REQUEST src [FOUND] IP %s %d %s %03d %03d %03d %03d ##\n",
										__func__,__LINE__,epd->name,
										(0xff & arp->ip_src[0]),
										(0xff & arp->ip_src[1]),
										(0xff & arp->ip_src[2]),
										(0xff & arp->ip_src[3])
										);
			printf("## ARP REQUEST dest [FOUND] IP %s %d %s %03d %03d %03d %03d # %08x #\n",
										__func__,__LINE__,epd->name,
										(0xff & arp->ip_dest[0]),
										(0xff & arp->ip_dest[1]),
										(0xff & arp->ip_dest[2]),
										(0xff & arp->ip_dest[3]),
										ud.key
										);

pthread_mutex_unlock(&md->print_mutex);
#endif


								pipe_epd = pud->epd;
								pthread_mutex_lock(&get_pitd->pitd_mutex);
								if(pipe_epd == NULL || pipe_epd->n_fdd == NULL || pipe_epd->ss == NULL || pipe_epd->pc == NULL || pipe_epd->pii == NULL || pipe_epd->ps == NULL){
									pthread_mutex_lock(&opt->user_tree_mutex);
									rb_delete(opt->user_tree,pud,true,sizeof(struct user_data));
									pthread_mutex_unlock(&opt->user_tree_mutex);
									ret = -1;
								}else{

									if(pipe_epd->stop == 0){
										int net_wfd = pipe_epd->n_fdd->net_wfd;
										get_pitd->dst_fd 					= net_wfd;
										get_pitd->TPT_packet_status 	= 0;
										get_pitd->TPT_send_ok   		= 0;
										get_pitd->NPT_packet_status 	= PACKET_SEND;
										get_pitd->NPT_send_ok   		= SEND_OK;
										get_pitd->net_epd 				= pipe_epd;

										pthread_mutex_lock(&pipe_epd->pii->data_send_idx_mutex);
#if 1
										pthread_mutex_lock(&md->TPT_idx_mutex);
										get_pitd->key = md->TPT_idx;
										if(md->TPT_idx == 0){
											md->TPT_idx = 1;
										}else{
											md->TPT_idx++;
										}
										pthread_mutex_unlock(&md->TPT_idx_mutex);
#endif
										pipe_epd->pii->data_send_idx++;
										if(pipe_epd->pii->data_send_idx == 0){
											pipe_epd->pii->data_send_idx = 1;
										}
										get_pitd->data_send_idx = pipe_epd->pii->data_send_idx;
#if 0
										pud = NULL;
										pud = malloc(sizeof(struct user_data));
										pud->key = get_pitd->data_send_idx;
										pud->epd = pipe_epd;
										pud->pitd = get_pitd;

										pthread_mutex_lock(&pipe_epd->nit->net_idx_tree_mutex);	
										rb_insert(pipe_epd->nit->net_idx_tree,pud);
										pthread_mutex_unlock(&pipe_epd->nit->net_idx_tree_mutex);	
#endif

										pthread_mutex_unlock(&pipe_epd->pii->data_send_idx_mutex);
										ret = 1;


									}else{
										ret = -1;
									}
								}
								pthread_mutex_unlock(&get_pitd->pitd_mutex);
							}else{
#if 0
pthread_mutex_lock(&md->print_mutex);
			printf("## ARP REQUEST src [NOT FOUND] IP %s %d %s %03d %03d %03d %03d ##\n",
										__func__,__LINE__,epd->name,
										(0xff & arp->ip_src[0]),
										(0xff & arp->ip_src[1]),
										(0xff & arp->ip_src[2]),
										(0xff & arp->ip_src[3])
										);
			printf("## ARP REQUEST dest [NOT FOUND] IP %s %d %s %03d %03d %03d %03d # %08x #\n",
										__func__,__LINE__,epd->name,
										(0xff & arp->ip_dest[0]),
										(0xff & arp->ip_dest[1]),
										(0xff & arp->ip_dest[2]),
										(0xff & arp->ip_dest[3]),
										ud.key
										);

pthread_mutex_unlock(&md->print_mutex);
#endif

								pthread_mutex_lock(&get_pitd->pitd_mutex);
								normal_packet_data_len = get_pitd->normal_packet_data_len-A_INTERNAL_HEADER;
								normal_packet_data = malloc(normal_packet_data_len);
								memset(normal_packet_data,0x00,normal_packet_data_len);
								memcpy(normal_packet_data,get_pitd->normal_packet_data+A_INTERNAL_HEADER,normal_packet_data_len);

								pthread_mutex_lock(&md->li_mutex);
								for(i=0,now = md->li->next; now; now=now->next,i++){
									if(now == NULL){
										MM("## %s %s[:%d] S %s D NULL ##\n",__FILE__,__func__,__LINE__,epd->name);
										break;
									}

									pud = (struct user_data *)now->data;
									if(pud != NULL && pud->epd != NULL){
										pipe_epd = pud->epd;

										if(pipe_epd == NULL){
											MM("## %s %s[:%d] S %s D NULL ##\n",__FILE__,__func__,__LINE__,epd->name);
											del_list(md->li,now);
											continue;
										}


										if(pipe_epd == NULL || pipe_epd->n_fdd == NULL || pipe_epd->ss == NULL || pipe_epd->pc == NULL || pipe_epd->pii == NULL || pipe_epd->ps == NULL){
											MM("## %s %s[:%d] S %s D NULL ##\n",__FILE__,__func__,__LINE__,epd->name);
											del_list(md->li,now);
											continue;
										}

										if(get_pitd->src_fd == pipe_epd->n_fdd->net_wfd){
											MM("## %s %s[:%d] S %s D NULL ##\n",__FILE__,__func__,__LINE__,epd->name);
											continue;
										}

										ALL_SEND_handle(epd,get_pitd->src_fd,normal_packet_data,normal_packet_data_len);

									}else{
										del_list(md->li,now);
										continue;
									}
								}
								pthread_mutex_unlock(&md->li_mutex);

								free(normal_packet_data);
								pthread_mutex_unlock(&get_pitd->pitd_mutex);
								ret = -1;

							}
						}
						break;
					default:
						ret = -1;
						break;

				}
				if(ret == -1){
						pthread_mutex_lock(&get_pitd->pitd_mutex);
						get_pitd->TPT_packet_status 	= 0;
						get_pitd->TPT_send_ok   		= 0;
						get_pitd->NPT_packet_status 	= PACKET_DROP;
						get_pitd->NPT_send_ok   		= SEND_OK;
						pthread_mutex_unlock(&get_pitd->pitd_mutex);
				}


			}else if(md->opt->mode == CLIENT){
				switch(htons(eth_hdr->ether_type)){
					case 0x0800:
					case 0x0806:
						pipe_epd = md->net_epd;
						int net_wfd = pipe_epd->n_fdd->net_wfd;
						pthread_mutex_lock(&get_pitd->pitd_mutex);
						get_pitd->dst_fd 					= net_wfd;
						get_pitd->TPT_packet_status 	= 0;
						get_pitd->TPT_send_ok   		= 0;
						get_pitd->NPT_packet_status 	= PACKET_SEND;
						get_pitd->NPT_send_ok   		= SEND_OK;
						get_pitd->net_epd 				= pipe_epd;

						pthread_mutex_lock(&pipe_epd->pii->data_send_idx_mutex);
#if 1
						pthread_mutex_lock(&md->TPT_idx_mutex);
						get_pitd->key = md->TPT_idx;
						if(md->TPT_idx == 0){
							md->TPT_idx = 1;
						}else{
						   md->TPT_idx++;
						}
						pthread_mutex_unlock(&md->TPT_idx_mutex);
#endif

						pipe_epd->pii->data_send_idx++;
						if(pipe_epd->pii->data_send_idx == 0){
							pipe_epd->pii->data_send_idx = 1;
						}
						get_pitd->data_send_idx = pipe_epd->pii->data_send_idx;
#if 0
						pud = NULL;
						pud = malloc(sizeof(struct user_data));
						pud->key = get_pitd->data_send_idx;
						pud->epd = pipe_epd;
						pud->pitd = get_pitd;

						pthread_mutex_lock(&pipe_epd->nit->net_idx_tree_mutex);	
						rb_insert(pipe_epd->nit->net_idx_tree,pud);
						pthread_mutex_unlock(&pipe_epd->nit->net_idx_tree_mutex);	
#endif
						pthread_mutex_unlock(&pipe_epd->pii->data_send_idx_mutex);
						pthread_mutex_unlock(&get_pitd->pitd_mutex);

						ret = 1;
						break;
					default:
						pthread_mutex_lock(&get_pitd->pitd_mutex);
						get_pitd->TPT_packet_status 	= 0;
						get_pitd->TPT_send_ok   		= 0;
						get_pitd->NPT_packet_status 	= PACKET_DROP;
						get_pitd->NPT_send_ok   		= SEND_OK;
						pthread_mutex_unlock(&get_pitd->pitd_mutex);
						ret = -1;
						break;
				}
			}
		}
	}
	return ret;
}


