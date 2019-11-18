#include <rain_common.h>

int send_thread_process(struct main_data *md,int type)
{
#if 0
	struct options *opt = NULL;
	opt = md->opt;
#endif
	struct pth_timer_data *p_t_d = NULL;
	p_t_d = malloc(sizeof(struct pth_timer_data));
	if(p_t_d == NULL){
		MM("## ERR: EXIT %s %d ##\n",__func__,__LINE__);
		exit(0);
	}
	memset(p_t_d,0x00,sizeof(struct pth_timer_data));
	struct epoll_ptr_data *epd = NULL;
	epd = malloc(sizeof(struct epoll_ptr_data));
	if(epd == NULL){
		printf("## ERR: EXIT %s %d ##\n",__func__,__LINE__);
		exit(0);
	}
	memset(epd,0x00,sizeof(struct epoll_ptr_data));

	struct pipe_fd_data *p_fdd=NULL;
	p_fdd = malloc(sizeof(struct pipe_fd_data));
	if(p_fdd == NULL){
		printf("## ERR: EXIT %s %d ##\n",__func__,__LINE__);
		exit(0);
	}
	memset(p_fdd,0x00,sizeof(struct pipe_fd_data));
	pthread_mutex_init(&p_fdd->pipe_r_mutex,NULL);
	pthread_mutex_init(&p_fdd->pipe_w_mutex,NULL);

	epd->p_fdd = p_fdd;

	epd->epoll_fd = epoll_init(PIPE_MAX_EVENTS);
	pipe(epd->p_fdd->pipe_fd);
	epd->p_fdd->pipe_rfd = epd->p_fdd->pipe_fd[0];
	epd->p_fdd->pipe_wfd = epd->p_fdd->pipe_fd[1];

	epoll_add(epd->epoll_fd,epd->p_fdd->pipe_rfd,0);

	epd->gl_var = (void *)md;
	p_t_d->func = rain_timer_start;
	if(type == THREAD_SEND_NET){
		epd->thd_mode 		= THREAD_SEND_NET;
		p_t_d->start_func = (void *)NPT_sync_thd;
		sprintf(p_t_d->name,"net_send_thread");
		sprintf(epd->name,"net_send_thread");
		md->net_send_epd = epd;
	}else if(type == THREAD_SEND_TUN){
		epd->thd_mode 		= THREAD_SEND_TUN;
		p_t_d->start_func = (void *)TPT_sync_thd;
		sprintf(p_t_d->name,"tun_send_thread");
		sprintf(epd->name,"tun_send_thread");
		md->tun_send_epd = epd;
	}
	p_t_d->sec           = 0;
	p_t_d->nsec          = 0;
	p_t_d->ptr           = (void *)epd;
	//p_t_d->timer_status  = 1;
	rain_timer_init(p_t_d);
	return 0;
}



int server_process(struct main_data *md,int epoll_fd,int server_fd){
	int ret=0;
	int nfds=0;
	int i=0;
	int net_fd=0;
	int cli_len =0;
	bool loop = true;
	struct epoll_event events[SERVER_MAX_EVENTS];
	struct sockaddr_in cli_addr;

	struct options *opt = md->opt;
	MM("## %s %d ###\n",__func__,__LINE__);

	while(loop){
		nfds=epoll_wait(epoll_fd,events,SERVER_MAX_EVENTS,1);
		if(nfds < 0){
			MM("##ERR: %s %d ###\n",__func__,__LINE__);
		}else if(nfds == 0){
			continue;
		}else{
			for(i = 0 ; i < nfds ; i++){
				if(events[i].data.fd == server_fd){
					memset((char *)&cli_addr,0x00,sizeof(cli_addr));
					cli_len =  sizeof(cli_addr);
					net_fd = accept(server_fd, (struct sockaddr *)&cli_addr,(socklen_t *)&cli_len);
					if(net_fd <= 0){
						perror("#ERR server_process : ");
						MM("##ERR: %s %d server_fd %d net_fd %d ###\n",__func__,__LINE__,server_fd,net_fd);
					}else{
						//mtrace();

						struct user_data ud;
						struct user_data *pud;
						ud.key = cli_addr.sin_addr.s_addr;
						//memcpy(&ud.key,&cli_addr.sin_addr.s_addr,4);
						//ud.key = 
						pthread_mutex_lock(&opt->client_tree_mutex);
						pud = rb_find(opt->client_tree,&ud);
						pthread_mutex_unlock(&opt->client_tree_mutex);
						if(pud == NULL || pud->epd == NULL){

							if(pud != NULL){
								pthread_mutex_lock(&opt->client_tree_mutex);
								rb_delete(opt->client_tree,pud,true,sizeof(struct user_data));
								pthread_mutex_unlock(&opt->client_tree_mutex);
								pud = NULL;
							}

							pud = malloc(sizeof(struct user_data));
							memset(pud,0x00,sizeof(struct user_data));
							//memcpy(pud->key,&cli_addr.sin_addr.s_addr,4);
							pud->key = cli_addr.sin_addr.s_addr;

							pthread_mutex_lock(&opt->client_tree_mutex);
							pud = rb_insert(opt->client_tree,pud);
							pthread_mutex_unlock(&opt->client_tree_mutex);

							char *name = malloc(32);
							if(name == NULL){
								printf("##====================== ERR: EXIT %s %d ##\n",__func__,__LINE__);
								exit(0);
							}
							memset(name,0x00,32);

							sprintf(name,"%03d_%03d_%03d_%03d",
									cli_addr.sin_addr.s_addr     & 0x000000ff,
									cli_addr.sin_addr.s_addr>>8  & 0x000000ff,
									cli_addr.sin_addr.s_addr>>16 & 0x000000ff,
									cli_addr.sin_addr.s_addr>>24 & 0x000000ff
									);
							//MM("## %s %d %s net_fd %d ##\n",__func__,__LINE__,name,net_fd);
							net_process(md,net_fd,name,cli_addr.sin_addr.s_addr);

							struct timeval timeout;      
							timeout.tv_sec = 1;
							timeout.tv_usec = 0;

							if(setsockopt (net_fd, SOL_SOCKET, SO_RCVTIMEO, (char *)&timeout, sizeof(timeout)) < 0){
								MM("%s %d setsockopt failed\n",__func__,__LINE__);
							}

							if (setsockopt (net_fd, SOL_SOCKET, SO_SNDTIMEO, (char *)&timeout, sizeof(timeout)) < 0){
								MM("%s %d setsockopt failed\n",__func__,__LINE__);
							}

							sfree(name,32);
						}else{
							MM("## FIND %s %d net_fd %d  %08x ##\n",__func__,__LINE__,net_fd,cli_addr.sin_addr.s_addr);
							close(net_fd);
						}
					}
				}
			}
		}
	}
	return ret;
}

int net_process(struct main_data *md,int net_fd,char *thread_name,uint32_t ipaddress)
{
	int ret=0;
	struct options *opt=NULL;
	opt = md->opt;

	struct pth_timer_data *p_t_d=NULL;
	p_t_d = malloc(sizeof(struct pth_timer_data));
	if(p_t_d == NULL){
		printf("##============================ ERR: EXIT %s %d ##\n",__func__,__LINE__);
		exit(0);
	}
	memset(p_t_d,0x00,sizeof(struct pth_timer_data));

	struct epoll_ptr_data *epd=NULL;
	epd = malloc(sizeof(struct epoll_ptr_data));
	if(epd == NULL){
		printf("## ERR:=============================== EXIT %s %d ##\n",__func__,__LINE__);
		exit(0);
	}
	memset(epd,0x00,sizeof(struct epoll_ptr_data));
	pthread_mutex_init(&epd->mutex,NULL);
	pthread_mutex_init(&epd->all_packet_cnt_mutex,NULL);
	pthread_mutex_init(&epd->send_idx_mutex,NULL);
	pthread_mutex_init(&epd->keynego_mutex,NULL);


	struct net_fd_data *n_fdd=NULL;
	n_fdd = malloc(sizeof(struct net_fd_data));
	if(n_fdd == NULL){
		printf("## ERR:=========================== EXIT %s %d ##\n",__func__,__LINE__);
		exit(0);
	}
	memset(n_fdd,0x00,sizeof(struct net_fd_data));
	pthread_mutex_init(&n_fdd->net_r_mutex,NULL);
	pthread_mutex_init(&n_fdd->net_w_mutex,NULL);

	n_fdd->net_rfd	= net_fd;
	n_fdd->net_wfd	= n_fdd->net_rfd;

	struct ssl_state *ss=NULL;
	ss = malloc(sizeof(struct ssl_state));
	if(ss == NULL){
		printf("## ERR:=============== EXIT %s %d ##\n",__func__,__LINE__);
		exit(0);
	}
	memset(ss,0x00,sizeof(struct ssl_state));
	ss->keyid = 0;
	ss->sk[ss->keyid].state = S_INITIAL;
#if 0
	ss->ping_keyid_change = false;
	pthread_mutex_init(&ss->ss_mutex,NULL);
	pthread_mutex_init(&ss->ping_keyid_change_mutex,NULL);
#endif

	struct ping_state *pc=NULL;
	pc = malloc(sizeof(struct ping_state));
	if(pc == NULL){
		printf("## ERR: EXIT %s %d ##\n",__func__,__LINE__);
		exit(0);
	}
	memset(pc,0x00,sizeof(struct ping_state));
	pthread_mutex_init(&pc->ping_check_mutex,NULL);


	struct packet_id_idx *pii=NULL;	
	pii = malloc(sizeof(struct packet_id_idx));
	if(pii == NULL){
		printf("## ERR: EXIT %s %d ##\n",__func__,__LINE__);
		exit(0);
	}
	memset(pii,0x00,sizeof(struct packet_id_idx));
	pthread_mutex_init(&pii->ssl_send_idx_mutex,NULL);
	pthread_mutex_init(&pii->data_send_idx_mutex,NULL);

	struct push_state *ps=NULL;	
	ps = malloc(sizeof(struct push_state));
	if(ps == NULL){
		printf("## ERR: EXIT %s %d ##\n",__func__,__LINE__);
		exit(0);
	}
	memset(ps,0x00,sizeof(struct push_state));
	pthread_mutex_init(&ps->ps_mutex,NULL);

#if 0
	struct net_idx_tree * nit;
	nit = malloc(sizeof(struct net_idx_tree));
	memset(nit,0x00,sizeof(struct net_idx_tree));
	nit->net_idx = 0;
	pthread_mutex_init(&nit->net_idx_mutex,NULL);
	nit->net_idx_tree = rb_create((void *)packet_idx_compare,NULL,NULL,"net_idx_tree");
	pthread_mutex_init(&nit->net_idx_tree_mutex,NULL);
	epd->nit = nit;
#endif

	epd->ss 	= ss;
	epd->pc 	= pc;
	epd->pii = pii;
	epd->ps 	= ps;

	epd->epoll_fd = epoll_init(NET_TUN_MAX_EVENTS);
	if(epoll_add(epd->epoll_fd,n_fdd->net_rfd,0) < 0){
		printf("##ERR: EXIT %s %d epoll_fd %d net_rfd %d ##\n",__func__,__LINE__,epd->epoll_fd,n_fdd->net_rfd);
		exit(0);
	}

	epd->t_fdd	= NULL;
	epd->p_fdd	= NULL; //p_fdd;
	epd->n_fdd	= n_fdd;

	epd->tp_fdd	= NULL;
	epd->np_fdd	= NULL;
	epd->thd_mode	= THREAD_NET;

	epd->gl_var 					= (void *)md;
	epd->in_handle_func			= net_FD_recv_handle;
	epd->out_handle_func			= NULL;
	epd->pipe_in_handle_func	= NULL;//net_PIPE_recv_handle;
	epd->pipe_out_handle_func	= NULL;

	p_t_d->func 			= rain_timer_start;
	p_t_d->start_func 	= (void *)packet_thd;
	p_t_d->sec 				= 0;
	p_t_d->nsec				= 0;
	p_t_d->ptr 				= (void *)epd;
	sprintf(p_t_d->name,"%s",thread_name);
	sprintf(epd->name,"%s",thread_name);
	epd->ipaddress = ipaddress;
#if 1
	//p_t_d->timer_status  = 1;
	rain_timer_init(p_t_d);

	epd->all_packet_cnt = 0;

	if(opt->mode == SERVER){
		struct user_data *ud=malloc(sizeof(struct user_data));
		if(ud == NULL){
			printf("## ERR: EXIT %s %d ##\n",__func__,__LINE__);
			exit(0);
		}
		memset(ud,0x00,sizeof(struct user_data));

		struct user_data *pud=NULL;
		struct user_data *plud=NULL;

		ud->key = net_fd;
		ud->epd = epd;

		pthread_mutex_lock(&opt->ct_tree_mutex);
		pud = rb_find(opt->ct_tree,ud);
		pthread_mutex_unlock(&opt->ct_tree_mutex);
		sfree(ud,sizeof(struct user_data));
		if(pud != NULL){
			pthread_mutex_lock(&opt->ct_tree_mutex);
			rb_delete(opt->ct_tree,pud,true,sizeof(struct user_data));
			pthread_mutex_unlock(&opt->ct_tree_mutex);
		}
		pud = NULL;
		pud = malloc(sizeof(struct user_data));
		if(pud == NULL){
			printf("## ERR: EXIT %s %d ##\n",__func__,__LINE__);
			exit(0);
		}
		memset(pud,0x00,sizeof(struct user_data));
		pud->key = net_fd;
		pud->epd = epd;

		pthread_mutex_lock(&opt->ct_tree_mutex);
		rb_insert(opt->ct_tree,pud);
		pthread_mutex_unlock(&opt->ct_tree_mutex);

		plud = malloc(sizeof(struct user_data));
		if(plud == NULL){
			printf("## ERR: EXIT %s %d ##\n",__func__,__LINE__);
			exit(0);
		}
		memset(plud,0x00,sizeof(struct user_data));
		plud->key = net_fd;
		plud->epd = epd;

		pthread_mutex_lock(&md->li_mutex);
		input_list(md->li,(char *)plud);
		pthread_mutex_unlock(&md->li_mutex);

		//MM("## %s %s[:%d] ## NET thread start netfd %d ##\n",__FILE__,__func__,__LINE__,n_fdd->net_rfd);
	}else if(opt->mode == CLIENT){

		if(md->recv_wait == true){
			md->recv_wait = false;
		}
		md->net_epd = epd;

		//MM("## %s %s[:%d] ## NET thread start netfd %d ##\n",__FILE__,__func__,__LINE__,n_fdd->net_rfd);
		while(1){
			sleep(1);
			if(epd->stop == 1){
				MM("## %s %s[:%d] ## NET thread top netfd %d ##\n",__FILE__,__func__,__LINE__,n_fdd->net_rfd);
				break;
			}
		}
		md->net_epd = NULL;

		printf("## start %s %d =============================================================================\n",__func__,__LINE__);

		delete_routes(md->opt->route_list,md->opt->route_ipv6_list,md->opt,0);

		free(md->opt->routes);
		md->opt->routes = NULL;
		printf("## end %s %d =============================================================================\n",__func__,__LINE__);
		//sfree(epd,sizeof(struct epoll_ptr_data));
	}
#endif

	return ret;
}


int pipe_process(struct main_data *md){
	int ret=0;
	struct options *opt=NULL;
	opt = md->opt;
	struct pth_timer_data *p_t_d[opt->core];
	struct epoll_ptr_data *epd[opt->core];

	unsigned int i=0;
	int x=0;
	char name[32]={0,};

	pthread_mutex_init(&md->work_in_out_mutex,NULL);
	pthread_mutex_init(&md->work_out_in_mutex,NULL);


	for(x=0;x<2;x++){
		for(i=0;i<opt->core;i++){
			p_t_d[i] =malloc(sizeof(struct pth_timer_data));
			if(p_t_d[i] == NULL){
				printf("## ERR: EXIT %s %d ##\n",__func__,__LINE__);
				exit(0);
			}
			memset(p_t_d[i],0x00,sizeof(struct pth_timer_data));
			epd[i] = malloc(sizeof(struct epoll_ptr_data));
			if(epd[i] == NULL){
				printf("## ERR: EXIT %s %d ##\n",__func__,__LINE__);
				exit(0);
			}
			memset(epd[i],0x00,sizeof(struct epoll_ptr_data));
			pthread_mutex_init(&epd[i]->mutex,NULL);
			pthread_mutex_init(&epd[i]->all_packet_cnt_mutex,NULL);
			pthread_mutex_init(&epd[i]->send_idx_mutex,NULL);


			struct pipe_fd_data *p_fdd=NULL;
			p_fdd = malloc(sizeof(struct pipe_fd_data));
			if(p_fdd == NULL){
				printf("## ERR: EXIT %s %d ##\n",__func__,__LINE__);
				exit(0);
			}
			memset(p_fdd,0x00,sizeof(struct pipe_fd_data));
			pthread_mutex_init(&p_fdd->pipe_r_mutex,NULL);
			pthread_mutex_init(&p_fdd->pipe_w_mutex,NULL);

			epd[i]->epoll_fd = epoll_init(PIPE_MAX_EVENTS);

			epd[i]->t_fdd		= NULL;
			epd[i]->p_fdd		= NULL;
			epd[i]->n_fdd		= NULL;
			epd[i]->gl_var 	= (void *)md;

			if(x == 0){
				epd[i]->idx			= i;
				epd[i]->tp_fdd		= p_fdd;
				epd[i]->np_fdd		= NULL;
				epd[i]->thd_mode	= THREAD_PIPE_IN_OUT;

				epd[i]->out_handle_func		= NULL;
				epd[i]->in_handle_func		= pipe_RECV_handle;

				epd[i]->pipe_out_handle_func	= NULL;
				epd[i]->pipe_in_handle_func	= NULL;

				sprintf(name,"work_in_out_%d",i);
				sprintf(p_t_d[i]->name,name);
				sprintf(epd[i]->name,name);
				md->work_in_out_epd[i] = epd[i];
				pipe(epd[i]->tp_fdd->pipe_fd);
				epd[i]->tp_fdd->pipe_rfd = epd[i]->tp_fdd->pipe_fd[0];
				epd[i]->tp_fdd->pipe_wfd = epd[i]->tp_fdd->pipe_fd[1];
				epoll_add(epd[i]->epoll_fd,epd[i]->tp_fdd->pipe_rfd,0);	
			}else if(x == 1){
				epd[i]->idx			= i;
				epd[i]->tp_fdd		= NULL;
				epd[i]->np_fdd		= p_fdd;
				epd[i]->thd_mode	= THREAD_PIPE_OUT_IN;

				epd[i]->out_handle_func		= NULL;
				epd[i]->in_handle_func		= pipe_RECV_handle;

				epd[i]->pipe_out_handle_func	= NULL;
				epd[i]->pipe_in_handle_func	= NULL;

				sprintf(name,"work_out_in_%d",i);
				sprintf(p_t_d[i]->name,name);
				sprintf(epd[i]->name,name);
				md->work_out_in_epd[i] = epd[i];
				pipe(epd[i]->np_fdd->pipe_fd);
				epd[i]->np_fdd->pipe_rfd = epd[i]->np_fdd->pipe_fd[0];
				epd[i]->np_fdd->pipe_wfd = epd[i]->np_fdd->pipe_fd[1];
				epoll_add(epd[i]->epoll_fd,epd[i]->np_fdd->pipe_rfd,0);	
			}

			p_t_d[i]->func 		= rain_timer_start;
			p_t_d[i]->start_func	= (void *)packet_thd;
			p_t_d[i]->sec 			= 0;
			p_t_d[i]->nsec			= 0;
			p_t_d[i]->ptr 			= (void *)epd[i];
			//p_t_d[i]->timer_status  = 1;
			rain_timer_init(p_t_d[i]);

		}
	}
	return ret;
}



int tun_process(struct main_data *md){
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


	struct tun_fd_data *t_fdd=NULL;
	t_fdd = malloc(sizeof(struct tun_fd_data));
	if(t_fdd == NULL){
		printf("## ERR: EXIT %s %d ##\n",__func__,__LINE__);
		exit(0);
	}
	memset(t_fdd,0x00,sizeof(struct tun_fd_data));
	pthread_mutex_init(&t_fdd->tun_r_mutex,NULL);
	pthread_mutex_init(&t_fdd->tun_w_mutex,NULL);

	t_fdd->tun_rfd	= tun_open((char *)opt->dev,dev_type_enum (opt->dev, opt->dev_type));
	t_fdd->tun_wfd	= t_fdd->tun_rfd;
#if 0
	struct pipe_fd_data *p_fdd=NULL;
	p_fdd = malloc(sizeof(struct pipe_fd_data));
	memset(p_fdd,0x00,sizeof(struct pipe_fd_data));
	pthread_mutex_init(&p_fdd->pipe_r_mutex,NULL);
	pthread_mutex_init(&p_fdd->pipe_w_mutex,NULL);

	pipe(p_fdd->pipe_fd);
	p_fdd->pipe_rfd = p_fdd->pipe_fd[0];
	p_fdd->pipe_wfd = p_fdd->pipe_fd[1];
#endif
	epd->epoll_fd = epoll_init(NET_TUN_MAX_EVENTS);
	epoll_add(epd->epoll_fd,t_fdd->tun_rfd,0);

	epd->t_fdd		= t_fdd;
	epd->p_fdd		= NULL;//p_fdd;
	epd->n_fdd		= NULL;

	epd->tp_fdd		= NULL;
	epd->np_fdd		= NULL;
	epd->thd_mode	= THREAD_TUN;

	epd->gl_var 					= (void *)md;
	epd->in_handle_func			= tun_FD_recv_handle;
	epd->out_handle_func			= NULL;
	epd->pipe_in_handle_func	= NULL;//tun_PIPE_recv_handle;
	epd->pipe_out_handle_func	= NULL;

	p_t_d->func 		= rain_timer_start;
	p_t_d->start_func	= (void *)packet_thd;
	p_t_d->sec 			= 0;
	p_t_d->nsec			= 0;
	p_t_d->ptr 			= (void *)epd;
	sprintf(p_t_d->name,"tun_thread");
	sprintf(epd->name,"tun_thread");

	//p_t_d->timer_status  = 1;

	rain_timer_init(p_t_d);

	md->tun_epd = epd;

	if(opt->mode == SERVER){
		do_ifconfig(epd);
		if(md->opt->routes && md->opt->route_list){
			do_init_route_list(epd,md->opt);
			print_route_options (md->opt->routes);
			add_routes(md->opt->route_list,md->opt->route_ipv6_list,md->opt,0);
		}


		struct user_data ud;
		struct user_data *pud=NULL;
		struct user_data *plud=NULL;
		ud.key = t_fdd->tun_fd;
		ud.epd = epd;

		pthread_mutex_lock(&opt->ct_tree_mutex);
		pud = rb_find(opt->ct_tree,&ud);
		pthread_mutex_unlock(&opt->ct_tree_mutex);
		if(pud != NULL){
			pthread_mutex_lock(&opt->ct_tree_mutex);
			rb_delete(opt->ct_tree,pud,true,sizeof(struct user_data));
			pthread_mutex_unlock(&opt->ct_tree_mutex);
		}
		pud=NULL;
		pud = malloc(sizeof(struct user_data));
		if(pud == NULL){
			printf("## ERR: EXIT %s %d ##\n",__func__,__LINE__);
			exit(0);
		}
		memset(pud,0x00,sizeof(struct user_data));
		pud->key = t_fdd->tun_fd;
		pud->epd = epd;

		plud = malloc(sizeof(struct user_data));
		if(plud == NULL){
			printf("## ERR: EXIT %s %d ##\n",__func__,__LINE__);
			exit(0);
		}
		memset(plud,0x00,sizeof(struct user_data));
		plud->key = t_fdd->tun_fd;
		plud->epd = epd;

		input_list(md->li,(char *)plud);

		pthread_mutex_lock(&opt->ct_tree_mutex);
		rb_insert(opt->ct_tree,pud);
		pthread_mutex_unlock(&opt->ct_tree_mutex);

	}
	//MM("## %s %d ## TUN thread start tunfd %d pipe_rfd %d pipe_wfd %d ##\n",__func__,__LINE__,t_fdd->tun_rfd,p_fdd->pipe_rfd,p_fdd->pipe_wfd);
	MM("## %s %d ##  %d ##\n",__func__,__LINE__,t_fdd->tun_rfd);
	return ret;
}



int packet_thd(struct pth_timer_data *p_t_d)
{
	int ret=0;
	int tun_net_pipe_fd=0;
	int epoll_ret=0;
	bool loop = true;
	struct epoll_ptr_data *epd = NULL;
	epd = (struct epoll_ptr_data *)p_t_d->ptr;

	struct main_data *md = NULL;
	md = (struct main_data *)epd->gl_var;
	struct options *opt=NULL;
	opt = md->opt;

	uint32_t ipaddress = 0;

	struct timeval time;
#if 0
	struct timeval *time = malloc(sizeof(struct timeval));
	memset(time,0x00,sizeof(struct timeval));
	gettimeofday(time,NULL);
#endif

	int ft_s=0;
	int lt_s=0;

	int ping_ft_s=0;
	//int ping_lt_s=0;

	//struct timeval T_time;
#if 0
	struct timeval *T_time = malloc(sizeof(struct timeval));
	memset(T_time,0x00,sizeof(struct timeval));
	gettimeofday(T_time,NULL);
#endif
	//int T_ft_s=0;
	//int T_lt_s=0;
	int renego_sec_time = 0;

	struct list_data *now=NULL;

	int i=0;
	//int f_ping_cnt = 0;

	if(epd->thd_mode == THREAD_TUN){
		tun_net_pipe_fd = epd->t_fdd->tun_rfd;
	}else if(epd->thd_mode == THREAD_NET){
		tun_net_pipe_fd = epd->n_fdd->net_rfd;
	}else if(epd->thd_mode == THREAD_PIPE_IN_OUT){
		tun_net_pipe_fd = epd->tp_fdd->pipe_rfd;
	}else if(epd->thd_mode == THREAD_PIPE_OUT_IN){
		tun_net_pipe_fd = epd->np_fdd->pipe_rfd;
	}

	int ping_ret = 0;
	int init_ret = 0;	

	int ping_time = 0;

	ft_s = get_sec(&time);
	while(loop){
		ping_ret = 0 ;
		init_ret = 0;
		if(epd->stop == 0){
			epoll_ret = epoll_event_exec(epd,tun_net_pipe_fd);
			if((epoll_ret & 0xffff) & RET_EPOLL_ERR){
				//MM("##ERR: %s %s[:%d] ## %s RET_EPOLL_ERR %08x ##\n",__FILE__,__func__,__LINE__,epd->name,epoll_ret);
				if(epd->thd_mode == THREAD_NET){
					//loop = false;
				}
			}

			if(((epoll_ret & 0xffff0000)>>16) & RET_EPOLL_ERR){
				//MM("##ERR: %s %s[:%d] ## %s RET_EPOLL_ERR %08x ##\n",__FILE__,__func__,__LINE__,epd->name,epoll_ret);
				if(epd->thd_mode == THREAD_NET){
					//loop = false;
				}
			}

			if((epoll_ret & 0xffff) & RET_EPOLL_RECV_ERR){
				//MM("##ERR: %s %s[:%d] ## %s RET_EPOLL_RECV_ERR %08x ##\n",__FILE__,__func__,__LINE__,epd->name,epoll_ret);
				if(epd->thd_mode == THREAD_NET){
					//MM("##ERR: %s %s[:%d] ## %s RET_EPOLL_RECV_ERR %08x ##\n",__FILE__,__func__,__LINE__,epd->name,epoll_ret);
					epd->kill = true;
					loop = false;
				}
			}

			if(((epoll_ret & 0xffff0000)>>16) & RET_EPOLL_RECV_ERR){
				//MM("##ERR: %s %s[:%d] ## %s RET_EPOLL_RECV_ERR %08x ##\n",__FILE__,__func__,__LINE__,epd->name,epoll_ret);
				if(epd->thd_mode == THREAD_NET){
					loop = false;
				}
			}
		}
		if(epd->thd_mode == THREAD_NET && epd->stop == 0){
			if(opt->mode == CLIENT){
				if(epd->ss->sk[epd->ss->keyid].state == S_INITIAL){
					printf("## %s %d ##\n",__func__,__LINE__);
					init_ret = process(epd,NULL,0,NULL,0);
					if(init_ret < 0){
						MM("## ERR: %s %d ##\n",__func__,__LINE__);
					}
				}
			}
#if 1
			pthread_mutex_lock(&epd->pc->ping_check_mutex);
			if(epd->pc->ping_f_last_time.tv_sec > 0){
				ping_time = (epd->pc->ping_l_last_time.tv_sec - epd->pc->ping_f_last_time.tv_sec);
				if(ping_time > (md->opt->keepalive_ping)){
					epd->pc->ready = true;
					MM("#################### true  %s %d LAST time = %d ####\n",__func__,__LINE__,ping_time);
					//epd->stop = 1;
					//loop = false;
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

			gettimeofday(&time,NULL);
			lt_s = get_sec(&time);
			if(ft_s != lt_s){
				if(opt->mode == SERVER){
					if(ping_ft_s == md->opt->keepalive_ping){

						if(epd->ss->sk[epd->ss->keyid].state == S_NORMAL_OP){
							//printf("## %s %d ping send ###\n",__func__,__LINE__);
							ping_ret = ping_SEND_handle(epd);
							if(ping_ret < 0){
								MM("## ERR: %s %d ##\n",__func__,__LINE__);
							}
						}
						ping_ft_s = 0;
					}else{
						ping_ft_s++;
					}


					if(epd->ss->sk[epd->ss->keyid].state == S_NORMAL_OP){
						if(epd->ss->renego_again == false){
							renego_sec_time++;
						}else{
							renego_sec_time = 0;

						}
					}

					if(renego_sec_time == md->opt->renegotiate_seconds){
						renego_sec_time = 0;
						epd->ss->renego_again = true;
						process(epd,NULL,0,NULL,0);
						//printf("####### %s %d %s renego_keyid %d ###\n",__func__,__LINE__,epd->name,epd->ss->renego_keyid);
					}

					if((epd->ss->sk[epd->ss->renego_keyid].state == S_ACTIVE) && (epd->ps->push_reply == true) && (epd->ss->renego_success == true)){

						epd->ss->keyid = epd->ss->renego_keyid;
						epd->ss->sk[epd->ss->keyid].state = S_NORMAL_OP;
						renego_sec_time = 0;
						pthread_mutex_lock(&epd->keynego_mutex);
						epd->keynego = false;
						pthread_mutex_unlock(&epd->keynego_mutex);
					}

				}


				if(opt->mode == CLIENT){
					if(epd->stop == 1){
							MM("## disconnect %s %d ##\n",__func__,__LINE__);
							exit(0);
					}
					if(epd->ss->sk[epd->ss->keyid].state == S_NORMAL_OP){
						ping_ret = ping_SEND_handle(epd);
						if(ping_ret < 0){
							MM("## ERR: %s %d ##\n",__func__,__LINE__);
						}else{
							pthread_mutex_lock(&epd->pc->ping_check_mutex);
							if(epd->pc->ping_check == false && md->opt->keepalive_ping > 0 ){
							}else{
								epd->pc->ping_check = false;
							}
							pthread_mutex_unlock(&epd->pc->ping_check_mutex);
						}
						renego_sec_time++;
					}

					if(epd->ss->sk[epd->ss->keyid].state == S_ACTIVE){
						if(epd->ps->push_request == false){
							int ctl_ret = 0;
							//char ctl_out[4096]={0,};
							char *ctl_out = malloc(4096);
							if(ctl_out == NULL){
								printf("## ERR: EXIT %s %d ##\n",__func__,__LINE__);
								exit(0);
							}
							memset(ctl_out,0x00,4096);
							ctl_ret = ctl_msg_request_process(epd,ctl_out,SSL_REQUEST);
							if(ctl_ret > 0){
								key_state_write_plaintext_const(epd->ss->sk[epd->ss->keyid].ks_ssl,ctl_out,ctl_ret);
							}
							sfree(ctl_out,4096);
						}else{
						}

						ret = process(epd,NULL,0,NULL,0);
					}
					if((epd->ss->sk[epd->ss->renego_keyid].state == S_ACTIVE) && (epd->ps->push_request == true)){
						//MM("## %s %d keyid %d renego_keyid %d %d ##\n",__func__,__LINE__,epd->ss->keyid,epd->ss->renego_keyid,epd->ss->sk[epd->ss->renego_keyid].state);
						epd->ss->sk[epd->ss->renego_keyid].state = S_NORMAL_OP;
						epd->ss->keyid = epd->ss->renego_keyid;
						renego_sec_time = 0;
						pthread_mutex_lock(&epd->keynego_mutex);
						epd->keynego = false;
						pthread_mutex_unlock(&epd->keynego_mutex);
					}

					if(renego_sec_time == md->opt->renegotiate_seconds){
						renego_sec_time = 0;

#if 0
						epd->ss->renego_again = true;
						process(epd,NULL,0,NULL,0);
#endif
					}


				}
				ft_s = lt_s;
			}
		}
		if(epd->thd_mode == THREAD_NET && epd->stop == 1){
			if(md->opt->mode == SERVER){
#if 0
				unsigned long all_packet_cnt = 0;
				pthread_mutex_lock(&epd->all_packet_cnt_mutex);
				all_packet_cnt = epd->all_packet_cnt;
				pthread_mutex_unlock(&epd->all_packet_cnt_mutex);
#endif
				struct user_data *pud=NULL;
				struct user_data *ud=malloc(sizeof(struct user_data));
				if(ud == NULL){
					printf("##============================ ERR: EXIT %s %d ##\n",__func__,__LINE__);
					exit(0);
				}
				memset(ud,0x00,sizeof(struct user_data));

				ud->key = epd->n_fdd->net_rfd;

				pthread_mutex_lock(&md->opt->ct_tree_mutex);
				pud = rb_find(md->opt->ct_tree,ud);
				sfree(ud,sizeof(struct user_data));

				if(pud != NULL){
					rb_delete(md->opt->ct_tree,pud,true,sizeof(struct user_data));
				}
				pthread_mutex_unlock(&md->opt->ct_tree_mutex);
				pud = NULL;

				pthread_mutex_lock(&md->li_mutex);
				for(i=0,now = md->li->next; now; now=now->next,i++){
					if(now == NULL){
						//MM("## %s %s[:%d] S %s D NULL ##\n",__FILE__,__func__,__LINE__,epd->name);
						break;
					}

					pud = (struct user_data *)now->data;

					if(pud->epd == NULL){
						//MM("## %s %s[:%d] S %s D NULL ##\n",__FILE__,__func__,__LINE__,epd->name);
						del_list(md->li,now);
						continue;
					}

					if(pud->epd == epd){
						del_list(md->li,now);
						if(now->data != NULL){
							sfree(now->data,sizeof(struct user_data));
							now->data = NULL;
						}
						break;
					}
				}
				pthread_mutex_unlock(&md->li_mutex);

				pthread_mutex_lock(&epd->n_fdd->net_w_mutex);
				pthread_mutex_lock(&epd->n_fdd->net_r_mutex);
				epoll_ctl(epd->epoll_fd,EPOLL_CTL_DEL,epd->n_fdd->net_rfd,NULL);
				close(epd->n_fdd->net_rfd);
				close(epd->epoll_fd);
				pthread_mutex_unlock(&epd->n_fdd->net_w_mutex);
				pthread_mutex_unlock(&epd->n_fdd->net_r_mutex);

			}
		}
	}
	//MM("## %s %d all_packet_cnt %ld stop %d ##\n",__func__,__LINE__,(long)epd->all_packet_cnt,epd->stop);

	if(epd->thd_mode == THREAD_NET){
		ft_s=0;
		lt_s=0;
		int end_time=0;
		struct timeval tv;
		gettimeofday(&tv,NULL);
		ft_s = get_sec(&tv);
		while(1){
			gettimeofday(&tv,NULL);
			lt_s = get_sec(&tv);
			if(ft_s != lt_s){
				ft_s = lt_s;
				if(end_time == 3){
					break;
				}else{
					end_time++;
				}
			}
		}

		if(md->opt->mode == SERVER){
			dz_pthread_mutex_destroy(&epd->n_fdd->net_r_mutex);
			dz_pthread_mutex_destroy(&epd->n_fdd->net_w_mutex);
			sfree(epd->n_fdd,sizeof(struct net_fd_data));
			epd->n_fdd = NULL;
		}else if(md->opt->mode == CLIENT){

		}

		key_state_ssl_remove(epd,true);
		if(epd->ss->common_name != NULL){
			sfree(epd->ss->common_name,epd->ss->common_name_length);
			epd->ss->common_name = NULL;
		}
		int c = 0;
		for(c = 0; c < MAX_CERT_DEPTH ;c++){
			if(epd != NULL && epd->ss != NULL && epd->ss->cert_hash_set != NULL && epd->ss->cert_hash_set->ch[c] != NULL){
				sfree(epd->ss->cert_hash_set->ch[c],sizeof(struct cert_hash));
				epd->ss->cert_hash_set->ch[c] = NULL;
			}
		}

		if(epd != NULL && epd->ss != NULL && epd->ss->cert_hash_set != NULL){
			sfree(epd->ss->cert_hash_set,sizeof(struct cert_hash_set));
			epd->ss->cert_hash_set = NULL;
		}
		sfree(epd->ss,sizeof(struct ssl_state));
		epd->ss = NULL;

		dz_pthread_mutex_destroy(&epd->pc->ping_check_mutex);
		sfree(epd->pc,sizeof(struct ping_state));
		epd->pc = NULL;

		dz_pthread_mutex_destroy(&epd->pii->ssl_send_idx_mutex);
		dz_pthread_mutex_destroy(&epd->pii->data_send_idx_mutex);
		sfree(epd->pii,sizeof(struct packet_id_idx));
		epd->pii = NULL;

		dz_pthread_mutex_destroy(&epd->ps->ps_mutex);
		sfree(epd->ps,sizeof(struct push_state));
		epd->ps = NULL;
		
		epd->gl_var = NULL;
		dz_pthread_mutex_destroy(&epd->all_packet_cnt_mutex);
		dz_pthread_mutex_destroy(&epd->send_idx_mutex);
		dz_pthread_mutex_destroy(&epd->mutex);
		ipaddress = epd->ipaddress;
		p_t_d->ptr = NULL;

		if(md->opt->mode == SERVER){
				struct user_data ud;
				struct user_data *pud;
				ud.key = ipaddress;
				//memcpy(&ud.key,ipaddress,4);
				pthread_mutex_lock(&opt->client_tree_mutex);

				pud = rb_find(opt->client_tree,&ud);
				if(pud != NULL){
					rb_delete(opt->client_tree,pud,true,sizeof(struct user_data));
					pud->epd = NULL;
				}else{
					printf("####### client_tree not found %08x ####\n",ipaddress);
				}
				pthread_mutex_unlock(&opt->client_tree_mutex);
		}
	}
	p_t_d->timer_status = 1;
	MM("## %s %d END thread %s  ##\n",__func__,__LINE__,epd->name);
	sfree(epd,sizeof(struct epoll_ptr_data));

	return ret;
}

