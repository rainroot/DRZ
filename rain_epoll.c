#include <rain_common.h>

int setnonblocking(int fd,int blocking)
{
#if 1
	int flags=0;
	int ret=0;
	//blocking=0;
	if (fd < 0){
		return -1;
	}

	flags = fcntl(fd, F_GETFL, 0);
	if (flags < 0){
		ret = -1;
	}else{

		if(blocking == 0){
			flags = (flags&~O_NONBLOCK);
		}else if(blocking == 1){
			flags = (flags|O_NONBLOCK);
		}

		ret = fcntl(fd, F_SETFL, flags);

		if(ret == 0){
			ret = 0;
		}else{
			ret = -1;
		}
	}
	return  ret;
#else
	return 0;
#endif
}

int epoll_init(int epoll_cnt)
{
	int epoll_fd;
	int ret=0;

	epoll_fd = epoll_create(epoll_cnt);
	if(epoll_fd < 0)
	{
		MM("Epoll create Fails.%d \n",epoll_fd);
		ret=-1;
	}
	ret = epoll_fd;
	return ret;
}


int epoll_add(int epoll_fd,int fd,int flags)
{
	int ret=0;
	struct epoll_event events;

	if(flags == 1){
		events.events = EPOLLIN | EPOLLET ;
	}else{
		events.events = EPOLLIN ;
	}
	events.data.fd = fd;

	if(epoll_ctl(epoll_fd, EPOLL_CTL_ADD, fd, &events) < 0 )
	{
		MM("ERR: EXIT() Epoll control fails[%s][%d]. epoll_fd %d fd %d \n",__func__,__LINE__,epoll_fd,fd);
		close(epoll_fd);
		ret=-1;
		//exit(0);
	}

	return ret;
}

int get_sec(struct timeval *ptime)
{
	struct tm ptm;
	localtime_r((time_t *)&ptime->tv_sec,&ptm);
	return ptm.tm_sec;
}


unsigned long epoll_event_exec(struct epoll_ptr_data *epd,int net_tun_pipe_fd)
{

	int nfds=0;
	int i=0;
	unsigned long ret = 0;

	int event_count = 0;

	if(epd->thd_mode == THREAD_NET || epd->thd_mode == THREAD_TUN){
		event_count = NET_TUN_MAX_EVENTS;
	}else{
		event_count = PIPE_MAX_EVENTS;
	}
	struct epoll_event events[event_count];

	//struct epoll_event *events = calloc(MAX_EVENTS,sizeof(struct epoll_event));
	int read_ret = 0;


	bool wait = false;

	struct main_data *md = NULL;
	md = (struct main_data *)epd->gl_var;
	struct options *opt = NULL;
	opt = md->opt;


#if 1
	//bool TPT_wait = false;
	//bool NPT_wait = false;
	//uint32_t TPT_idx=0;
	//uint32_t T_TPT_idx=0;
	//uint32_t NPT_idx=0;
	//uint32_t T_NPT_idx=0;
	uint32_t rb_count=0;

	struct timespec sleeptime;

#if 0
	if(opt->core > 1){
		if(epd->thd_mode == THREAD_NET){

			pthread_mutex_lock(&md->NPT_tree_mutex);
			rb_count = md->NPT_idx_tree->rb_count;
			pthread_mutex_unlock(&md->NPT_tree_mutex);

			if(rb_count > (opt->core - 1)){
				wait = true;
			}

		}else if(epd->thd_mode == THREAD_TUN){
			pthread_mutex_lock(&md->TPT_tree_mutex);
			rb_count = md->TPT_idx_tree->rb_count;
			pthread_mutex_unlock(&md->TPT_tree_mutex);

			if(rb_count > (opt->core -1)){
				wait = true;
			}
		}

	}else{
		wait = false;
	}
#endif

//	if(epd->thd_mode == THREAD_TUN){
		pthread_mutex_lock(&md->NPT_tree_mutex);
		rb_count = md->NPT_idx_tree->rb_count;
		pthread_mutex_unlock(&md->NPT_tree_mutex);

		pthread_mutex_lock(&md->TPT_tree_mutex);
		rb_count += md->TPT_idx_tree->rb_count;
		pthread_mutex_unlock(&md->TPT_tree_mutex);

		if(rb_count > (md->opt->mempool_cnt - 1024)){

			sleeptime.tv_sec = 0;
			sleeptime.tv_nsec = 100;

			wait = true;
		}else{
			wait = false;
		}
//	}
	if(epd->thd_mode == THREAD_TUN || epd->thd_mode == THREAD_NET){
		if(opt->mode == CLIENT){
			if(rb_count > 0){
				if(md->recv_wait == true){
					wait = true;
				}
			}
		}
	}
#else
	wait = false;
#endif
	if(wait == false){
		//nfds = epoll_wait(epd->epoll_fd,events,event_count,900);
		nfds = epoll_wait(epd->epoll_fd,events,event_count,1);
		if(nfds < 0 ){
		}else if(nfds == 0){
		}else{
			for(i=0;i<nfds;i++){
				if(events[i].data.fd == net_tun_pipe_fd){
					if(events[i].events & EPOLLIN){
						if(events[i].data.fd == net_tun_pipe_fd){
#if 0
							if(epd->thd_mode == THREAD_NET || epd->thd_mode == THREAD_TUN){
								MM("## %s %s[:%d] rb_count %d core %d TPT_idx %d NPT_idx %d  ##\n",__FILE__,__func__,__LINE__,md->G_packet_idx_tree->rb_count,opt->core,md->TPT_idx,md->NPT_idx);
							}
#endif
							read_ret = epd->in_handle_func(epd);
							ret |= RET_EPOLL_IN;
						}
						if(read_ret < 0){
							//MM("## ERR: %s %s[:%d] %s  read_ret %d ##\n",__FILE__,__func__,__LINE__,epd->name,read_ret);

							if(epd->thd_mode == THREAD_NET){
								MM("## ERR: %s %s[:%d] %s  read_ret %d ##\n",__FILE__,__func__,__LINE__,epd->name,read_ret);
								epd->stop = 1;
								if(opt->mode == CLIENT){
									md->recv_wait = true;
								}
								if(epoll_ctl(epd->epoll_fd,EPOLL_CTL_DEL,events[i].data.fd,&events[i]) < 0){
									MM("epoll_ctl error \n");
								}
							}else{
								//MM("# ERR: %s %s[:%d] %s  read_ret %d ##\n",__FILE__,__func__,__LINE__,epd->name,read_ret);
							}
							ret = RET_EPOLL_RECV_ERR;
						}
					}
				}
			}
		}
	}else{
		nanosleep(&sleeptime, NULL);
	}
	return ret;
}


