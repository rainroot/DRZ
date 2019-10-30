#include <rain_common.h>

void MM(char *fmt, ...)
{
#if 1
	va_list ap;
	char msg[4096]={0,};
	va_start(ap,fmt);
	vsprintf(msg+strlen(msg),fmt,ap);
	va_end(ap);
	syslog(LOG_INFO,"%s",msg);
#endif
}
#if 0
void dump_print_hex(char* data, int size)
{
	char ascii[17];
	int i, j;
	ascii[16] = '\0';
	for (i = 0; i < size; ++i) {
		printf("%02X ", ((unsigned char*)data)[i]);
		if (((unsigned char*)data)[i] >= ' ' && ((unsigned char*)data)[i] <= '~') {
			ascii[i % 16] = ((unsigned char*)data)[i];
		} else {
			ascii[i % 16] = '.';
		}
		if ((i+1) % 8 == 0 || i+1 == size) {
			printf(" ");
			if ((i+1) % 16 == 0) {
				printf("|  %s \n", ascii);
			} else if (i+1 == size) {
				ascii[(i+1) % 16] = '\0';
				if ((i+1) % 16 <= 8) {
					printf(" ");
				}
				for (j = (i+1) % 16; j < 16; ++j) {
					printf("   ");
				}
				printf("|  %s \n", ascii);
			}
		}
	}
}
#endif

void dump_print(int length, char *data){
	int i;
	for(i=0;i<length;i++){
		if((!(i%8)) && (i != 0)){
			printf("\n");
		}
		printf(" %02x ",(unsigned char)data[i]);
	}
	printf("\n");
}

bool gen_path (char *directory, char *filename,char *out)
{

	int CC_PATH_RESERVED = CC_SLASH;
	bool ret = false;
	char *safe_filename = malloc(strlen(filename)+1);
	memset(safe_filename,0x00,strlen(filename)+1);

	ret = string_mod_const (filename, CC_PRINT, CC_PATH_RESERVED, '_',safe_filename);

	if(ret == true){
		if (safe_filename && strcmp (safe_filename, ".") && strcmp (safe_filename, ".."))
		{
#if 0
			printf("## %s %d ##\n",__func__,__LINE__);
			size_t outsize = strlen(safe_filename) + (directory ? strlen (directory) : 0) + 16;
			char *out = malloc(outsize);
			memset(out,0x00,outsize);
			printf("## %s %d ##\n",__func__,__LINE__);
#endif
			if (directory){
				out += sprintf(out,"%s/",directory);
			}
			out += sprintf (out, "%s",safe_filename);

			free(safe_filename);
			return true;
		}else{
			free(safe_filename);
			return false;
		}

	}else{
		free(safe_filename);
		return false;
	}
}



int max_int (int x, int y)
{
	if (x > y){
		return x;
	}else{
		return y;
	}
}

int min_int (int x, int y)
{
	if (x < y){
		return x;
	}else{
		return y;
	}
}

bool compat_flag (unsigned int flag)
{
	static unsigned int compat_flags = 0;

	if (flag & COMPAT_FLAG_SET){
		compat_flags |= (flag >> 1);
	}

	return (compat_flags & (flag >> 1));
}



#if defined(__GNUC__)
#define likely(x)       __builtin_expect((x),1)
#define unlikely(x)     __builtin_expect((x),0)
#endif

size_t array_mult_safe (size_t m1, size_t m2, size_t extra)
{
	size_t limit = 0xFFFFFFFF;
	unsigned long long res = (unsigned long long)m1 * (unsigned long long)m2 + (unsigned long long)extra;
	if (unlikely(m1 > limit) || unlikely(m2 > limit) || unlikely(extra > limit) || unlikely(res > (unsigned long long)limit)){
		MM("attemped allocation of excessively large array\n");
	}
	return (size_t) res;
}



void run_up_down (struct options *opt, char *context)
{

	char cmd[1024]={0,};

	int tun_mtu = 1500;
	int link_mtu = 1500;
	const char *dev = NULL;

	dev = opt->dev;
printf("############################### %s %d ############\n",__func__,__LINE__);

	if (opt->up_script)
	{
		sprintf(cmd,"%s %s %d %d %s %s %s",
				opt->up_script,
				dev,
				tun_mtu,
				link_mtu,
				opt->ifconfig_local,
				opt->ifconfig_remote_netmask,
				context);
		system(cmd);
	}
}

#if 1
void get_ip_list(struct main_data *md){
	FILE *f;

	char line[128]={0,};
	char iface[32]={0,};

	unsigned int dest,gateway,netmask;
	int flags,refcnt,use,metric,mtu,win,irtt;

	int ret=0;
	int i = 0;
	f=fopen("/proc/net/route","r");
	if(f != NULL){

		while(fgets(line,100,f)){

			if(i > 0 && !(i%2)){

				ret = sscanf(line,"%s %x %x %x %u %d %d %x %d %d %d",iface,&dest,&gateway,&flags,&refcnt,&use,&metric,&netmask,&mtu,&win,&irtt);
				if(ret > 0){	
					if(dest != 0x0){

						struct ip_info *ii=NULL;
						ii = malloc(sizeof(struct ip_info));
						memset(ii,0x00,sizeof(struct ip_info));

						sprintf(ii->iface,"%s",iface);
						ii->ipaddr = dest;
						ii->netmask = netmask;

						input_list(md->ip_li,(char *)ii);	

						MM("### iface %s ip %08x netmask %08x gateway %08x ###\n",iface,dest,netmask,gateway);

					}
				}else{
					break;
				}

			}
			i++;
		}
	}else{
		MM("## ERR: %s %d not foun /proc/net/route \n",__func__,__LINE__);
	}

	fclose(f);
}
#endif
void main_sighandle(int signum)
{
	MM("REceived signal %d \n",signum);
}

void  sysctl_init(){
	system("modprobe tcp_htcp");
	system("sysctl -q -w net.ipv4.ip_forward=1");
	system("sysctl -q -w net.ipv4.conf.default.rp_filter=2");
	system("sysctl -q -w net.ipv4.conf.all.rp_filter=2");
	system("sysctl -q -w net.ipv4.conf.lo.rp_filter=0");
	system("sysctl -q -w net.ipv4.conf.eth0.rp_filter=0");
	system("sysctl -q -w net.ipv4.tcp_mem='8192 16777216 16777216'");
	system("sysctl -q -w net.ipv4.tcp_rmem='8192 16777216 16777216'");
	system("sysctl -q -w net.ipv4.tcp_wmem='8192 16777216 16777216'");
#if 1
	system("sysctl -q -w kernel.threads-max=2400000");
	system("sysctl -q -w vm.max_map_count=10000000");
	system("sysctl -q -w kernel.pid_max=2000000");
#endif
	system("sysctl -q -w net.ipv4.tcp_congestion_control=htcp");

	limit_max_set();
	limit_set();	
}



int process_init(struct main_data *md)
{
	struct tls_root_ctx *ctx;
	ctx = malloc(sizeof(struct tls_root_ctx));
	memset(ctx,0x00,sizeof(struct tls_root_ctx));
	md->ctx = ctx;

	struct network_info_sec *T_nis = NULL;
	T_nis = malloc(sizeof(struct network_info_sec));
	memset(T_nis,0x00,sizeof(struct network_info_sec));
	pthread_mutex_init(&T_nis->nis_mutex,NULL);
	md->T_nis = T_nis;	

	struct network_info_sec *N_nis = NULL;
	N_nis = malloc(sizeof(struct network_info_sec));
	memset(N_nis,0x00,sizeof(struct network_info_sec));
	pthread_mutex_init(&N_nis->nis_mutex,NULL);
	md->N_nis = N_nis;	

	md->TPT_idx = 1;
	pthread_mutex_init(&md->TPT_idx_mutex,NULL);
	md->T_TPT_idx = 1;
	pthread_mutex_init(&md->T_TPT_idx_mutex,NULL);
	md->TPT_idx_tree = rb_create((void *)packet_idx_compare,NULL,NULL,"TPT_idx_tree");
	pthread_mutex_init(&md->TPT_tree_mutex,NULL);

	md->NPT_idx = 1;
	pthread_mutex_init(&md->NPT_idx_mutex,NULL);
	md->T_NPT_idx = 1;
	pthread_mutex_init(&md->T_NPT_idx_mutex,NULL);
	md->NPT_idx_tree = rb_create((void *)packet_idx_compare,NULL,NULL,"NPT_idx_tree");
	pthread_mutex_init(&md->NPT_tree_mutex,NULL);

	rand_bytes((uint8_t *)md->session_id,8);

	init_key_type(&md->key_type,md->opt->ciphername,md->opt->authname,md->opt->keysize,false);

	init_ssl(md->ctx,md->opt);

#ifdef OPENSSL_CONF
	thread_setup();
#endif

#ifdef MEMPOLL_ENABLE
	struct mempool *pitd_mp = mempool_create(sizeof(struct packet_idx_tree_data),md->opt->mempool_cnt);
	md->pitd_mp = pitd_mp;
#endif
	sysctl_init();

	drizzle_status(md);

	send_thread_process(md,THREAD_SEND_NET);
	send_thread_process(md,THREAD_SEND_TUN);

#ifdef ENABLE_MANAGEMENT
	mngt_process(md);
#endif


	return 0;
}


void server_func(struct options *opt){
printf("============================================ %s %d ============================\n",__func__,__LINE__);
	/* open fd : net_fd ,tun_fd */
	struct socket_fd *sf;
	sf = malloc(sizeof(socket_fd_t));
	memset(sf, 0x00, sizeof(socket_fd_t));

	struct main_data *md;
	md = malloc(sizeof(main_data_t));
	memset(md,0x00,sizeof(main_data_t));
	pthread_mutex_init(&md->print_mutex,NULL);
	md->opt = opt;

	opt->user_ip_tree = rb_create((void *)user_ip_compare,NULL,NULL,"user_ip_tree");
	if(opt->user_ip_tree == NULL){
		printf("ERR: %s %d  EXIT user_ip_tree NULL \n",__func__,__LINE__);
		exit(0);
	}
	pthread_mutex_init(&opt->user_ip_tree_mutex,NULL);
#if 1
	if(dev_type_enum (md->opt->dev, md->opt->dev_type) == DEV_TYPE_TUN){
		opt->user_tree = rb_create((void *)uint32_compare,NULL,NULL,"user_tree");
	}else{
		opt->user_tree = rb_create((void *)user_compare,NULL,NULL,"user_tree");
	}
#endif
	if(opt->user_tree == NULL){
		printf("ERR: %s %d  EXIT user_tree NULL \n",__func__,__LINE__);
		exit(0);
	}
	pthread_mutex_init(&opt->user_tree_mutex,NULL);

	opt->ct_tree = rb_create((void *)ct_compare,NULL,NULL,"ct_tree");
	if(opt->ct_tree == NULL){
		printf("ERR: %s %d  EXIT ct_tree NULL \n",__func__,__LINE__);
		exit(0);
	}
	pthread_mutex_init(&opt->ct_tree_mutex,NULL);

	opt->client_tree = rb_create((void *)client_compare,NULL,NULL,"client_tree");
	if(opt->client_tree == NULL){
		printf("ERR: %s %d  EXIT client_tree NULL \n",__func__,__LINE__);
		exit(0);
	}
	pthread_mutex_init(&opt->client_tree_mutex,NULL);

	md->li = list_init();
	pthread_mutex_init(&md->li_mutex,NULL);

	ifconfig_pool_read(opt);

	process_init(md);

	do_alloc_route_list(opt);

	sf->server_fd = tcp_server(NULL,opt->ce.local_port);
	if(sf->server_fd < 0){
		printf("ERR: server fd %s %d ##\n",__func__,__LINE__);
		exit(0);
	}
	sf->epoll_fd = epoll_init(SERVER_MAX_EVENTS);
	epoll_add(sf->epoll_fd,sf->server_fd,0);

	tun_process(md);
	pipe_process(md);

	server_process(md,sf->epoll_fd,sf->server_fd);
}

void client_func(struct options *opt){
	/* open fd : net_fd,tun_fd */
	int idx = 0;
	struct socket_fd *sf;
	sf = malloc(sizeof(socket_fd_t));
	memset(sf, 0x00, sizeof(socket_fd_t));

	struct main_data *md=NULL;
	md = malloc(sizeof(main_data_t));
	memset(md,0x00,sizeof(main_data_t));
	pthread_mutex_init(&md->print_mutex,NULL);
	md->opt 		= opt;

#if 0
	md->li 		= list_init(); //struct user_data
	pthread_mutex_init(&md->li_mutex,NULL);
	md->ip_li	= list_init(); //struct ip_info
	get_ip_list(md);
#endif

	process_init(md);

	tun_process(md);
	pipe_process(md);


	while(1){
		MM("CLIENT MODE connect start\n");
		if(opt->remote_list->len > 0){
			for(idx = 0 ; idx < opt->remote_list->len; idx++){
				struct remote_entry *e = (struct remote_entry *)opt->remote_list->array[idx];

				sf->net_fd = tcp_connect(e->remote,e->remote_port,md);
				if(sf->net_fd < 0){
					MM("## ERR: Server Connecting Fail %s %d ##\n",__func__,__LINE__);
					sleep(5);
					continue;
				}
				do_alloc_route_list(md->opt);
				net_process(md,sf->net_fd,"net_thread",0);
				//tun_close(sf->tun_fd);
			}
		}else{
			sf->net_fd = tcp_connect(opt->ce.remote,opt->ce.local_port,md);
			if(sf->net_fd < 0){
				MM("## ERR: Server Connecting Fail %s %d ##\n",__func__,__LINE__);
				sleep(5);
				continue;
			}
			do_alloc_route_list(md->opt);
			net_process(md,sf->net_fd,"net_thread",0);
			//tun_close(sf->tun_fd);
		}
		sleep(5);
	}
}


int main(int argc,char *argv[])
{
	struct options *opt;
	opt = malloc(sizeof(options_t));
	memset(opt,0x00,sizeof(options_t));

	struct remote_list *remote_list;
	remote_list = malloc(sizeof(struct remote_list));
	memset(remote_list,0x00,sizeof(struct remote_list));
	opt->remote_list = remote_list;

	init_options(opt,false);
	parse_argv (opt, argc, argv, OPT_P_DEFAULT, NULL);

	options_postprocess (opt);
	//show_settings(opt);
	block_sigpipe();
	eng_init();

	signal(SIGTERM,main_sighandle);
	signal(SIGKILL,main_sighandle);


	if(opt->mode == SERVER){
		//sprintf(opt->str,"V4,dev-type tap,link-mtu 1539,tun-mtu 1532,proto TCPv4_SERVER,cipher [null-cipher],auth [null-digest],keysize 0,key-method 2,tls-server");
		server_func(opt);
	}else if(opt->mode == CLIENT){
		//sprintf(opt->str,"V4,dev-type tap,link-mtu 1575,tun-mtu 1532,proto TCPv4_CLIENT,cipher BF-CBC,auth SHA1,keysize 128,key-method 2,tls-client");
		client_func(opt);
	}

	free(opt);
	return 0;
}


