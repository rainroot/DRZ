#include <rain_common.h>
#include <linux/if_tun.h>
#define IFF_MULTI_QUEUE 0x0100

bool is_dev_type (const char *dev, const char *dev_type, const char *match_type)
{
	if (!dev){
		return false;
	}
	if (dev_type){
		return !strcmp (dev_type, match_type);
	}else{
		return !strncmp (dev, match_type, strlen (match_type));
	}
}

int dev_type_enum (const char *dev, const char *dev_type)
{
	if (is_dev_type (dev, dev_type, "tun")){
		return DEV_TYPE_TUN;
	}else if (is_dev_type (dev, dev_type, "tap")){
		return DEV_TYPE_TAP;
	}else if (is_dev_type (dev, dev_type, "null")){
		return DEV_TYPE_NULL;
	}else{
		return DEV_TYPE_UNDEF;
	}
}

char * dev_type_string (const char *dev, const char *dev_type)
{
	switch (dev_type_enum (dev, dev_type))
	{
		case DEV_TYPE_TUN:
			return "tun";
		case DEV_TYPE_TAP:
			return "tap";
		case DEV_TYPE_NULL:
			return "null";
		default:
			return "[unknown-dev-type]";
	}
}


int tun_open(char *dev, int flags)
{
	struct ifreq ifr;
	int fd=0;

	if(dev == NULL){
		MM("## ERR: EXIT  tun dev NULL %s %d ##\n",__func__,__LINE__);
		exit(0);
	}


	if ((fd = open ("/dev/net/tun", O_RDWR)) < 0)
	{
		MM("## ERROR: Cannot open TUN/TAP dev ##\n");
	}

	memset(&ifr, 0, sizeof(ifr));

	ifr.ifr_flags = IFF_NO_PI; // only ipv4

#if 0 //not user options 
	ifr.ifr_flags |= IFF_MULTI_QUEUE;
#endif

	if (flags == DEV_TYPE_TUN)
	{
		ifr.ifr_flags |= IFF_TUN;
	}
	else if (flags == DEV_TYPE_TAP)
	{
		ifr.ifr_flags |= IFF_TAP;
	}
	else
	{
		MM("## I don't recognize device %s as a tun or tap device ##\n", dev);
	}

	if((strcmp(dev,"tun") ) && (strcmp(dev,"tap") )){
		strncpy(ifr.ifr_name, dev, IFNAMSIZ);
	}

	if (ioctl (fd, TUNSETIFF, (void *) &ifr) < 0)
	{
		MM("### ERROR: EXIT() Cannot ioctl TUNSETIFF %s #### \n", dev);
		exit(0);
	}

	struct ifreq netifr;
	int ctl_fd;
	int txq = 3000;
	if ((ctl_fd = socket (AF_INET, SOCK_DGRAM, 0)) >= 0)
	{
		memset(&netifr,0,sizeof(netifr));
		strncpy(netifr.ifr_name, ifr.ifr_name, IFNAMSIZ);
		netifr.ifr_qlen = txq;
		if (ioctl (ctl_fd, SIOCSIFTXQLEN, (void *) &netifr) >= 0){
			MM("TUN/TAP TX queue length set to %d \n", txq);
		}else{
			MM( "Note: Cannot set tx queue length on %s \n", ifr.ifr_name);
		}
		close (ctl_fd);
	}
	else
	{
		MM("Note: Cannot open control socket on %s", ifr.ifr_name);
	}

	//dev = ifr.ifr_name;

	sprintf(dev,"%s",ifr.ifr_name);
	MM("#### TUN/TAP device %s opened ####\n", dev);


	if (fcntl (fd, F_SETFD, FD_CLOEXEC) < 0){
	}

#if 0 //not user options 
	if (ioctl (fd, TUNSETPERSIST, 0) < 0){
		printf( "Cannot ioctl TUNSETPERSIST(%d) %s", 1, dev);
	}
#endif

	if (fcntl (fd, F_SETFL, O_NONBLOCK) < 0){
		MM("### ERR: %s %d TUN/TAP NONBLOCK ERROR ###\n",__func__,__LINE__);
	}

	struct timeval timeout;      
	timeout.tv_sec = 1;
	timeout.tv_usec = 0;

	if(setsockopt (fd, SOL_SOCKET, SO_RCVTIMEO, (char *)&timeout, sizeof(timeout)) < 0){
		MM("%s %d setsockopt failed\n",__func__,__LINE__);
	}

	if (setsockopt (fd, SOL_SOCKET, SO_SNDTIMEO, (char *)&timeout, sizeof(timeout)) < 0){
		MM("%s %d setsockopt failed\n",__func__,__LINE__);
	}

	return fd;
}

int tun_close(int fd)
{
	close(fd);
	return 0;
}

in_addr_t generate_ifconfig_broadcast_addr (in_addr_t local, in_addr_t netmask)
{
	return local | ~netmask;
}


void do_ifconfig(struct epoll_ptr_data *epd)
{
	char ifconfig_broadcast[65]={0,};
	bool geterr = true;

	bool tun_type = false;

	int tun_mtu = 1500;

	struct main_data *md=NULL;
	md = (struct main_data *)epd->gl_var;

	struct options *opt = NULL;
	opt = (struct options *)md->opt;

	char cmd[1024]={0,};

	if(dev_type_enum (opt->dev, opt->dev_type) == DEV_TYPE_TUN){
		tun_type = true;
	}else{
		tun_type = false;
	}

	if(opt->mode == CLIENT){
		in_addr_t t_ifconfig_local = get_ip_addr(opt->ifconfig_local,&geterr);
		in_addr_t t_ifconfig_remote_netmask = get_ip_addr(opt->ifconfig_remote_netmask,&geterr);

		if(tun_type == false){
			print_in_addr_t(generate_ifconfig_broadcast_addr(t_ifconfig_local,t_ifconfig_remote_netmask),0,ifconfig_broadcast);
		}

	}


	if(tun_type == true){

		if(opt->mode == SERVER){
			char network[64]={0,};
			char netmask[64]={0,};
			print_in_addr_t(opt->server_network+1,0,network);
			print_in_addr_t(opt->server_network+2,0,netmask);
			print_in_addr_t(opt->server_network+2,0,opt->route_default_gateway);

			sprintf(cmd,"ifconfig %s %s pointopoint %s mtu %d", opt->dev,network,netmask,tun_mtu);
			system(cmd);

		}else{
			sprintf(cmd,"ifconfig %s %s pointopoint %s mtu %d", opt->dev,opt->ifconfig_local,opt->ifconfig_remote_netmask,tun_mtu);
			system(cmd);
		}
	}else{
		if(opt->mode == SERVER){

		}else{
			printf("################### start %s %d ###################\n",__func__,__LINE__);
			sprintf(cmd,"ifconfig %s %s netmask %s mtu %d broadcast %s ", opt->dev,opt->ifconfig_local,opt->ifconfig_remote_netmask,tun_mtu,ifconfig_broadcast);
			system(cmd);
			printf("################### end %s %d ###################\n",__func__,__LINE__);
		}
	}
}

char * ifconfig_options_string (struct epoll_ptr_data *epd,bool remote)
{
	struct main_data *md=NULL;
	md = (struct main_data *)epd->gl_var;

	struct options *opt = NULL;
	opt = (struct options *)md->opt;


	char *out = malloc(256);
	memset(out,0x00,256);

	bool tun_type = false;
	bool geterr = true;

	char network[64]={0,};
	char netmask[64]={0,};

	if(dev_type_enum (opt->dev, opt->dev_type) == DEV_TYPE_TUN){
		tun_type = true;
	}else{
		tun_type = false;
	}

	if (tun_type == false || (tun_type == true && opt->topology == TOP_SUBNET))
	{
		in_addr_t t_ifconfig_local = get_ip_addr(opt->ifconfig_local,&geterr);
		in_addr_t t_ifconfig_remote_netmask = get_ip_addr(opt->ifconfig_remote_netmask,&geterr);
		print_in_addr_t(t_ifconfig_local & t_ifconfig_remote_netmask, 0,network);
		print_in_addr_t (t_ifconfig_remote_netmask, 0,netmask);
		sprintf (out, "%s %s", network,netmask);
	}
	else if (tun_type == true)
	{
		const char *l, *r;
		if (remote)
		{
			r = opt->ifconfig_local;
			l = opt->ifconfig_remote_netmask;
		}
		else
		{
			l = opt->ifconfig_local;
			r = opt->ifconfig_remote_netmask;
		}
		sprintf (out, "%s %s", r, l);
	}
	else{
		sprintf (out, "[undef]");
	}

	return out;
}


