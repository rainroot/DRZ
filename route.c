#include <rain_common.h>

#define ROUTE_PATH "route"

void do_init_route_list (struct epoll_ptr_data *epd,struct options *options)
{
	char gw[64]={0,};

	int dev = dev_type_enum (options->dev, options->dev_type);
	int metric = 0;

	struct main_data *md=NULL;
	md = (struct main_data *)epd->gl_var;

	if (dev == DEV_TYPE_TUN && (options->topology == TOP_NET30 || options->topology == TOP_P2P)){
		sprintf(gw,"%s",options->ifconfig_remote_netmask);
	}
	if (strlen(options->route_default_gateway) != 0){

		sprintf(gw,"%s",options->route_default_gateway);
	}
	if (options->route_default_metric){
		metric = options->route_default_metric;
	}
	if (!init_route_list (options->route_list, options->routes,gw,metric,link_socket_current_remote (md)))
	{
		MM("## ERR: %s %d ##\n",__func__,__LINE__);
	}
}


in_addr_t netbits_to_netmask (int netbits)
{
	int addrlen = sizeof (in_addr_t) * 8;
	in_addr_t mask = 0;
	if (netbits > 0 && netbits <= addrlen){
		mask = IPV4_NETMASK_HOST << (addrlen-netbits);
	}
	return mask;
}

void print_bypass_addresses (struct route_bypass *rb)
{
	int i;
	char str0[64]={0,};
	for (i = 0; i < rb->n_bypass; ++i)
	{
		print_in_addr_t (rb->bypass[i], 0,str0);
		MM("ROUTE: bypass_host_route[%d]=%s\n", i,str0);
	}
}


bool add_bypass_address (struct route_bypass *rb,in_addr_t a)
{
	int i;
	for (i = 0; i < rb->n_bypass; ++i)
	{
		if (a == rb->bypass[i]){
			return true;
		}
	}
	if (rb->n_bypass < N_ROUTE_BYPASS)
	{
		rb->bypass[rb->n_bypass++] = a;
		return true;
	}
	else
	{
		return false;
	}
}

struct route_option_list * new_route_option_list (int max_routes)
{
	printf("############################# %s %d ################################### ????????????????????????????? \n",__func__,__LINE__);
	size_t rl_size = array_mult_safe (sizeof(struct route_option), max_routes, sizeof(struct route_option_list));
	struct route_option_list *ret = malloc(rl_size);
	memset(ret,0x00,rl_size);
	ret->capacity = max_routes;
	return ret;
}

struct route_ipv6_option_list * new_route_ipv6_option_list (int max_routes)
{
	size_t rl_size = array_mult_safe (sizeof(struct route_ipv6_option), max_routes, sizeof(struct route_ipv6_option_list));
	struct route_ipv6_option_list *ret = malloc(rl_size);
	memset(ret,0x00,rl_size);
	return ret;
}

struct route_option_list * clone_route_option_list (struct route_option_list *src)
{
	size_t rl_size = array_mult_safe (sizeof(struct route_option), src->capacity, sizeof(struct route_option_list));
	struct route_option_list *ret = malloc (rl_size);
	memset(ret,0x00,rl_size);
	memcpy (ret, src, rl_size);
	return ret;
}

struct route_ipv6_option_list * clone_route_ipv6_option_list (struct route_ipv6_option_list *src)
{
	size_t rl_size = array_mult_safe (sizeof(struct route_ipv6_option), src->capacity, sizeof(struct route_ipv6_option_list));
	struct route_ipv6_option_list *ret = malloc (rl_size);
	memset(ret,0x00,rl_size);
	memcpy (ret, src, rl_size);
	return ret;
}

void copy_route_option_list (struct route_option_list *dest,struct route_option_list *src)
{
	size_t src_size = array_mult_safe (sizeof(struct route_option), src->capacity, sizeof(struct route_option_list));
	if (src->capacity > dest->capacity){
		MM("ERR: %s %d  ROUTE: (copy) number of route options in src (%d) is greater than route list capacity in dest (%d)\n",__func__,__LINE__, src->capacity, dest->capacity);
	}
	memcpy (dest, src, src_size);
}

void copy_route_ipv6_option_list (struct route_ipv6_option_list *dest,struct route_ipv6_option_list *src)
{
	size_t src_size = array_mult_safe (sizeof(struct route_ipv6_option), src->capacity, sizeof(struct route_ipv6_option_list));
	if (src->capacity > dest->capacity){
		MM("ERR: %s %d  ROUTE: (copy) number of route options in src (%d) is greater than route list capacity in dest (%d)\n",__func__,__LINE__,src->capacity, dest->capacity);
	}
	memcpy (dest, src, src_size);
}

struct route_list * new_route_list (int max_routes)
{
	struct route_list *ret;
	size_t size = array_mult_safe (sizeof(struct route_ipv4), max_routes, sizeof(struct route_list));
	ret = malloc(size);
	memset(ret,0x00,size);
	ret->capacity = max_routes;
	return ret;
}

struct route_ipv6_list * new_route_ipv6_list (int max_routes)
{
	struct route_ipv6_list *ret;
	size_t size = array_mult_safe (sizeof(struct route_ipv6), max_routes, sizeof(struct route_ipv6_list));
	ret = malloc(size);
	memset(ret,0x00,size);
	ret->capacity = max_routes;
	return ret;
}

char * route_string (struct route_ipv4 *r)
{
	char *out = malloc(256);
	memset(out,0x00,256);

	char network[64]={0,};
	char netmask[64]={0,};
	char gateway[64]={0,};

	print_in_addr_t(r->network,0,network);
	print_in_addr_t(r->netmask,0,netmask);
	print_in_addr_t(r->gateway,0,gateway);

	sprintf (out,"ROUTE network %s netmask %s gateway %s",network,netmask,gateway);
	if (r->flags & RT_METRIC_DEFINED){
		sprintf (out, "%s metric %d",out, r->metric);
	}
	return out;
}

bool is_route_parm_defined (char *parm)
{

	if (strlen(parm) == 0){
		return false;
	}
	if (!strcmp (parm, "default")){
		return false;
	}
	return true;
}

bool get_special_addr (struct route_list *rl,char *string,in_addr_t *out,bool *status)
{
	if (status){
		*status = true;
	}
	if (!strcmp (string, "vpn_gateway"))
	{
		if (rl)
		{
			if (rl->spec.flags & RTSA_REMOTE_ENDPOINT){
				*out = rl->spec.remote_endpoint;
			}else{
				MM("ROUTE: vpn_gateway undefined \n");
				if (status){
					*status = false;
				}
			}
		}
		return true;
	}
	else if (!strcmp (string, "net_gateway"))
	{
		if (rl)
		{
			if (rl->rgi.flags & RGI_ADDR_DEFINED){
				*out = rl->rgi.gateway.addr;
			}else{
				MM("ROUTE: net_gateway undefined -- unable to get default gateway from system\n");
				if (status){
					*status = false;
				}
			}
		}
		return true;
	}
	else if (!strcmp (string, "remote_host"))
	{
		if (rl)
		{
			if (rl->spec.flags & RTSA_REMOTE_HOST){
				*out = rl->spec.remote_host;
			}else{
				MM(" ROUTE: remote_host undefined\n");
				if (status){
					*status = false;
				}
			}
		}
		return true;
	}
	return false;
}

bool is_special_addr (char *addr_str)
{
	if (addr_str){
		return get_special_addr (NULL, addr_str, NULL, NULL);
	}else{
		return false;
	}
}

bool init_route (struct route_ipv4 *r, struct addrinfo **network_list,struct route_option *ro,struct route_list *rl)
{
	in_addr_t default_netmask = IPV4_NETMASK_HOST;
	bool status;
	int ret;
	struct in_addr special;

	r->option = ro;

	if (!is_route_parm_defined (ro->network))
	{
		goto fail;
	}

	if(get_special_addr (rl, ro->network, &special.s_addr, &status))
	{
		special.s_addr = htonl(special.s_addr);
		ret = openvpn_getaddrinfo(0, inet_ntoa(special), 0, NULL, AF_INET, network_list);
	}else{
		ret = openvpn_getaddrinfo(GETADDR_RESOLVE | GETADDR_WARN_ON_SIGNAL,ro->network, 0, NULL, AF_INET, network_list);
	}

	status = (ret == 0);

	if (!status){
		goto fail;
	}

	if (is_route_parm_defined (ro->netmask))
	{
		r->netmask = getaddr (GETADDR_HOST_ORDER| GETADDR_WARN_ON_SIGNAL,ro->netmask,0,&status,NULL);
		if (!status){
			goto fail;
		}
	}else{
		r->netmask = default_netmask;
	}

	if (is_route_parm_defined (ro->gateway))
	{
		if (!get_special_addr (rl, ro->gateway, &r->gateway, &status))
		{
			r->gateway = getaddr (GETADDR_RESOLVE| GETADDR_HOST_ORDER| GETADDR_WARN_ON_SIGNAL,ro->gateway,0,&status,NULL);
		}
		if (!status){
			goto fail;
		}
	}else{
		if (rl->spec.flags & RTSA_REMOTE_ENDPOINT){
			r->gateway = rl->spec.remote_endpoint;
		}else{
			MM("ERR: %s %d  ROUTE: needs a gateway parameter for a --route option and no default was specified by either --route-gateway or --ifconfig options\n",__func__,__LINE__);
			goto fail;
		}
	}

	r->metric = 0;
	if (is_route_parm_defined (ro->metric))
	{
		r->metric = atoi (ro->metric);
		if (r->metric < 0)
		{
			MM("ERR:%s %d  ROUTE: route metric for network %s (%s) must be >= 0\n",__func__,__LINE__, ro->network,ro->metric);
			goto fail;
		}
		r->flags |= RT_METRIC_DEFINED;
	}
	else if (rl->spec.flags & RTSA_DEFAULT_METRIC)
	{
		r->metric = rl->spec.default_metric;
		r->flags |= RT_METRIC_DEFINED;
	}

	r->flags |= RT_DEFINED;

	return true;

fail:
	MM("ERR:%s %d  ROUTE: failed to parse/resolve route for host/network: %s \n", __func__,__LINE__, ro->network);
	return false;
}

bool init_route_ipv6 (struct route_ipv6 *r6,struct route_ipv6_option *r6o,struct route_ipv6_list *rl6 )
{
	r6->defined = false;

	if ( !get_ipv6_addr( r6o->prefix, &r6->network, &r6->netbits, NULL )){
		goto fail;
	}

	if (is_route_parm_defined (r6o->gateway))
	{
		if ( inet_pton( AF_INET6, r6o->gateway, &r6->gateway ) != 1 )
		{
			MM("ROUTE6: cannot parse gateway spec '%s'\n", r6o->gateway );
		}
	}
	else if (rl6->remote_endpoint_defined)
	{
		r6->gateway = rl6->remote_endpoint_ipv6;
	}
	else
	{
		MM("ERR %s %d  ROUTE6:  needs a gateway parameter for a --route-ipv6 option and no default was specified by either --route-ipv6-gateway or --ifconfig-ipv6 options\n",__func__,__LINE__);
		goto fail;
	}

	r6->metric_defined = false;
	r6->metric = -1;
	if (is_route_parm_defined (r6o->metric))
	{
		r6->metric = atoi (r6o->metric);
		if (r6->metric < 0)
		{
			MM("ERR: %s %d  ROUTE: route metric for network %s (%s) must be >= 0",__func__,__LINE__, r6o->prefix,r6o->metric);
			goto fail;
		}
		r6->metric_defined = true;
	}
	else if (rl6->default_metric_defined)
	{
		r6->metric = rl6->default_metric;
		r6->metric_defined = true;
	}

	r6->defined = true;

	return true;

fail:
	MM("ERR: %s %d  ROUTE: failed to parse/resolve route for host/network: %s",__func__,__LINE__, r6o->prefix);
	r6->defined = false;
	return false;
}

void add_route_to_option_list (struct route_option_list *l,char *network, char *netmask,char *gateway,char *metric)
{
	struct route_option *ro;

	if (l->n >= l->capacity){
		MM("ERR: %s %d  ROUTE: cannot add more than %d routes -- please increase the max-routes option in the client configuration file",__func__,__LINE__,l->capacity);
	}
	ro = &l->routes[l->n];
	if(network != NULL){
		sprintf(ro->network,"%s",network);
		if(netmask != NULL){
			sprintf(ro->netmask,"%s",netmask);
		}
	}
	if(gateway != NULL){
		sprintf(ro->gateway,"%s",gateway);
	}
	if(metric != NULL){
		sprintf(ro->metric,"%s",metric);
	}
	++l->n;
}

void add_route_ipv6_to_option_list (struct route_ipv6_option_list *l, char *prefix,char *gateway,char *metric)
{
	struct route_ipv6_option *ro;
	if (l->n >= l->capacity){
		MM(" ROUTE: cannot add more than %d IPv6 routes -- please increase the max-routes option in the client configuration file\n", l->capacity);
	}
	ro = &l->routes_ipv6[l->n];
	ro->prefix = prefix;
	ro->gateway = gateway;
	ro->metric = metric;
	++l->n;
}

void clear_route_list (struct route_list *rl)
{
	int capacity = rl->capacity;
	size_t rl_size = array_mult_safe (sizeof(struct route_ipv4), capacity, sizeof(struct route_list));
	memset(rl, 0, rl_size);
	rl->capacity = capacity;
}

void clear_route_ipv6_list (struct route_ipv6_list *rl6)
{
	int capacity = rl6->capacity;
	size_t rl6_size = array_mult_safe (sizeof(struct route_ipv6), capacity, sizeof(struct route_ipv6_list));
	memset(rl6, 0, rl6_size);
	rl6->capacity = capacity;
}

#if 0
void route_list_add_vpn_gateway (struct route_list *rl, in_addr_t addr)
{
	if(!(rl)){
		MM("## ERR: %s %d ###\n",__func__,__LINE__);
	}
	rl->spec.remote_endpoint = addr;
	rl->spec.flags |= RTSA_REMOTE_ENDPOINT;
}
#endif

void add_block_local_item (struct route_list *rl, struct route_gateway_address *gateway,in_addr_t target)
{
	unsigned int rgi_needed = (RGI_ADDR_DEFINED|RGI_NETMASK_DEFINED);
	if (((rl->rgi.flags & rgi_needed) == rgi_needed ) && (rl->rgi.gateway.netmask < 0xFFFFFFFF ) && ((rl->n)+2 <= rl->capacity))
	{
		struct route_ipv4 r;
		unsigned int l2;
		memset(&r,0x00,sizeof(struct route_ipv4));

		r.flags = RT_DEFINED;
		r.gateway = target;
		r.network = gateway->addr & gateway->netmask;
		l2 = ((~gateway->netmask)+1)>>1;
		r.netmask = ~(l2-1);
		rl->routes[rl->n++] = r;
		r.network += l2;
		rl->routes[rl->n++] = r;
	}
}

void add_block_local (struct route_list *rl)
{
	unsigned int rgi_needed = (RGI_ADDR_DEFINED|RGI_NETMASK_DEFINED);
	if ((rl->flags & RG_BLOCK_LOCAL) && (rl->rgi.flags & rgi_needed) == rgi_needed && (rl->spec.flags & RTSA_REMOTE_ENDPOINT) && rl->spec.remote_host_local != TLA_LOCAL)
	{
		size_t i;
		add_bypass_address (&rl->spec.bypass, rl->rgi.gateway.addr);

		add_block_local_item (rl, &rl->rgi.gateway, rl->spec.remote_endpoint);

		for (i = 0;(int)i < rl->rgi.n_addrs; ++i)
		{
			struct route_gateway_address *gwa = &rl->rgi.addrs[i];
			if (!((rl->rgi.gateway.addr & rl->rgi.gateway.netmask) == (gwa->addr & gwa->netmask) && rl->rgi.gateway.netmask == gwa->netmask)){
				add_block_local_item (rl, gwa, rl->spec.remote_endpoint);
			}
		}
	}
}

bool init_route_list (struct route_list *rl, struct route_option_list *opt,const char *remote_endpoint,int default_metric,in_addr_t remote_host)
{
	bool ret = true;
	clear_route_list (rl);
	rl->flags = opt->flags;

	if (remote_host)
	{
		rl->spec.remote_host = remote_host;
		rl->spec.flags |= RTSA_REMOTE_HOST;
	}

	if (default_metric)
	{
		rl->spec.default_metric = default_metric;
		rl->spec.flags |= RTSA_DEFAULT_METRIC;
	}

	get_default_gateway (&rl->rgi);
	if (rl->rgi.flags & RGI_ADDR_DEFINED)
	{
		print_default_gateway(&rl->rgi);
	}
	else
	{
		MM( "ROUTE: default_gateway=UNDEF \n");
	}

	if (rl->spec.flags & RTSA_REMOTE_HOST){
		rl->spec.remote_host_local = test_local_addr (remote_host, &rl->rgi);
	}
	if (is_route_parm_defined ((char *)remote_endpoint))
	{
		bool defined = false;
		rl->spec.remote_endpoint = getaddr (GETADDR_RESOLVE|GETADDR_HOST_ORDER|GETADDR_WARN_ON_SIGNAL,remote_endpoint,0,&defined,NULL);

		if (defined)
		{
			rl->spec.flags |= RTSA_REMOTE_ENDPOINT;
		}
		else
		{
			MM(" ROUTE: failed to parse/resolve default gateway: %s", remote_endpoint);
			ret = false;
		}
	}

	if (rl->flags & RG_ENABLE)
	{
		add_block_local (rl);
		get_bypass_addresses (&rl->spec.bypass, rl->flags);
		print_bypass_addresses (&rl->spec.bypass);
	}

	{
		int i = 0;
		int j = rl->n;
		bool warned = false;
		for (i = 0; i < opt->n; ++i)
		{
			struct addrinfo* netlist;
			struct route_ipv4 r;
			if (!init_route (&r,&netlist,&opt->routes[i],rl)){
				ret = false;
			}else{
				struct addrinfo* curele;
				for (curele = netlist; curele; curele = curele->ai_next)
				{
					if (j < rl->capacity)
					{
						r.network = ntohl(((struct sockaddr_in*)(curele)->ai_addr)->sin_addr.s_addr);
						rl->routes[j++] = r;
					}else{
						if (!warned)
						{
							MM("ROUTE: routes dropped because number of expanded routes is greater than route list capacity (%d)\n", rl->capacity);
							warned = true;
						}
					}
				}
				freeaddrinfo(netlist);
			}
		}
		rl->n = j;
	}

	return ret;
}

bool init_route_ipv6_list (struct route_ipv6_list *rl6, struct route_ipv6_option_list *opt6,char *remote_endpoint,int default_metric)
{
	bool ret = true;

	clear_route_ipv6_list (rl6);

	rl6->flags = opt6->flags;

	if (default_metric >= 0 )
	{
		rl6->default_metric = default_metric;
		rl6->default_metric_defined = true;
	}else{
		MM("ROUTE6: default_gateway=UNDEF\n");
	}

	if ( is_route_parm_defined( remote_endpoint ))
	{
		if ( inet_pton( AF_INET6, remote_endpoint,  &rl6->remote_endpoint_ipv6) == 1 )
		{
			rl6->remote_endpoint_defined = true;
		}else{
			MM(" ROUTE: failed to parse/resolve default gateway: %s \n", remote_endpoint);
			ret = false;
		}
	}
	else{
		rl6->remote_endpoint_defined = false;
	}


	if (!(opt6->n >= 0 && opt6->n <= rl6->capacity)){
		MM(" ROUTE6: (init) number of route options (%d) is greater than route list capacity (%d)\n", opt6->n, rl6->capacity);
	}

	{
		int i, j = 0;
		for (i = 0; i < opt6->n; ++i)
		{
			if (!init_route_ipv6 (&rl6->routes_ipv6[j], &opt6->routes_ipv6[i],rl6 )){
				ret = false;
			}else{
				++j;
			}
		}
		rl6->n = j;
	}
	return ret;
}

void add_route3 (in_addr_t network,in_addr_t netmask,in_addr_t gateway,struct options *opt,unsigned int flags,struct route_gateway_info *rgi)
{
	struct route_ipv4 r;
	memset(&r,0x00,sizeof(struct route_ipv4));
	r.flags = RT_DEFINED;
	r.network = network;
	r.netmask = netmask;
	r.gateway = gateway;
	add_route (&r, opt, flags, rgi);
}

void del_route3 (in_addr_t network, in_addr_t netmask,in_addr_t gateway,struct options *opt ,unsigned int flags,struct route_gateway_info *rgi)
{
	struct route_ipv4 r;
	memset(&r,0x00,sizeof(struct route_ipv4));
	r.flags = RT_DEFINED|RT_ADDED;
	r.network = network;
	r.netmask = netmask;
	r.gateway = gateway;
	delete_route (&r, opt, flags, rgi);
}

void add_bypass_routes (struct route_bypass *rb,in_addr_t gateway,struct options *opt,unsigned int flags,struct route_gateway_info *rgi)
{
	int i;
	for (i = 0; i < rb->n_bypass; ++i)
	{
		if (rb->bypass[i]){
			add_route3 (rb->bypass[i], IPV4_NETMASK_HOST,gateway,opt ,flags | ROUTE_REF_GW,rgi);
		}
	}
}

void del_bypass_routes (struct route_bypass *rb, in_addr_t gateway,struct options *opt ,unsigned int flags,struct route_gateway_info *rgi)
{
	int i;
	for (i = 0; i < rb->n_bypass; ++i)
	{
		if (rb->bypass[i]){
			del_route3 (rb->bypass[i],IPV4_NETMASK_HOST,gateway,opt,flags | ROUTE_REF_GW,rgi);
		}
	}
}

void redirect_default_route_to_vpn (struct route_list *rl,struct options *opt , unsigned int flags)
{
	char err[] = "NOTE: unable to redirect default gateway --";

	if ( rl && rl->flags & RG_ENABLE )
	{
		if (!(rl->spec.flags & RTSA_REMOTE_ENDPOINT))
		{
			MM("%s VPN gateway parameter (--route-gateway or --ifconfig) is missing\n", err);
		}
		else if (!(rl->rgi.flags & RGI_ADDR_DEFINED))
		{
			MM("%s Cannot read current default gateway from system\n", err);
		}
		else if (!(rl->spec.flags & RTSA_REMOTE_HOST))
		{
			MM("%s Cannot obtain current remote host address\n", err);
		}
		else
		{
			bool local = BOOL_CAST(rl->flags & RG_LOCAL);
			if (rl->flags & RG_AUTO_LOCAL) {
				int tla = rl->spec.remote_host_local;
				if (tla == TLA_NONLOCAL)
				{
					MM("ROUTE remote_host is NOT LOCAL\n");
					local = false;
				}
				else if (tla == TLA_LOCAL)
				{
					MM( "ROUTE remote_host is LOCAL\n");
					local = true;
				}
			}
			if (!local)
			{
				if (rl->spec.remote_host != IPV4_INVALID_ADDR) {
					add_route3 (rl->spec.remote_host, IPV4_NETMASK_HOST,rl->rgi.gateway.addr,opt ,flags | ROUTE_REF_GW, &rl->rgi);
					rl->iflags |= RL_DID_LOCAL;
				} else {
					MM("ROUTE remote_host protocol differs from tunneled\n");
				}
			}

			add_bypass_routes (&rl->spec.bypass, rl->rgi.gateway.addr, opt, flags, &rl->rgi);

			if (rl->flags & RG_REROUTE_GW)
			{
				if (rl->flags & RG_DEF1)
				{
					add_route3 (0x00000000, 0x80000000,rl->spec.remote_endpoint,opt,flags,&rl->rgi);
					add_route3 (0x80000000,0x80000000,rl->spec.remote_endpoint,opt,flags,&rl->rgi);
				}
				else
				{
					del_route3 (0,0,rl->rgi.gateway.addr,opt,flags | ROUTE_REF_GW,&rl->rgi);

					add_route3 (0,0,rl->spec.remote_endpoint,opt,flags,&rl->rgi);
				}
			}

			rl->iflags |= RL_DID_REDIRECT_DEFAULT_GATEWAY;
		}
	}
}

void undo_redirect_default_route_to_vpn (struct route_list *rl, struct options *opt, unsigned int flags)
{
	if ( rl && rl->iflags & RL_DID_REDIRECT_DEFAULT_GATEWAY )
	{
		if (rl->iflags & RL_DID_LOCAL)
		{
			del_route3 (rl->spec.remote_host, IPV4_NETMASK_HOST,rl->rgi.gateway.addr,opt, flags | ROUTE_REF_GW,&rl->rgi);
			rl->iflags &= ~RL_DID_LOCAL;
		}

		del_bypass_routes (&rl->spec.bypass, rl->rgi.gateway.addr, opt, flags, &rl->rgi);

		if (rl->flags & RG_REROUTE_GW)
		{
			if (rl->flags & RG_DEF1)
			{
				del_route3 (0x00000000,0x80000000,rl->spec.remote_endpoint,opt,flags,&rl->rgi);
				del_route3 (0x80000000,0x80000000,rl->spec.remote_endpoint,opt,flags,&rl->rgi);
			}
			else
			{
				del_route3 (0,0,rl->spec.remote_endpoint,opt,flags,&rl->rgi);

				add_route3 (0, 0,rl->rgi.gateway.addr,opt,flags | ROUTE_REF_GW,&rl->rgi);
			}
		}

		rl->iflags &= ~RL_DID_REDIRECT_DEFAULT_GATEWAY;
	}
}

void add_routes (struct route_list *rl, struct route_ipv6_list *rl6,struct options *opt, unsigned int flags)
{

	redirect_default_route_to_vpn (rl, opt, flags);
	if ( rl && !(rl->iflags & RL_ROUTES_ADDED) )
	{
		int i;
		for (i = 0; i < rl->n; ++i)
		{
			struct route_ipv4 *r = &rl->routes[i];
			//check_subnet_conflict (r->network, r->netmask, "route");
			if (flags & ROUTE_DELETE_FIRST){
				delete_route (r, opt, flags, &rl->rgi);
			}
			add_route (r, opt, flags, &rl->rgi);
		}
		rl->iflags |= RL_ROUTES_ADDED;
	}
	if (rl6 && !rl6->routes_added)
	{
		int i;

		for (i = 0; i < rl6->n; ++i)
		{
			struct route_ipv6 *r = &rl6->routes_ipv6[i];
			if (flags & ROUTE_DELETE_FIRST){
				delete_route_ipv6 (r, opt, flags);
			}
			add_route_ipv6 (r, opt, flags);
		}
		rl6->routes_added = true;
	}
}

void delete_routes (struct route_list *rl, struct route_ipv6_list *rl6, struct options *opt, unsigned int flags)
{
	if ( rl && rl->iflags & RL_ROUTES_ADDED )
	{
		int i;
		for (i = rl->n - 1; i >= 0; --i)
		{
			struct route_ipv4 * r = &rl->routes[i];
			delete_route (r, opt, flags, &rl->rgi);
		}
		rl->iflags &= ~RL_ROUTES_ADDED;
	}

	undo_redirect_default_route_to_vpn (rl, opt, flags);

	if ( rl )
	{
		clear_route_list (rl);
	}

	if ( rl6 && rl6->routes_added )
	{
		int i;
		for (i = rl6->n - 1; i >= 0; --i)
		{
			struct route_ipv6 *r6 = &rl6->routes_ipv6[i];
			delete_route_ipv6 (r6, opt, flags);
		}
		rl6->routes_added = false;
	}

	if ( rl6 )
	{
		clear_route_ipv6_list (rl6);
	}
}

char * show_opt (char *option)
{
	if (strlen(option) == 0){
		return "nil";
	}else{
		return option;
	}
}

void print_route_option (struct route_option *ro)
{
	MM("  route %s/%s/%s/%s\n", show_opt (ro->network),show_opt (ro->netmask),show_opt (ro->gateway),show_opt (ro->metric));
}

void print_route_options (struct route_option_list *rol)
{
	int i;
	if (rol->flags & RG_ENABLE){
		MM("  [redirect_default_gateway local=%d]\n", (rol->flags & RG_LOCAL) != 0);
	}
	for (i = 0; i < rol->n; ++i){
		print_route_option (&rol->routes[i]);
	}
}

void print_default_gateway(struct route_gateway_info *rgi)
{
	char str0[64]={0,};
	char str1[64]={0,};
	if (rgi->flags & RGI_ADDR_DEFINED)
	{
		char *out = malloc(256);
		memset(out,0x00,256);
		sprintf (out, "ROUTE_GATEWAY");
		if (rgi->flags & RGI_ON_LINK){
			sprintf (out, "%s ON_LINK",out);
		}else{
			print_in_addr_t (rgi->gateway.addr, 0,str0);
			sprintf (out, "%s %s",out,str0);
		}
		if (rgi->flags & RGI_NETMASK_DEFINED){
			print_in_addr_t (rgi->gateway.netmask, 0,str1);
			sprintf (out, "%s/%s",out, str1);
		}
		if (rgi->flags & RGI_IFACE_DEFINED){
			sprintf (out, "%s IFACE=%s",out, rgi->iface);
		}
		if (rgi->flags & RGI_HWADDR_DEFINED){
			//sprintf (out, "%s HWADDR=%s",out, format_hex_ex (rgi->hwaddr, 6, 0, 1, ":", &gc));
		}
		MM("%s\n",out);
		free(out);
	}
}


void print_route (struct route_ipv4 *r)
{
	if (r->flags & RT_DEFINED){
		//MM("%s\n", route_string (r));
	}
}

void print_routes (struct route_list *rl)
{
	int i;
	for (i = 0; i < rl->n; ++i){
		print_route (&rl->routes[i]);
	}
}

#define LR_NOMATCH 0
#define LR_MATCH   1
#define LR_ERROR   2

int local_route (in_addr_t network, in_addr_t netmask,in_addr_t gateway,struct route_gateway_info *rgi)
{
	unsigned int rgi_needed = (RGI_ADDR_DEFINED|RGI_NETMASK_DEFINED|RGI_IFACE_DEFINED);
	if (rgi && (rgi->flags & rgi_needed) == rgi_needed && gateway == rgi->gateway.addr && netmask == 0xFFFFFFFF)
	{
		if (((network ^  rgi->gateway.addr) & rgi->gateway.netmask) == 0){
			return LR_MATCH;
		}else{
			size_t i;
			for (i = 0; (int)i < rgi->n_addrs; ++i)
			{
				struct route_gateway_address *gwa = &rgi->addrs[i];
				if (((network ^ gwa->addr) & gwa->netmask) == 0){
					return LR_MATCH;
				}
			}
		}
	}
	return LR_NOMATCH;
}

bool is_on_link (int is_local_route,unsigned int flags,struct route_gateway_info *rgi)
{
	return rgi && (is_local_route == LR_MATCH || ((flags & ROUTE_REF_GW) && (rgi->flags & RGI_ON_LINK)));
}

void add_route (struct route_ipv4 *r, struct options *opt,unsigned int flags,struct route_gateway_info *rgi)
{
	char network[64]={0,};
	char netmask[64]={0,};
	char gateway[64]={0,};
	bool status = false;
	int is_local_route;

	if(opt){}
	if(flags){}

	if (!(r->flags & RT_DEFINED)){
		return;
	}

	char *out = malloc(256);
	memset(out,0x00,256);

	print_in_addr_t(r->network,0,network);
	print_in_addr_t(r->netmask,0,netmask);
	print_in_addr_t(r->gateway,0,gateway);

	is_local_route = local_route(r->network, r->netmask, r->gateway, rgi);
	if (is_local_route == LR_ERROR){
		goto done;
	}

	sprintf (out, "%s add -net %s netmask %s",ROUTE_PATH,network,netmask);
	if (r->flags & RT_METRIC_DEFINED){
		sprintf(out, "%s metric %d",out,r->metric);
	}
	if (is_on_link (is_local_route, flags, rgi)){
		sprintf(out,"%s dev %s",out,rgi->iface);
	}else{
		sprintf(out, "%s gw %s",out,gateway);
	}
	status = system(out);
printf("## %s %d %s ##\n",__func__,__LINE__,out);
	//status = openvpn_execve_check (&argv, es, 0, "ERROR: Linux route add command failed");
done:
	if (status){
		r->flags |= RT_ADDED;
	}else{
		r->flags &= ~RT_ADDED;
	}
	free(out);
}


char * print_in6_addr_netbits_only( struct in6_addr network_copy, int netbits)
{
	int byte = 15;
	int bits_to_clear = 128 - netbits;

	while( byte >= 0 && bits_to_clear > 0 )
	{
		if ( bits_to_clear >= 8 ){
			network_copy.s6_addr[byte--] = 0;
			bits_to_clear -= 8; 
		}else{
			network_copy.s6_addr[byte--] &= (0xff << bits_to_clear); 
			bits_to_clear = 0; 
		}
	}

	return print_in6_addr( network_copy, 0);
}

void add_route_ipv6 (struct route_ipv6 *r6,struct options *opt , unsigned int flags)
{
	char *network;
	char *gateway;
	bool status = false;

	bool gateway_needed = false;

	int dev = dev_type_enum (opt->dev, opt->dev_type);

	if(flags){}

	if (!r6->defined){
		return;
	}

	network = print_in6_addr_netbits_only( r6->network, r6->netbits);
	gateway = print_in6_addr( r6->gateway, 0);

	if ( !opt->tun_ipv6 )
	{
		MM("add_route_ipv6(): not adding %s/%d, no IPv6 on if %s \n", network, r6->netbits, opt->dev);
		return;
	}

	char *out = malloc(256);
	memset(out,0x00,256);
	MM("add_route_ipv6(%s/%d -> %s metric %d) dev %s \n",network, r6->netbits, gateway, r6->metric, opt->dev);

	if (dev == DEV_TYPE_TAP && !(r6->metric_defined && r6->metric == 0 ))
	{
		gateway_needed = true;
	}

	sprintf(out, "%s -A inet6 add %s/%d dev %s", ROUTE_PATH,network,r6->netbits,opt->dev);
	if (gateway_needed){
		sprintf(out, "%s gw %s",out,gateway);
	}
	if (r6->metric_defined && r6->metric > 0 ){
		sprintf(out, "%s metric %d",out, r6->metric);
	}

	status = system(out);

	r6->defined = status;
	free(out);
}

void delete_route (struct route_ipv4 *r, struct options *opt,unsigned int flags, struct route_gateway_info *rgi)
{
	char network[64]={0,};
	char netmask[64]={0,};
	int is_local_route;

	if(opt){}
	if(flags){}

#if 0
	if ((r->flags & (RT_DEFINED|RT_ADDED)) != (RT_DEFINED|RT_ADDED)){
		return;
	}
#endif	
	char *out = malloc(256);
	memset(out,0x00,256);

	print_in_addr_t(r->network,0,network);
	print_in_addr_t(r->netmask,0,netmask);

	is_local_route = local_route(r->network, r->netmask, r->gateway, rgi);
	if (is_local_route == LR_ERROR){
			printf("## end %s %d ##\n",__func__,__LINE__);
		goto done;
	}

	sprintf(out, "%s del -net %s netmask %s", ROUTE_PATH,network,netmask);
	if (r->flags & RT_METRIC_DEFINED){
		sprintf(out, "%s metric %d",out,r->metric);
	}
	system(out);
	printf("## %s %d %s ##\n",__func__,__LINE__,out);
done:
	r->flags &= ~RT_ADDED;
	free(out);
}

void delete_route_ipv6 (struct route_ipv6 *r6,struct options *opt, unsigned int flags)
{
	char *network;
	char *gateway;
	bool gateway_needed = false;

	if(flags){}

	int dev = dev_type_enum (opt->dev, opt->dev_type);

	if (!r6->defined){
		return;
	}

	char *out = malloc(256);
	memset(out,0x00,256);


	network = print_in6_addr_netbits_only( r6->network, r6->netbits);
	gateway = print_in6_addr( r6->gateway, 0);

	if (!opt->tun_ipv6)
	{
		free(out);
		MM("delete_route_ipv6(): not deleting %s/%d, no IPv6 on if %s \n", network, r6->netbits, opt->dev);
		return;
	}

	MM("delete_route_ipv6(%s/%d)\n", network, r6->netbits );

	if ( dev == DEV_TYPE_TAP && !(r6->metric_defined && r6->metric == 0 ) )
	{
		gateway_needed = true;
	}

	sprintf (out, "%s -A inet6 del %s/%d dev %s", ROUTE_PATH,network,r6->netbits,opt->dev);
	if (gateway_needed){
		sprintf(out, "%s gw %s",out,gateway);
	}
	if (r6->metric_defined && r6->metric > 0 ){
		sprintf(out, "%s  metric %d",out,r6->metric);
	}

	MM("## %s %d %s ##\n",__func__,__LINE__,out);

	system(out);
	free(out);
}

void get_default_gateway (struct route_gateway_info *rgi)
{
	int sd = -1;
	char best_name[16];
	best_name[0] = 0;

	{
		FILE *fp = fopen ("/proc/net/route", "r");
		if (fp)
		{
			char line[256];
			int count = 0;
			unsigned int lowest_metric = UINT_MAX;
			in_addr_t best_gw = 0;
			bool found = false;
			while (fgets (line, sizeof (line), fp) != NULL)
			{
				if (count)
				{
					unsigned int net_x = 0;
					unsigned int mask_x = 0;
					unsigned int gw_x = 0;
					unsigned int metric = 0;
					unsigned int flags = 0;
					char name[16];
					name[0] = 0;
					int np = sscanf (line, "%15s\t%x\t%x\t%x\t%*s\t%*s\t%d\t%x", 
							name,
							&net_x,
							&gw_x,
							&flags,
							&metric,
							&mask_x);
					if (np == 6 && (flags & IFF_UP))
					{
						in_addr_t net = ntohl (net_x);
						in_addr_t mask = ntohl (mask_x);
						in_addr_t gw = ntohl (gw_x);

						if (!net && !mask && metric < lowest_metric)
						{
							found = true;
							best_gw = gw;
							strcpy (best_name, name);
							lowest_metric = metric;
						}
					}
				}
				++count;
			}
			fclose (fp);

			if (found)
			{
				rgi->gateway.addr = best_gw;
				rgi->flags |= RGI_ADDR_DEFINED;
				if (!rgi->gateway.addr && best_name[0]){
					rgi->flags |= RGI_ON_LINK;
				}
			}
		}
	}

	if (rgi->flags & RGI_ADDR_DEFINED)
	{
		struct ifreq *ifr, *ifend;
		in_addr_t addr, netmask;
		struct ifreq ifreq;
		struct ifconf ifc;
		struct ifreq ifs[20];

		if ((sd = socket (AF_INET, SOCK_DGRAM, 0)) < 0)
		{
			MM("GDG:%s %d  socket() failed\n",__func__,__LINE__);
			goto done;
		}
		ifc.ifc_len = sizeof (ifs);
		ifc.ifc_req = ifs;
		if (ioctl (sd, SIOCGIFCONF, &ifc) < 0)
		{
			MM("GDG: %s %d  ioctl(SIOCGIFCONF) failed",__func__,__LINE__);
			goto done;
		}

		ifend = ifs + (ifc.ifc_len / sizeof (struct ifreq));
		for (ifr = ifc.ifc_req; ifr < ifend; ifr++)
		{
			if (ifr->ifr_addr.sa_family == AF_INET)
			{
				addr = ntohl(((struct sockaddr_in *) &ifr->ifr_addr)->sin_addr.s_addr);
				strncpynt (ifreq.ifr_name, ifr->ifr_name, sizeof (ifreq.ifr_name));

				if (ioctl (sd, SIOCGIFFLAGS, &ifreq) < 0){
					continue;
				}
				if (!(ifreq.ifr_flags & IFF_UP)){
					continue;
				}

				if (rgi->flags & RGI_ON_LINK)
				{
					if (strcmp(ifreq.ifr_name, best_name)){
						continue;
					}
				}
				else
				{
					if (ioctl (sd, SIOCGIFNETMASK, &ifreq) < 0){
						continue;
					}
					netmask = ntohl(((struct sockaddr_in *) &ifreq.ifr_addr)->sin_addr.s_addr);

					if (((rgi->gateway.addr ^ addr) & netmask) != 0){
						continue;
					}

					rgi->gateway.netmask = netmask;
					rgi->flags |= RGI_NETMASK_DEFINED;
				}

				strncpynt (rgi->iface, ifreq.ifr_name, sizeof(rgi->iface));
				rgi->flags |= RGI_IFACE_DEFINED;

				memset (&ifreq.ifr_hwaddr, 0, sizeof (struct sockaddr));
				if (ioctl (sd, SIOCGIFHWADDR, &ifreq) < 0)
				{
					MM("GDG: %s %d  SIOCGIFHWADDR(%s) failed",__func__,__LINE__,ifreq.ifr_name);
					goto done;
				}
				memcpy (rgi->hwaddr, &ifreq.ifr_hwaddr.sa_data, 6);
				rgi->flags |= RGI_HWADDR_DEFINED;

				break;
			}
		}
	}

done:
	if (sd >= 0){
		close (sd);
	}
}


bool netmask_to_netbits (in_addr_t network,in_addr_t netmask, int *netbits)
{
	int i;
	int addrlen = sizeof (in_addr_t) * 8;

	if ((network & netmask) == network)
	{
		for (i = 0; i <= addrlen; ++i)
		{
			in_addr_t mask = netbits_to_netmask (i);
			if (mask == netmask)
			{
				if (i == addrlen){
					*netbits = -1;
				}else{
					*netbits = i;
				}
				return true;
			}
		}
	}
	return false;
}


void get_bypass_addresses (struct route_bypass *rb, unsigned int flags)
{
	if(rb){}
	if(flags){}
}


int test_local_addr (in_addr_t addr,struct route_gateway_info *rgi)
{
	if (rgi)
	{
		if (local_route (addr, 0xFFFFFFFF, rgi->gateway.addr, rgi)){
			return TLA_LOCAL;
		}else{
			return TLA_NONLOCAL;
		}
	}
	return TLA_NOT_IMPLEMENTED;
}


