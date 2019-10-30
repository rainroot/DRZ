#include <rain_common.h>


struct proto_names {
	char *short_form;
	char *display_form;
	bool  is_dgram;
	bool  is_net;
	unsigned short proto_af;
};

static const struct proto_names proto_names[PROTO_N] = {
	{"proto-uninitialized",	"proto-NONE",	0,0, AF_UNSPEC},
	{"udp",        		"UDPv4",	1,1, AF_INET},
	{"tcp-server", 		"TCPv4_SERVER",	0,1, AF_INET},
	{"tcp-client", 		"TCPv4_CLIENT",	0,1, AF_INET},
	{"tcp",        		"TCPv4",	0,1, AF_INET},
	{"udp6"       ,		"UDPv6",	1,1, AF_INET6},
	{"tcp6-server",		"TCPv6_SERVER",	0,1, AF_INET6},
	{"tcp6-client",		"TCPv6_CLIENT",	0,1, AF_INET6},
	{"tcp6"       ,		"TCPv6",	0,1, AF_INET6},
};

bool proto_is_net(int proto)
{
	if (proto < 0 || proto >= PROTO_N){
	}
	return proto_names[proto].is_net;
}

bool proto_is_dgram(int proto)
{
	if (proto < 0 || proto >= PROTO_N){
	}
	return proto_names[proto].is_dgram;
}

bool proto_is_udp(int proto)
{
	if (proto < 0 || proto >= PROTO_N){
	}
	return proto_names[proto].is_dgram&&proto_names[proto].is_net;
}

bool proto_is_tcp(int proto)
{
	if (proto < 0 || proto >= PROTO_N){
	}
	return (!proto_names[proto].is_dgram)&&proto_names[proto].is_net;
}

unsigned short proto_sa_family(int proto)
{
	if (proto < 0 || proto >= PROTO_N){
	}
	return proto_names[proto].proto_af;
}

int ascii2proto (const char* proto_name)
{
	int i;
	for (i = 0; i < PROTO_N; ++i){
		if (!strcmp (proto_name, proto_names[i].short_form)){
			return i;
		}
	}
	return -1;
}

char * proto2ascii (int proto, bool display_form)
{
	if (proto < 0 || proto >= PROTO_N){
		return "[unknown protocol]";
	}else if (display_form){
		return proto_names[proto].display_form;
	}else{
		return proto_names[proto].short_form;
	}
}

char *print_in_addr_t (in_addr_t addr, unsigned int flags,char *str)
{
	struct in_addr ia;
	memset(&ia,0x00,sizeof(struct in_addr));

	if (addr || !(flags & IA_EMPTY_IF_UNDEF))
	{
		ia.s_addr = (flags & IA_NET_ORDER) ? addr : htonl (addr);
		sprintf(str,"%s",inet_ntoa(ia));
		return str;
	}
	return NULL;
}


char * print_in6_addr (struct in6_addr a6, unsigned int flags)
{
	char *tmp_out_buf = malloc(64);
	memset(tmp_out_buf,0x00,64);

	if (memcmp(&a6, &in6addr_any, sizeof(a6)) != 0 || !(flags & IA_EMPTY_IF_UNDEF))
	{
		inet_ntop (AF_INET6, &a6, tmp_out_buf, sizeof(tmp_out_buf)-1);
		return tmp_out_buf;
	}
	return NULL;
}


struct in6_addr add_in6_addr( struct in6_addr base, uint32_t add )
{
	int i;

	for( i=15; i>=0 && add > 0 ; i-- )
	{
		register int carry;
		register uint32_t h;

		h = (unsigned char) base.s6_addr[i];
		base.s6_addr[i] = (h+add) & UINT8_MAX;

		carry = ((h & 0xff)  + (add & 0xff)) >> 8;
		add = (add>>8) + carry;
	}
	return base;
}

int proto_remote (int proto, bool remote)
{
	if(!(proto >= 0 && proto < PROTO_N)){
		MM("### %s %d ###\n",__func__,__LINE__);
	}
	if (remote)
	{
		switch (proto)
		{
			case PROTO_TCPv4_SERVER: return PROTO_TCPv4_CLIENT;
			case PROTO_TCPv4_CLIENT: return PROTO_TCPv4_SERVER;
			case PROTO_TCPv6_SERVER: return PROTO_TCPv4_CLIENT;
			case PROTO_TCPv6_CLIENT: return PROTO_TCPv4_SERVER;
			case PROTO_UDPv6: return PROTO_UDPv4;
		}
	}
	else
	{
		switch (proto)
		{
			case PROTO_TCPv6_SERVER: return PROTO_TCPv4_SERVER;
			case PROTO_TCPv6_CLIENT: return PROTO_TCPv4_CLIENT;
			case PROTO_UDPv6: return PROTO_UDPv4;
		}
	}
	return proto;
}

int openvpn_getaddrinfo (unsigned int flags, const char *hostname,int resolve_retry_seconds,int *signal_received,int ai_family,struct addrinfo **res)
{
	struct addrinfo hints;
	int status;
#if 0
	if (!hostname){
		hostname = "::";
	}

	if (flags & GETADDR_RANDOMIZE){
		hostname = hostname_randomize(hostname);
	}
#endif

	if(signal_received){}

	memset(&hints,0x00,sizeof(struct addrinfo));
	hints.ai_family = ai_family;
	hints.ai_flags = AI_NUMERICHOST;
	hints.ai_socktype = SOCK_STREAM;

	status = getaddrinfo(hostname, NULL, &hints, res);

	if (status != 0) /* parse as numeric address failed? */
	{
		const int fail_wait_interval = 5; /* seconds */
		int resolve_retries = (flags & GETADDR_TRY_ONCE) ? 1 : (resolve_retry_seconds / fail_wait_interval);
		const char *fmt;

		fmt = "RESOLVE: Cannot resolve host address: %s: %s";
		if (!resolve_retry_seconds){
			fmt = "RESOLVE: Cannot resolve host address: %s: %s (I would have retried this name query if you had specified the --resolv-retry option.)";
		}

		if (!(flags & GETADDR_RESOLVE) || status == EAI_FAIL)
		{
			MM("## ERR: RESOLVE: Cannot parse IP address: %s ##\n", hostname);
			goto done;
		}

		while (true)
		{
			hints.ai_flags = 0;
			status = getaddrinfo(hostname, NULL, &hints, res);
			if (0 == status){
				break;
			}

			MM("ERR %s %s %s ##\n",fmt, hostname,gai_strerror(status));
			if (--resolve_retries <= 0){
				goto done;
			}

			sleep (fail_wait_interval);
		}

	}
	else
	{
	}

done:
	return status;
}

in_addr_t getaddr (unsigned int flags, const char *hostname,int resolve_retry_seconds,bool *succeeded,int *signal_received)
{
	struct addrinfo *ai;
	int status;
	status = openvpn_getaddrinfo(flags, hostname, resolve_retry_seconds, signal_received, AF_INET, &ai);
	if(status==0) {
		struct in_addr ia;
		if(succeeded){
			*succeeded=true;
		}
		ia = ((struct sockaddr_in*)ai->ai_addr)->sin_addr;
		freeaddrinfo(ai);
		return (flags & GETADDR_HOST_ORDER) ? ntohl (ia.s_addr) : ia.s_addr;
	} else {
		if(succeeded){
			*succeeded =false;
		}
		return 0;
	}
}

bool mac_addr_safe (const char *mac_addr)
{
	if (!mac_addr){
		return false;
	}

	if (strlen (mac_addr) > 17){
		return false;
	}

	{
		int nnum = 0;
		const char *p = mac_addr;
		int c;

		while ((c = *p++))
		{
			if ( (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F') )
			{
				++nnum;
				if (nnum > 2)
					return false;
			}
			else if (c == ':')
			{
				nnum = 0;
			}
			else
				return false;
		}
	}
	return true;
}

bool dns_addr_safe (char *addr)
{
	if (addr)
	{
		size_t len = strlen (addr);
		return len > 0 && len <= 255 && string_class (addr, CC_ALNUM|CC_DASH|CC_DOT, 0);
	}
	else{
		return false;
	}
}

bool ip_or_dns_addr_safe (char *addr,bool allow_fqdn)
{
	if (ip_addr_dotted_quad_safe (addr)){
		return true;
	}else if (allow_fqdn){
		return dns_addr_safe (addr);
	}else{
		return false;
	}
}


bool ipv6_addr_safe (const char *ipv6_text_addr)
{
	if (!ipv6_text_addr){
		return false;
	}

	if (strlen (ipv6_text_addr) > INET6_ADDRSTRLEN ){
		return false;
	}

	{
		struct in6_addr a6;
		return inet_pton( AF_INET6, ipv6_text_addr, &a6 ) == 1;
	}
}

bool legal_ipv4_port (int port)
{
	return port > 0 && port < 65536;
}

bool ip_addr_dotted_quad_safe (const char *dotted_quad)
{
	if (!dotted_quad){
		return false;
	}

	if (strlen (dotted_quad) > 15){
		return false;
	}

	{
		int nnum = 0;
		const char *p = dotted_quad;
		int c;

		while ((c = *p++))
		{
			if (c >= '0' && c <= '9')
			{
				++nnum;
				if (nnum > 3){
					return false;
				}
			}
			else if (c == '.')
			{
				nnum = 0;
			}
			else{
				return false;
			}
		}
	}

	{
		struct in_addr a;
		return inet_aton (dotted_quad, &a) == OIA_IP;
	}
}
#if 0
bool addr_defined (struct openvpn_sockaddr *addr)
{
	if (!addr){ 
		return 0;
	}
	switch (addr->addr.sa.sa_family) {
		case AF_INET: 
			return addr->addr.in4.sin_addr.s_addr != 0;
		case AF_INET6: 
			return !IN6_IS_ADDR_UNSPECIFIED(&addr->addr.in6.sin6_addr);
		default: 
			return 0;
	}
}

bool link_socket_actual_defined (struct link_socket_actual *act)
{
	return act && addr_defined (&act->dest);
}
#endif


in_addr_t link_socket_current_remote (struct main_data *md)
{
	char out[64]={0,};
	if (md->server_addr.sin_family != AF_INET){
		return IPV4_INVALID_ADDR;
	}

	if (md->server_addr.sin_addr.s_addr != 0 ){
		print_in_addr_t (ntohl(md->server_addr.sin_addr.s_addr),0,out);
		return ntohl (md->server_addr.sin_addr.s_addr);
#if 0
	}else if (addr_defined (&lsa->remote)){

		MM("## %s %d ##\n",__func__,__LINE__);
		return ntohl (lsa->remote.addr.in4.sin_addr.s_addr);
#endif
	}else{
		return 0;
	}
}



int tcp_server(char *local_ip, int port)
{
	int sock;
	struct sockaddr_in server_addr;

	struct hostent *host=NULL;

	if ((sock = socket(PF_INET,SOCK_STREAM,IPPROTO_TCP)) == -1){
		return -1;
	}
	memset(&server_addr, 0, sizeof(server_addr));
	server_addr.sin_family = AF_INET;
	server_addr.sin_port = htons(port);
	if(local_ip != NULL){
		host = gethostbyname(local_ip);
		if(host == NULL){
			printf("########### ERROR #### %s %d ##\n",__func__,__LINE__);
			exit(0);
		}
		memcpy(&server_addr.sin_addr,host->h_addr_list[0],host->h_length);
	}else{
		server_addr.sin_addr.s_addr = htonl(INADDR_ANY);
	}
	if (bind(sock, (struct sockaddr *) &server_addr, sizeof(server_addr)) < 0){
		return -1;
	}

	if(listen(sock,5)<0){
		MM("ERR: %s %s[:%d] EXIT()  listen error \n",__FILE__,__func__,__LINE__);
		close(sock);
		exit(1);
	}

	return sock;

}

int tcp_connect(char *addr, int port,struct main_data *md)
{
	int sock;
	struct hostent *host;
	struct sockaddr_in server_addr;

	host = gethostbyname(addr);

	if ((sock = socket(AF_INET,SOCK_STREAM,0)) == -1){
		return -1;
	}
	memset(&md->server_addr, 0, sizeof(server_addr));

	md->server_addr.sin_family = AF_INET;
	md->server_addr.sin_port = htons(port);
	md->server_addr.sin_addr = *((struct in_addr *)host->h_addr);
	bzero(&(md->server_addr.sin_zero),8);

	if(connect(sock,(struct sockaddr *)&md->server_addr,sizeof(struct sockaddr)) == -1){
		close(sock);
		return -1;
	}
	return sock;
}


