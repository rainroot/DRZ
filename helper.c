#include <rain_common.h>


char * print_netmask (int netbits,char * out)
{
	const in_addr_t netmask = netbits_to_netmask (netbits);
	//char str[65]={0,};
	char *str = malloc(64);
	memset(str,0x00,64);
	print_in_addr_t (netmask, 0,str);
	sprintf(out, "%s (/%d)", str, netbits);
	free(str);
	return out;
}

char * print_opt_route_gateway (const in_addr_t route_gateway,char * out)
{
	//char str[65]={0,};
	char *str = malloc(64);
	memset(str,0x00,64);
	print_in_addr_t(route_gateway, 0,str);
	sprintf(out,"route-gateway %s",str);
	free(str);
	return out;
}

char * print_opt_route_gateway_dhcp (char *out)
{
	sprintf(out, "route-gateway dhcp");
	return out;
}

char * print_opt_route (const in_addr_t network, const in_addr_t netmask,char *out)
{
	//char str[65]={0,};
	char *str = malloc(64);
	memset(str,0x00,64);
	if (netmask){
		print_in_addr_t (network, 0,str);
		sprintf(out, "route %s",str);
		memset(str,0x00,64);
		print_in_addr_t (netmask, 0,str);
		sprintf(out, "%s %s", out,str);
	}else{
		print_in_addr_t (network, 0,str);
		sprintf(out, "route %s",str);
	}
	free(str);
	return out;
}

char * print_opt_topology (const int topology,char *out)
{
	sprintf(out, "topology %s", print_topology (topology));
	return out;
}

char * print_str_int (const char *str, const int i,char *out)
{
	sprintf(out, "%s %d", str, i);
	return out;
}

char * print_str (const char *str,char *out)
{
	sprintf(out, "%s", str);
	return out;
}

void helper_add_route (const in_addr_t network, const in_addr_t netmask, struct options *o)
{
	rol_check_alloc (o);
	//char str0[65]={0,};
	//char str1[65]={0,};
	char *str0 = malloc(64);
	memset(str0,0x00,64);
	char *str1 = malloc(64);
	memset(str1,0x00,64);
	print_in_addr_t (network, 0,str0);
	print_in_addr_t (netmask, 0,str1);
	add_route_to_option_list (o->routes, str0,str1,NULL,NULL);
	free(str0);
	free(str1);
}

void verify_common_subnet (const char *opt, const in_addr_t a, const in_addr_t b, const in_addr_t subnet)
{
	//char str0[65]={0,};
	//char str1[65]={0,};
	//char str2[65]={0,};

	char *str0 = malloc(64);
	memset(str0,0x00,64);
	char *str1 = malloc(64);
	memset(str1,0x00,64);
	char *str2 = malloc(64);
	memset(str2,0x00,64);
	print_in_addr_t (a, 0,str0);
	print_in_addr_t (b, 0,str1);
	print_in_addr_t (subnet, 0,str2);

	if ((a & subnet) != (b & subnet)){
		MM("%s IP addresses %s and %s are not in the same %s subnet\n",opt,str0,str1,str2);
	}
	free(str0);
	free(str1);
	free(str2);
}


void helper_client_server (struct options *o)
{

	const int dev = dev_type_enum (o->dev, o->dev_type);
	const int topology = o->topology;

	//char out[2048]={0,};
	//char str0[65]={0,};
	//char str1[65]={0,};

	char *str0 = malloc(64);
	memset(str0,0x00,64);
	char *str1 = malloc(64);
	memset(str1,0x00,64);

	char *out = malloc(2048);
	memset(out,0x00,2048);

	/* 
	 *
	 * HELPER DIRECTIVE for IPv6
	 *
	 * server-ipv6 2001:db8::/64
	 *
	 * EXPANDS TO:
	 *
	 * tun-ipv6
	 * push "tun-ipv6"
	 * ifconfig-ipv6 2001:db8::1 2001:db8::2
	 * if !nopool: 
	 *   ifconfig-ipv6-pool 2001:db8::1:0/64
	 * 
	 */
	if ( o->server_ipv6_defined )
	{
		if ( ! o->server_defined )
		{
			MM("--server-ipv6 must be used together with --server\n");
		}
		if ( o->server_flags & SF_NOPOOL )
		{
			MM("--server-ipv6 is incompatible with 'nopool' option\n");
		}
		if ( o->ifconfig_ipv6_pool_defined )
		{
			MM("--server-ipv6 already defines an ifconfig-ipv6-pool, so you can't also specify --ifconfig-pool explicitly\n");
		}

		o->ifconfig_ipv6_local = 
			print_in6_addr( add_in6_addr( o->server_network_ipv6, 1), 0);
		o->ifconfig_ipv6_remote = 
			print_in6_addr( add_in6_addr( o->server_network_ipv6, 2), 0);
		o->ifconfig_ipv6_netbits = o->server_netbits_ipv6;

		o->ifconfig_ipv6_pool_defined = true;
		o->ifconfig_ipv6_pool_base = 
			add_in6_addr( o->server_network_ipv6, 0x1000 );
		o->ifconfig_ipv6_pool_netbits = o->server_netbits_ipv6;

		o->tun_ipv6 = true;

		push_option(o, "tun-ipv6");
	}

	/*
	 *
	 * HELPER DIRECTIVE:
	 *
	 * server 10.8.0.0 255.255.255.0
	 *
	 * EXPANDS TO:
	 *
	 * mode server
	 * tls-server
	 * push "topology [topology]"
	 *
	 * if tun AND (topology == net30 OR topology == p2p):
	 *   ifconfig 10.8.0.1 10.8.0.2
	 *   if !nopool: 
	 *     ifconfig-pool 10.8.0.4 10.8.0.251
	 *   route 10.8.0.0 255.255.255.0
	 *   if client-to-client:
	 *     push "route 10.8.0.0 255.255.255.0"
	 *   else if topology == net30:
	 *     push "route 10.8.0.1"
	 *
	 * if tap OR (tun AND topology == subnet):
	 *   ifconfig 10.8.0.1 255.255.255.0
	 *   if !nopool: 
	 *     ifconfig-pool 10.8.0.2 10.8.0.254 255.255.255.0
	 *   push "route-gateway 10.8.0.1"
	 */

	if (o->server_defined)
	{
		int netbits = -2;
		bool status = false;

		if (o->client){
			MM("--server and --client cannot be used together\n");
		}

		if (o->server_bridge_defined || o->server_bridge_proxy_dhcp){
			MM( "--server and --server-bridge cannot be used together\n");
		}

		if (o->shared_secret_file){
			MM("--server and --secret cannot be used together (you must use SSL/TLS keys)\n");
		}

		if (!(o->server_flags & SF_NOPOOL) && o->ifconfig_pool_defined){
			MM("--server already defines an ifconfig-pool, so you can't also specify --ifconfig-pool explicitly\n");
		}

		if (!(dev == DEV_TYPE_TAP || dev == DEV_TYPE_TUN)){
			MM("--server directive only makes sense with --dev tun or --dev tap\n");
		}

		status = netmask_to_netbits (o->server_network, o->server_netmask, &netbits);
		if (!status){
			MM("--server directive network/netmask combination is invalid\n");
		}

		if (netbits < 0){
			MM("--server directive netmask is invalid\n");
		}

		if (netbits < IFCONFIG_POOL_MIN_NETBITS){
			memset(out,0x00,2048);
			print_netmask (IFCONFIG_POOL_MIN_NETBITS,out);
			MM("--server directive netmask allows for too many host addresses (subnet must be %s or higher)\n",out);
		}

		if (dev == DEV_TYPE_TUN)
		{
			int pool_end_reserve = 4;

			if (netbits > 29){
				memset(out,0x00,2048);
				print_netmask (30,out);
				MM("--server directive when used with --dev tun must define a subnet of %s or lower\n", out);
			}

			if (netbits == 29){
				pool_end_reserve = 0;
			}

			o->mode = (int)SERVER;
			o->tls_server = true;

			if (topology == TOP_NET30 || topology == TOP_P2P)
			{

				if (!(o->server_flags & SF_NOPOOL))
				{
					o->ifconfig_pool_defined = true;
					o->ifconfig_pool_start = o->server_network + 4;
					o->ifconfig_pool_end = (o->server_network | ~o->server_netmask) - pool_end_reserve;
					ifconfig_pool_verify_range (o->ifconfig_pool_start, o->ifconfig_pool_end);
				}

				helper_add_route (o->server_network, o->server_netmask, o);
				if (o->enable_c2c){
					memset(out,0x00,2048);
					print_opt_route (o->server_network, o->server_netmask,out);
					push_option (o,out);
				}else if (topology == TOP_NET30){
					memset(out,0x00,2048);
					print_opt_route (o->server_network + 1, 0,out);
					push_option (o,out);
				}
			}
			else if (topology == TOP_SUBNET)
			{
				print_in_addr_t (o->server_network + 1, 0,str0);
				print_in_addr_t (o->server_netmask, 0,str1);
				sprintf(o->ifconfig_local,"%s",str0);
				sprintf(o->ifconfig_remote_netmask,"%s",str1);

				//o->ifconfig_local = print_in_addr_t (o->server_network + 1, 0);
				//o->ifconfig_remote_netmask = print_in_addr_t (o->server_netmask, 0);

				if (!(o->server_flags & SF_NOPOOL))
				{
					o->ifconfig_pool_defined = true;
					o->ifconfig_pool_start = o->server_network + 2;
					o->ifconfig_pool_end = (o->server_network | ~o->server_netmask) - 2;
					ifconfig_pool_verify_range (o->ifconfig_pool_start, o->ifconfig_pool_end);
				}
				o->ifconfig_pool_netmask = o->server_netmask;
				memset(out,0x00,2048);
				print_opt_route_gateway (o->server_network + 1,out);
				push_option (o,out);
			}
			else{
				//ASSERT (0);
			}

			memset(out,0x00,2048);
			print_opt_topology (topology,out);
			push_option (o,out);
		}
		else if (dev == DEV_TYPE_TAP)
		{
			if (netbits > 30){
				memset(out,0x00,2048);
				print_netmask (30,out);
				MM("--server directive when used with --dev tap must define a subnet of %s or lower\n", out);
			}

			o->mode = SERVER;
			o->tls_server = true;

			print_in_addr_t (o->server_network + 1, 0,str0);
			print_in_addr_t (o->server_netmask, 0,str1);
			sprintf(o->ifconfig_local,"%s",str0);
			sprintf(o->ifconfig_remote_netmask,"%s",str1);

			//o->ifconfig_local = print_in_addr_t (o->server_network + 1, 0);
			//o->ifconfig_remote_netmask = print_in_addr_t (o->server_netmask, 0);

			if (!(o->server_flags & SF_NOPOOL))
			{
				o->ifconfig_pool_defined = true;
				o->ifconfig_pool_start = o->server_network + 2;
				o->ifconfig_pool_end = (o->server_network | ~o->server_netmask) - 1;
				ifconfig_pool_verify_range (o->ifconfig_pool_start, o->ifconfig_pool_end);
			}
			o->ifconfig_pool_netmask = o->server_netmask;

			memset(out,0x00,2048);
			print_opt_route_gateway (o->server_network + 1,out);
			push_option (o,out);
		}
		else
		{
			//ASSERT (0);
		}

		if ((dev == DEV_TYPE_TAP || topology == TOP_SUBNET))
		{
			o->push_ifconfig_constraint_defined = true;
			o->push_ifconfig_constraint_network = o->server_network;
			o->push_ifconfig_constraint_netmask = o->server_netmask;
		}
	}

	/*
	 * HELPER DIRECTIVE:
	 *
	 * server-bridge 10.8.0.4 255.255.255.0 10.8.0.128 10.8.0.254
	 *
	 * EXPANDS TO:
	 *
	 * mode server
	 * tls-server
	 *
	 * ifconfig-pool 10.8.0.128 10.8.0.254 255.255.255.0
	 * push "route-gateway 10.8.0.4"
	 *
	 * OR
	 *
	 * server-bridge
	 *
	 * EXPANDS TO:
	 *
	 * mode server
	 * tls-server
	 *
	 * if !nogw:
	 *   push "route-gateway dhcp"
	 */
	else if (o->server_bridge_defined | o->server_bridge_proxy_dhcp)
	{
		if (o->client){
			MM("--server-bridge and --client cannot be used together\n");
		}

		if (!(o->server_flags & SF_NOPOOL) && o->ifconfig_pool_defined){
			MM("--server-bridge already defines an ifconfig-pool, so you can't also specify --ifconfig-pool explicitly");
		}

		if (o->shared_secret_file){
			MM("--server-bridge and --secret cannot be used together (you must use SSL/TLS keys)");
		}

		if (dev != DEV_TYPE_TAP){
			MM("--server-bridge directive only makes sense with --dev tap");
		}

		if (o->server_bridge_defined)
		{
			verify_common_subnet ("--server-bridge", o->server_bridge_ip, o->server_bridge_pool_start, o->server_bridge_netmask); 
			verify_common_subnet ("--server-bridge", o->server_bridge_pool_start, o->server_bridge_pool_end, o->server_bridge_netmask); 
			verify_common_subnet ("--server-bridge", o->server_bridge_ip, o->server_bridge_pool_end, o->server_bridge_netmask); 
		}

		o->mode = (int)SERVER;
		o->tls_server = true;

		if (o->server_bridge_defined)
		{
			o->ifconfig_pool_defined = true;
			o->ifconfig_pool_start = o->server_bridge_pool_start;
			o->ifconfig_pool_end = o->server_bridge_pool_end;
			ifconfig_pool_verify_range (o->ifconfig_pool_start, o->ifconfig_pool_end);
			o->ifconfig_pool_netmask = o->server_bridge_netmask;
			memset(out,0x00,2048);
			print_opt_route_gateway (o->server_bridge_ip,out);
			push_option (o, out);
		}
		else if (o->server_bridge_proxy_dhcp && !(o->server_flags & SF_NO_PUSH_ROUTE_GATEWAY))
		{
			memset(out,0x00,2048);
			print_opt_route_gateway_dhcp(out);	
			push_option (o,out);
		}
	}
	else{
		/*
		 * HELPER DIRECTIVE:
		 *
		 * client
		 *
		 * EXPANDS TO:
		 *
		 * pull
		 * tls-client
		 */
		if (o->client)
		{
			if (o->key_method != 2){
				MM("--client requires --key-method 2\n");
			}

			o->pull = true;
			o->tls_client = true;
		}
	}
	free(str0);
	free(str1);
	free(out);
}

/*
 *
 * HELPER DIRECTIVE:
 *
 * keepalive 10 60
 *
 * EXPANDS TO:
 *
 * if mode server:
 *   ping 10
 *   ping-restart 120
 *   push "ping 10"
 *   push "ping-restart 60"
 * else
 *   ping 10
 *   ping-restart 60
 */
void helper_keepalive (struct options *o)
{
	//char out[2048]={0,};
	char *out=malloc(2048);
	memset(out,0x00,2048);

	if (o->keepalive_ping || o->keepalive_timeout)
	{
		/*
		 * Sanity checks.
		 */
		if (o->keepalive_ping <= 0 || o->keepalive_timeout <= 0){
			MM("--keepalive parameters must be > 0");
		}
		if (o->keepalive_ping * 2 > o->keepalive_timeout){
			MM("the second parameter to --keepalive (restart timeout=%d) must be at least twice the value of the first parameter (ping interval=%d).  A ratio of 1:5 or 1:6 would be even better.  Recommended setting is --keepalive 10 60.\n", o->keepalive_timeout,o->keepalive_ping);
		}
		if (o->ping_send_timeout || o->ping_rec_timeout){
			MM("--keepalive conflicts with --ping, --ping-exit, or --ping-restart.  If you use --keepalive, you don't need any of the other --ping directives.\n");
		}

		/*
		 * Expand.
		 */
		if (o->mode == CLIENT)
		{
			o->ping_rec_timeout_action = PING_RESTART;
			o->ping_send_timeout = o->keepalive_ping;
			o->ping_rec_timeout = o->keepalive_timeout;
		}
		else if (o->mode == SERVER)
		{
			o->ping_rec_timeout_action = PING_RESTART;
			o->ping_send_timeout = o->keepalive_ping;
			o->ping_rec_timeout = o->keepalive_timeout * 2;
			memset(out,0x00,2048);
			print_str_int ("ping", o->keepalive_ping,out);
			push_option (o,out);
			memset(out,0x00,2048);
			print_str_int ("ping-restart", o->keepalive_timeout,out);
			push_option (o, out);
		}
		else
		{
			//ASSERT (0);
		}
	}
	free(out);
}

/*
 *
 * HELPER DIRECTIVE:
 *
 * tcp-nodelay
 *
 * EXPANDS TO:
 *
 * if mode server:
 *   socket-flags TCP_NODELAY
 *   push "socket-flags TCP_NODELAY"
 */
void helper_tcp_nodelay (struct options *o)
{
	//char out[2048]={0,};
	char *out = malloc(2048);
	memset(out,0x00,2048);

	if (o->server_flags & SF_TCP_NODELAY_HELPER)
	{
		if (o->mode == SERVER)
		{
			o->sockflags |= SF_TCP_NODELAY;	  
			memset(out,0x00,2048);
			print_str ("socket-flags TCP_NODELAY",out);
			push_option (o,out);
		}
		else
		{
			//ASSERT (0);
		}
	}
	free(out);
}

