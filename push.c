#include <rain_common.h>


char * skip_leading_whitespace (char *str)
{
	while (*str)
	{
		char c = *str;
		if (!(c == ' ' || c == '\t')){
			break;
		}
		++str;
	}
	return str;
}

char * print_argv (char **p, unsigned int flags)
{
	char *out = malloc(256);
	memset(out,0x00,256);

	int i = 0;
	for (;;)
	{
		char *cp = *p++;
		if (!cp){
			break;
		}
		if (i){
			sprintf(out,"%s ",out);
		}
		if (flags & PA_BRACKET){
			sprintf(out,"%s[%s]",out,cp);
		}else{
			sprintf(out,"%s%s",out,cp);
		}
		++i;
	}
	return out;
}


char ** make_inline_array (const char *str)
{
	char line[OPTION_LINE_SIZE];
	char *buf;
	int len = 0;
	char **ret = NULL;
	int i = 0;

	buf = malloc(strlen(str)+1);
	memset(buf,0x00,strlen(str)+1);

	snprintf(buf,strlen(str)+1,"%s",str);
	while (char_parse (buf, '\n', line, sizeof (line)))
		++len;

	ret = malloc(len+1*sizeof(char *));

	
	snprintf(buf,strlen(str)+1,"%s",str);
	while (char_parse (buf, '\n', line, sizeof (line)))
	{
		chomp (line);
		if(!(i < len)){
			MM("## ERR: %s %d ##\n",__func__,__LINE__);
		}
		char *str = skip_leading_whitespace (line);
		int len = strlen(str);
		ret[i] = malloc(len);
		memcpy (ret[i], str, len);
		++i;
	}
	if(!(i <= len)){
		MM("## ERR: %s %d ##\n",__func__,__LINE__);
	}
	ret[i] = NULL;
	return ret;
}


char ** make_arg_array (const char *first, const char *parms)
{
	int base = 0;
	int n = 0;
	int idx = 0;
	char **ret = NULL;
	int max_parms = MAX_PARMS + 2;

	//char *ret[MAX_PARAMS+2];

	ret = malloc(max_parms*sizeof(char *));

	if (first)
	{
		idx = base++;
		ret[idx] = malloc(strlen(first)+1);
		memset(ret[idx],0x00,strlen(first)+1);
		snprintf(ret[idx],strlen(first)+1,"%s",first);
	}

	if (parms)
	{
		n = parse_line (parms, &ret[base], max_parms - base - 1, "make_arg_array", 0);
		//ASSERT (n >= 0 && n + base + 1 <= max_parms);
	}
	ret[base + n] = NULL;
	return ret;
}

char ** make_arg_copy (char **p)
{
	char **ret = NULL;
	int len = string_array_len (p);
	const int max_parms = len + 1;
	int i;

	ret = malloc(max_parms*sizeof(char *));
	for (i = 0; i < len; ++i){
		ret[i] = p[i];
	}

	return ret;
}

char ** make_extended_arg_array (char **p)
{
	int argc = string_array_len (p);

	if (!strcmp (p[0], INLINE_FILE_TAG) && argc == 2){
		return make_inline_array (p[1]);
	}else{
		if (argc == 0){
			return make_arg_array (NULL, NULL);
		}else if (argc == 1){
			return make_arg_array (p[0], NULL);
		}else if (argc == 2){
			return make_arg_array (p[0], p[1]);
		}else{
			return make_arg_copy (p);
		}
	}
}




int ctl_msg_process(struct epoll_ptr_data *epd,char *out)
{
	struct main_data *md=NULL;
	md = (struct main_data *)epd->gl_var;

	int ret = 0;
	char *buff = epd->ss->sk[epd->ss->renego_keyid].prb;
	int len =  epd->ss->sk[epd->ss->renego_keyid].prb_len;
	struct push_entry *e = md->opt->push_list.head;

	char str0[64]={0,};
	char str1[64]={0,};
	char str2[64]={0,};
#if 0
	char *str0=malloc(64);
	memset(str0,0x00,64);
	char *str1=malloc(64);
	memset(str1,0x00,64);
	char *str2=malloc(64);
	memset(str2,0x00,64);
#endif

	if(((strncmp(buff,"PUSH_REQUEST",12) == 0) || (strncmp(buff,"PUSH_DRIZZLE_REQUEST",12) == 0)) && (epd->ps->push_reply == false)){

		if(strncmp(buff,"PUSH_REQUEST",12) == 0){
			epd->openvpn = true;
		}else if(strncmp(buff,"PUSH_DRIZZLE_REQUEST",12) == 0){
			epd->openvpn = false;
		}

		char *cmd = "PUSH_REPLY";
		sprintf(out,"%s",cmd);
		if (md->opt->push_ifconfig_ipv6_defined){
			sprintf(out,"%s,ifconfig-ipv6 %s/%d %s",out,
					print_in6_addr(md->opt->push_ifconfig_ipv6_local, 0),
					md->opt->push_ifconfig_ipv6_netbits,
					print_in6_addr(md->opt->push_ifconfig_ipv6_remote, 0));
		}
		while(e){
			if(e->enable){
				sprintf(out,"%s,%s",out,e->option);
			}
			e = e->next;
		}

		struct user_tree_data utd;
		struct user_tree_data *ret_utd;
		unsigned int crc=0;
		crc = crc32(0L,(const Bytef *)epd->ss->common_name,strlen(epd->ss->common_name));
		memcpy((char *)&utd.key,&crc,4);

		if(md->opt->server_bridge_defined){

			pthread_mutex_lock(&md->opt->user_ip_tree_mutex);
			ret_utd = (struct user_tree_data *)rb_find(md->opt->user_ip_tree,(void *)&utd);
			pthread_mutex_unlock(&md->opt->user_ip_tree_mutex);
			if(ret_utd != NULL){
				in_addr_t ifconfig_current = ret_utd->ipaddr;
				in_addr_t ifconfig_netmask = ret_utd->netmask;
				print_in_addr_t(ifconfig_current,0,str0);
				print_in_addr_t(ifconfig_netmask,0,str1);
				sprintf(out,"%s,ifconfig %s", out,str0);
				sprintf(out,"%s %s", out,str1);
			}else{
				if((md->opt->server_bridge_pool_current  == 0) || (md->opt->server_bridge_pool_current > md->opt->server_bridge_pool_end)){
					md->opt->server_bridge_pool_current = md->opt->server_bridge_pool_start;
				}else{
					md->opt->server_bridge_pool_current++;
				}
				in_addr_t ifconfig_current = md->opt->server_bridge_pool_current;
				in_addr_t ifconfig_netmask = md->opt->server_bridge_netmask;
				print_in_addr_t(ifconfig_current,0,str0);
				print_in_addr_t(ifconfig_netmask,0,str1);
				sprintf(out,"%s,ifconfig %s", out,str0);
				sprintf(out,"%s %s", out,str1);

				ret_utd = malloc(sizeof(struct user_tree_data));
				memset(ret_utd,0x00,sizeof(struct user_tree_data));
				memcpy((char*)&ret_utd->key,&crc,4);
				memcpy(ret_utd->cn_buf,epd->ss->common_name,strlen(epd->ss->common_name));
				ret_utd->ipaddr = ifconfig_current;
				ret_utd->netmask = ifconfig_netmask;

				pthread_mutex_lock(&md->opt->user_ip_tree_mutex);
				rb_insert(md->opt->user_ip_tree,ret_utd);
				pthread_mutex_unlock(&md->opt->user_ip_tree_mutex);

			}

		}else if(md->opt->server_defined){

			pthread_mutex_lock(&md->opt->user_ip_tree_mutex);
			ret_utd = (struct user_tree_data *)rb_find(md->opt->user_ip_tree,(void *)&utd);
			pthread_mutex_unlock(&md->opt->user_ip_tree_mutex);

			if(ret_utd != NULL){
				in_addr_t ifconfig_current = ret_utd->ipaddr;
				in_addr_t ifconfig_netmask = ret_utd->netmask;
				print_in_addr_t(ifconfig_current,0,str0);
				print_in_addr_t(ifconfig_netmask,0,str1);
				sprintf(out,"%s,ifconfig %s", out,str0);
				sprintf(out,"%s %s", out,str1);
				option_iroute(md->opt,str0,"255.255.255.255",epd);
			}else{
				if((md->opt->server_pool_current == 0) || (md->opt->server_pool_current > md->opt->server_pool_end)){

					md->opt->server_pool_current = md->opt->ifconfig_pool_start;
					md->opt->server_pool_end = md->opt->ifconfig_pool_end;
				}else{
					md->opt->server_pool_current+=1;
				}

				in_addr_t ifconfig_netmask = md->opt->server_pool_current;
				md->opt->server_pool_current++;
				in_addr_t ifconfig_current = md->opt->server_pool_current;
				print_in_addr_t(ifconfig_current,0,str0);
				print_in_addr_t(ifconfig_netmask,0,str1);
				sprintf(out,"%s,ifconfig %s", out,str0);
				sprintf(out,"%s %s", out,str1);
				option_iroute(md->opt,str0,"255.255.255.255",epd);
				if(md->opt->ifconfig_pool_persist_filename != NULL){
					char str_cmd[1024]={0,};
					print_in_addr_t(ifconfig_current-2,0,str2);

					sprintf(str_cmd,"echo %s,%s >> %s",epd->ss->common_name,str2,md->opt->ifconfig_pool_persist_filename);
					system(str_cmd);
					ifconfig_pool_read(md->opt);
				}
			}
		}

		ret = strlen(out)+1;
		epd->ps->push_reply = true;

		if((md->opt->mode == SERVER) && (dev_type_enum (md->opt->dev, md->opt->dev_type) == DEV_TYPE_TUN)){
			if(md->opt->client_config_dir != NULL){

				unsigned int option_permissions_mask =
					OPT_P_INSTANCE
					| OPT_P_INHERIT
					| OPT_P_PUSH
					| OPT_P_TIMER
					| OPT_P_CONFIG
					| OPT_P_ECHO
					| OPT_P_COMP
					| OPT_P_SOCKFLAGS;

				unsigned int option_types_found = 0;

				bool ret = false;

				size_t outsize = strlen(epd->ss->common_name) + (md->opt->client_config_dir ? strlen (md->opt->client_config_dir) : 0) + 16;
				char *ccd_file = malloc(outsize);
				memset(ccd_file,0x00,outsize);


				printf("##################### %s %d %s #############\n",__func__,__LINE__,epd->ss->common_name);
				ret = gen_path((char *)md->opt->client_config_dir,epd->ss->common_name,ccd_file);
				if(ret == true){
					printf("##################### %s %d %s #############\n",__func__,__LINE__,epd->ss->common_name);
					options_server_import(md->opt,ccd_file,option_permissions_mask,&option_types_found,epd);
				}
				free(ccd_file);
			}else{
				struct user_data *ud;
				ud = malloc(sizeof(user_data_t));
				memset(ud,0x00,sizeof(user_data_t));
				ud->rfd = epd->n_fdd->net_fd;
				//ud->wfd = epd->p_fdd->pipe_wfd; //rainroot 20170330
				ud->thd_mode = THREAD_MODE_NET;
				input_list(md->li,(char *)ud);

			}
		}
		epd->ss->sk[epd->ss->renego_keyid].state = S_NORMAL_OP;

	}else if((strncmp(buff,"PUSH_REPLY",10) == 0) && (epd->ps->push_request == false)){

		printf("- %s %d -#%s#-\n",__func__,__LINE__,buff);
		unsigned int permission_mask = 
			OPT_P_UP
			| OPT_P_ROUTE_EXTRAS
			| OPT_P_SOCKBUF
			| OPT_P_SOCKFLAGS
			| OPT_P_SETENV
			| OPT_P_SHAPER
			| OPT_P_TIMER
			| OPT_P_COMP
			| OPT_P_PERSIST
			| OPT_P_MESSAGES
			| OPT_P_EXPLICIT_NOTIFY
			| OPT_P_ECHO
			| OPT_P_PULL_MODE;
		unsigned int option_types_found = 0;

		apply_push_options(md->opt,buff+(strlen("PUSH_REPLY,")),len - (strlen("PUSH_REPLY,")),permission_mask,&option_types_found);

		//show_settings (md->opt);

		struct route_gateway_info rgi;
		get_default_gateway(&rgi);
		print_default_gateway(&rgi);

		do_ifconfig(epd);

		if(md->opt->routes && md->opt->route_list){
			do_init_route_list(epd,md->opt);
			print_route_options (md->opt->routes);

			add_routes(md->opt->route_list,md->opt->route_ipv6_list,md->opt,0);

			if(md->opt->mode == SERVER){
		printf("-------------------------------------------------------------------------- %s %d -----------------------\n",__func__,__LINE__);
				bool err;
				struct ip_info *ii=NULL;
				ii = malloc(sizeof(struct ip_info));
				memset(ii,0x00,sizeof(struct ip_info));

				sprintf(ii->iface,"%s",md->opt->dev);
				ii->ipaddr = (unsigned int )htonl(get_ip_addr(md->opt->ifconfig_local,&err));
				ii->netmask = 0xffffffff;

				input_list(md->ip_li,(char *)ii);

				MM("### iface %s ip %08x netmask %08x ###\n",ii->iface,ii->ipaddr,ii->netmask);
			}
		}
#if 0
		if(md->opt->route_ipv6 && md->opt->route_ipv6_list){
			do_init_route_ipv6_list(md->opt);
		}
#endif



		epd->ps->push_request = true;

		run_up_down(md->opt,"up");
	}	
#if 0
	free(str0);
	free(str1);
	free(str2);
#endif
	return ret;
}

int ctl_msg_request_process(struct epoll_ptr_data *epd,char *out,int cmd)
{
	int ret = 0;
	if(epd){}
	switch(cmd){
		case SSL_REQUEST:
			sprintf(out,"PUSH_REQUEST");
			//sprintf(out,"PUSH_DRIZZLE_REQUEST");
			return strlen(out)+1;
			break;
		default:
			break;

	}
	return ret;
}





void clone_push_list (struct options *o)
{
	if(o){}
#if 0
	if (o->push_list.head)
	{
		struct push_entry *e = o->push_list.head;
		push_reset (o);
		while (e)
		{
			push_option_ex (o, string_alloc (e->option), true, M_FATAL);
			e = e->next;
		}
	}
#endif
}


void push_option_ex (struct options *o, const char *opt, bool enable)
{

	if(enable){}
	if (!string_class (opt, CC_ANY, CC_COMMA))
	{
		MM("PUSH OPTION FAILED (illegal comma (',') in string): '%s'\n", opt);
	}
	else
	{
		printf("-------------------------------------------------------------------------- %s %d -----------------------\n",__func__,__LINE__);
		struct push_entry *e;
		e = malloc(sizeof(struct push_entry));
		memset(e,0x00,sizeof(struct push_entry));
		e->enable = true;
		//e->option = opt;
		sprintf(e->option,"%s",opt);
		if (o->push_list.head)
		{
			if(!(o->push_list.tail)){
				MM("## ERR: %s %d ##\n",__func__,__LINE__);
			}
			o->push_list.tail->next = e;
			o->push_list.tail = e;
		}
		else
		{
			if(!(!o->push_list.tail)){
				MM("## ERR: %s %d ##\n",__func__,__LINE__);
			}
			o->push_list.head = e;
			o->push_list.tail = e;
		}
	}
}

void push_option (struct options *o, const char *opt)
{
	push_option_ex (o, opt, true);
}

void push_options (struct options *o, char **p)
{
	char **argv = make_extended_arg_array (p);
	char *opt = print_argv (argv, 0);
	push_option (o, opt);
}


void push_reset (struct options *o)
{
	if(o){}
	//memset(&o->push_list,0x00,sizeof(o->push_list));
}
