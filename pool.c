#include <rain_common.h>
bool ifconfig_pool_verify_range (const in_addr_t start, const in_addr_t end)
{
	bool ret = true;

	//char str0[64]={0,};
	//char str1[64]={0,};

	char *str0 = malloc(64);
	memset(str0,0x00,64);
	char *str1 = malloc(64);
	memset(str1,0x00,64);


	if (start > end)
	{
		print_in_addr_t (start, 0,str0);
		print_in_addr_t(end, 0,str1);
		MM("--ifconfig-pool start IP [%s] is greater than end IP [%s]\n",str0,str1);
		ret = false;
	}

	if (end - start >= IFCONFIG_POOL_MAX)
	{
		print_in_addr_t (start, 0,str0);
		print_in_addr_t(end, 0,str1);
		MM("--ifconfig-pool address range is too large [%s -> %s].  Current maximum is %d addresses, as defined by IFCONFIG_POOL_MAX variable.\n",str0,str1,IFCONFIG_POOL_MAX);
		ret = false;
	}
	free(str0);
	free(str1);
	return ret;
}

void ifconfig_pool_read(struct options *opt)
{
	FILE *fp;
	int line_num;
	char *p[MAX_PARMS];
	char line[OPTION_LINE_SIZE];

	char *ip_buf;
	char *cn_buf;
	int buf_size = 128;

	fp = fopen (opt->ifconfig_pool_persist_filename, "r");
	if (fp)
	{
		//char *line= malloc(OPTION_LINE_SIZE);
		//memset(line,0x00,OPTION_LINE_SIZE);

		ip_buf = malloc(buf_size);
		memset(ip_buf,0x00,buf_size);

		cn_buf = malloc(buf_size);
		memset(cn_buf,0x00,buf_size);

		line_num = 0;
		while (fgets(line, sizeof (line), fp))
		{
			int offset = 0;
			memset(&p,0x00,sizeof(p));
			++line_num;
			if (line_num == 1 && strncmp (line, "\xEF\xBB\xBF", 3) == 0){
				offset = 3;
			}
			if(char_parse(line+offset,',',cn_buf,strlen(line))){
				offset += strlen(cn_buf)+1;
				 if(char_parse(line+offset,',',ip_buf,strlen(line)-offset)){

					struct user_tree_data utd;
					struct user_tree_data *ret_utd;
					struct user_tree_data *putd;
					bool err;
					unsigned long crc = 0;
					unsigned int ipaddr=0;

					crc = crc32(0L,(const Bytef *)cn_buf, strlen(cn_buf));

					memcpy((char *)&utd.key,&crc,4);

					pthread_mutex_lock(&opt->user_ip_tree_mutex);
					ret_utd = (struct user_tree_data *)rb_find(opt->user_ip_tree,(void *)&utd);
					pthread_mutex_unlock(&opt->user_ip_tree_mutex);
					if(ret_utd != NULL){
						MM(" ERR: %s %d ### %s ## [%s] same user name ERR ##\n",__func__,__LINE__,opt->ifconfig_pool_persist_filename,cn_buf);
						//exit(0);
					}else{
						putd = malloc(sizeof(struct user_tree_data));
						memset(putd,0x00,sizeof(struct user_tree_data));
						memcpy((char *)&putd->key,&crc,4);
						memcpy(putd->cn_buf,cn_buf,strlen(cn_buf));
						ipaddr = get_ip_addr(ip_buf,&err);
						
						if(opt->server_bridge_defined){
							putd->netmask = opt->server_bridge_netmask;
						}else{
							ipaddr++;
							putd->netmask = ipaddr;
						}

						ipaddr++;
						putd->ipaddr = ipaddr;

						pthread_mutex_lock(&opt->user_ip_tree_mutex);
						rb_insert(opt->user_ip_tree,putd);
						pthread_mutex_unlock(&opt->user_ip_tree_mutex);

						if(opt->ifconfig_pool_start <= putd->ipaddr){
							ipaddr++;
							opt->ifconfig_pool_start = putd->ipaddr;
						}
					}
				}
			}

		}
		free(ip_buf);
		free(cn_buf);
		//free(line);
		fclose (fp);
	}
	else
	{
		MM("## ERR:  %s %d  %s ##\n",__func__,__LINE__,opt->ifconfig_pool_persist_filename);
	}
}


#if 0

void ifconfig_pool_entry_free (struct ifconfig_pool_entry *ipe, bool hard)
{
	ipe->in_use = false;
	if (hard && ipe->common_name)
	{
		free (ipe->common_name);
		ipe->common_name = NULL;
	}
#if 0
	if (hard){
		ipe->last_release = 0;
	}else{
		ipe->last_release = now;
	}
#endif
}

int ifconfig_pool_find (struct ifconfig_pool *pool, char *common_name)
{
	int i;
	time_t earliest_release = 0;
	int previous_usage = -1;
	int new_usage = -1;

	for (i = 0; i < pool->size; ++i)
	{
		struct ifconfig_pool_entry *ipe = &pool->list[i];
		if (!ipe->in_use)
		{
			if (pool->duplicate_cn)
			{
				new_usage = i;
				break;
			}

			if ((new_usage == -1 || ipe->last_release < earliest_release) && !ipe->fixed)
			{
				earliest_release = ipe->last_release;
				new_usage = i;
			}

			if (previous_usage < 0 && common_name && ipe->common_name && !strcmp (common_name, ipe->common_name)){
				previous_usage = i;
			}

		}
	}

	if (previous_usage >= 0){
		return previous_usage;
	}

	if (new_usage >= 0){
		return new_usage;
	}
	return -1;
}



struct ifconfig_pool * ifconfig_pool_init (int type, in_addr_t start, in_addr_t end,bool duplicate_cn,bool ipv6_pool,struct in6_addr ipv6_base,int ipv6_netbits )
{
	struct ifconfig_pool *pool = NULL;

	if(!(start <= end && end - start < IFCONFIG_POOL_MAX)){
		MM("## ERR: %s %d ##\n",__func__,__LINE__);
	}

	pool = malloc(sizeof(struct ifconfig_pool));
	memset(pool,0x00,sizeof(struct ifconfig_pool));


	pool->type = type;
	pool->duplicate_cn = duplicate_cn;

	switch (type)
	{
		case IFCONFIG_POOL_30NET:
			pool->base = start & ~3;
			pool->size = (((end | 3) + 1) - pool->base) >> 2;
			break;
		case IFCONFIG_POOL_INDIV:
			pool->base = start;
			pool->size = end - start + 1;
			break;
		default:
			break;
	}

	pool->ipv6 = ipv6_pool;
	if (pool->ipv6)
	{
		pool->base_ipv6 = ipv6_base;
		pool->size_ipv6 = ipv6_netbits>96? ( 1<<(128-ipv6_netbits) ) : IFCONFIG_POOL_MAX;

		MM("IFCONFIG POOL IPv6: (IPv4) size=%d, size_ipv6=%d, netbits=%d, base_ipv6=%s",pool->size,pool->size_ipv6,ipv6_netbits,print_in6_addr( pool->base_ipv6,0));
		#if 0
		if(!(pool->size < pool->size_ipv6)){
			MM("## ERR: %s %d ##\n",__func__,__LINE__);
		}
		#endif
	}

	//ALLOC_ARRAY_CLEAR (pool->list, struct ifconfig_pool_entry, pool->size);

	pool->list =malloc(sizeof(struct ifconfig_pool_entry) * pool->size);
	memset(pool->list,0x00,sizeof(struct ifconfig_pool_entry) * pool->size);

	MM("IFCONFIG POOL: base=%s size=%d, ipv6=%d", print_in_addr_t(pool->base, 0), pool->size, pool->ipv6 );

	return pool;
}

void ifconfig_pool_free (struct ifconfig_pool *pool)
{
	if (pool)
	{
		int i;
		for (i = 0; i < pool->size; ++i){
			ifconfig_pool_entry_free (&pool->list[i], true);
		}
		free (pool->list);
		free (pool);
	}
}

ifconfig_pool_handle ifconfig_pool_acquire (struct ifconfig_pool *pool, in_addr_t *local, in_addr_t *remote, struct in6_addr *remote_ipv6, char *common_name)
{
	int i;

	i = ifconfig_pool_find (pool, common_name);
	if (i >= 0)
	{
		struct ifconfig_pool_entry *ipe = &pool->list[i];
		if(!(!ipe->in_use)){
			MM("## ERR:  %s %d ##\n",__func__,__LINE__);
		}
		ifconfig_pool_entry_free (ipe, true);
		ipe->in_use = true;
		if (common_name){
			ipe->common_name = malloc(strlen(common_name));
			memset(ipe->common_name,0x00,strlen(common_name));
			snprintf(ipe->common_name,strlen(common_name),"%s",common_name);
		}

		switch (pool->type)
		{
			case IFCONFIG_POOL_30NET:
				{
					in_addr_t b = pool->base + (i << 2);
					*local = b + 1;
					*remote = b + 2;
					break;
				}
			case IFCONFIG_POOL_INDIV:
				{
					in_addr_t b = pool->base + i;
					*local = 0;
					*remote = b;
					break;
				}
			default:
				break;
		}

		if ( pool->ipv6 && remote_ipv6 )
		{
			*remote_ipv6 = add_in6_addr( pool->base_ipv6, i );
		}
	}
	return i;
}

bool ifconfig_pool_release (struct ifconfig_pool* pool, ifconfig_pool_handle hand, const bool hard)
{
	bool ret = false;
	if (pool && hand >= 0 && hand < pool->size)
	{
		ifconfig_pool_entry_free (&pool->list[hand], hard);
		ret = true;
	}
	return ret;
}

ifconfig_pool_handle ifconfig_pool_ip_base_to_handle (const struct ifconfig_pool* pool, const in_addr_t addr)
{
	ifconfig_pool_handle ret = -1;

	switch (pool->type)
	{
		case IFCONFIG_POOL_30NET:
			{
				ret = (addr - pool->base) >> 2;
				break;
			}
		case IFCONFIG_POOL_INDIV:
			{
				ret = (addr - pool->base);
				break;
			}
		default:
			break;
	}

	if (ret < 0 || ret >= pool->size){
		ret = -1;
	}
	return ret;
}


in_addr_t ifconfig_pool_handle_to_ip_base (const struct ifconfig_pool* pool, ifconfig_pool_handle hand)
{
	in_addr_t ret = 0;
	if (hand >= 0 && hand < pool->size)
	{
		switch (pool->type)
		{
			case IFCONFIG_POOL_30NET:
				{
					ret = pool->base + (hand << 2);;
					break;
				}
			case IFCONFIG_POOL_INDIV:
				{
					ret = pool->base + hand;
					break;
				}
			default:
					break;
		}
	}

	return ret;
}

struct in6_addr ifconfig_pool_handle_to_ipv6_base (const struct ifconfig_pool* pool, ifconfig_pool_handle hand)
{
	struct in6_addr ret = in6addr_any;

	if(pool){}
	if(hand){}
#if 0

	if (hand >= 0 && hand < pool->size_ipv6 )
	{
		ret = add_in6_addr( pool->base_ipv6, hand );
	}
#endif
	return ret;
}

void ifconfig_pool_set (struct ifconfig_pool* pool, const char *cn, const in_addr_t addr, const bool fixed)
{
	ifconfig_pool_handle h = ifconfig_pool_ip_base_to_handle (pool, addr);
	if (h >= 0)
	{
		struct ifconfig_pool_entry *e = &pool->list[h];
		ifconfig_pool_entry_free (e, true);
		e->in_use = false;
		e->common_name = malloc(strlen(cn));
		memset(e->common_name,0x00,strlen(cn));
		snprintf(e->common_name,strlen(cn),"%s",cn);

		//e->last_release = now;
		e->fixed = fixed;
	}
}
#endif
