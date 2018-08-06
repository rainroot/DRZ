
#define IFCONFIG_POOL_30NET   0
#define IFCONFIG_POOL_INDIV   1

#define IFCONFIG_POOL_MAX         65536
#define IFCONFIG_POOL_MIN_NETBITS    16

#if 0
typedef int ifconfig_pool_handle;

struct ifconfig_pool_entry
{
	bool in_use;
	char *common_name;
	time_t last_release;
	bool fixed;
};

struct ifconfig_pool
{
	in_addr_t base;
	int size;
	int type;
	bool duplicate_cn;
	bool ipv6;
	struct in6_addr base_ipv6;
	unsigned int size_ipv6;
	struct ifconfig_pool_entry *list;
};
#endif

bool ifconfig_pool_verify_range (const in_addr_t start, const in_addr_t end);
void ifconfig_pool_read(struct options *opt);
