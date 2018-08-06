#define MAX_ROUTES_DEFAULT 100

#define IPV4_NETMASK_HOST 0xffffffffU

#define EMPTY_ARRAY_SIZE 1


#define TLA_NOT_IMPLEMENTED 0
#define TLA_NONLOCAL        1
#define TLA_LOCAL           2



struct route_option {
	char network[64];
	char netmask[64];
	char gateway[64];
	char metric[64];
};

#define RG_ENABLE         (1<<0)
#define RG_LOCAL          (1<<1)
#define RG_DEF1           (1<<2)
#define RG_BYPASS_DHCP    (1<<3)
#define RG_BYPASS_DNS     (1<<4)
#define RG_REROUTE_GW     (1<<5)
#define RG_AUTO_LOCAL     (1<<6)
#define RG_BLOCK_LOCAL    (1<<7)


#define ROUTE_DELETE_FIRST  (1<<2)
#define ROUTE_REF_GW        (1<<3)

struct route_option_list {
	unsigned int flags;  /* RG_x flags */
	int capacity;
	int n;
	struct route_option routes[EMPTY_ARRAY_SIZE];
};



struct route_bypass
{
# define N_ROUTE_BYPASS 8
	int n_bypass;
	in_addr_t bypass[N_ROUTE_BYPASS];
};


struct route_special_addr
{
	/* bits indicating which members below are defined */
# define RTSA_REMOTE_ENDPOINT  (1<<0)
# define RTSA_REMOTE_HOST      (1<<1)
# define RTSA_DEFAULT_METRIC   (1<<2)
	unsigned int flags;

	in_addr_t remote_endpoint;
	in_addr_t remote_host;
	int remote_host_local;  /* TLA_x value */
	struct route_bypass bypass;
	int default_metric;
};

struct route_gateway_address {
	in_addr_t addr;
	in_addr_t netmask;
};

struct route_gateway_info {
# define RGI_ADDR_DEFINED     (1<<0)
# define RGI_NETMASK_DEFINED  (1<<1)
# define RGI_HWADDR_DEFINED   (1<<2)
# define RGI_IFACE_DEFINED    (1<<3)
# define RGI_OVERFLOW         (1<<4)
# define RGI_ON_LINK          (1<<5)
	unsigned int flags;

	char iface[16];
	uint8_t hwaddr[6];
	struct route_gateway_address gateway;

# define RGI_N_ADDRESSES 8
	int n_addrs;
	struct route_gateway_address addrs[RGI_N_ADDRESSES];
};



struct route_ipv4 {
# define RT_DEFINED        (1<<0)
# define RT_ADDED          (1<<1)
# define RT_METRIC_DEFINED (1<<2)
	unsigned int flags;
	struct route_option *option;
	in_addr_t network;
	in_addr_t netmask;
	in_addr_t gateway;
	int metric;
};

struct route_list {
#define RL_DID_REDIRECT_DEFAULT_GATEWAY (1<<0)
#define RL_DID_LOCAL                    (1<<1)
#define RL_ROUTES_ADDED                 (1<<2)
	unsigned int iflags;

	struct route_special_addr spec;
	struct route_gateway_info rgi;
	unsigned int flags;     /* RG_x flags */
	int capacity;
	int n;
	struct route_ipv4 routes[EMPTY_ARRAY_SIZE];
};

struct route_ipv6_option {
	char *prefix;           /* e.g. "2001:db8:1::/64" */
	char *gateway;          /* e.g. "2001:db8:0::2" */
	char *metric;           /* e.g. "5" */
};

struct route_ipv6_option_list {
	unsigned int flags;
	int capacity;
	int n;
	struct route_ipv6_option routes_ipv6[EMPTY_ARRAY_SIZE];
};


struct route_ipv6 {
	bool defined;
	struct in6_addr network;
	unsigned int netbits;
	struct in6_addr gateway;
	bool metric_defined;
	int metric;
};

struct route_ipv6_list {
	bool routes_added;
	unsigned int flags;
	int default_metric;
	bool default_metric_defined;
	struct in6_addr remote_endpoint_ipv6;
	bool remote_endpoint_defined;
	bool did_redirect_default_gateway;
	bool did_local;
	int capacity;
	int n;
	struct route_ipv6 routes_ipv6[EMPTY_ARRAY_SIZE];
};


struct iroute {
	in_addr_t network;
	int netbits;
	//struct iroute *next;
}iroute_t;

struct iroute_ipv6 {
	struct in6_addr network;
	unsigned int netbits;
	//struct iroute_ipv6 *next;
}iroute_ipv6;


bool is_special_addr (char *addr_str);
in_addr_t netbits_to_netmask (int netbits);
bool netmask_to_netbits (in_addr_t network,in_addr_t netmask, int *netbits);
void add_route_to_option_list (struct route_option_list *l,char *network, char *netmask,char *gateway,char *metric);
struct route_option_list * clone_route_option_list (struct route_option_list *src);
struct route_ipv6_option_list * clone_route_ipv6_option_list (struct route_ipv6_option_list *src);
void add_route_ipv6_to_option_list (struct route_ipv6_option_list *l, char *prefix,char *gateway,char *metric);
struct route_option_list * new_route_option_list (int max_routes);
void get_default_gateway (struct route_gateway_info *rgi);
void print_default_gateway(struct route_gateway_info *rgi);
int test_local_addr (in_addr_t addr,struct route_gateway_info *rgi);
void get_bypass_addresses (struct route_bypass *rb, unsigned int flags);
void add_route (struct route_ipv4 *r, struct options *opt,unsigned int flags,struct route_gateway_info *rgi);
void delete_route (struct route_ipv4 *r, struct options *opt,unsigned int flags, struct route_gateway_info *rgi);
void delete_route_ipv6 (struct route_ipv6 *r6,struct options *opt, unsigned int flags);
void add_route_ipv6 (struct route_ipv6 *r6,struct options *opt , unsigned int flags);
void print_route_options (struct route_option_list *rol);
struct route_list * new_route_list (int max_routes);
struct route_ipv6_list * new_route_ipv6_list (int max_routes);
bool init_route_list (struct route_list *rl, struct route_option_list *opt,const char *remote_endpoint,int default_metric,in_addr_t remote_host);
void do_init_route_list (struct epoll_ptr_data *epd,struct options *options);
void add_routes (struct route_list *rl, struct route_ipv6_list *rl6,struct options *opt, unsigned int flags);
