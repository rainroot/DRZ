
#define SOCKET_UNDEFINED (-1)

#define LINK_MTU_DEFAULT   1500
#define MSSFIX_DEFAULT     1450

#define RESOLV_RETRY_INFINITE 1000000000

#define IA_EMPTY_IF_UNDEF (1<<0)
#define IA_NET_ORDER      (1<<1)

#define GETADDR_RESOLVE               (1<<0)
#define GETADDR_FATAL                 (1<<1)
#define GETADDR_HOST_ORDER            (1<<2)
#define GETADDR_MENTION_RESOLVE_RETRY (1<<3)
#define GETADDR_FATAL_ON_SIGNAL       (1<<4)
#define GETADDR_WARN_ON_SIGNAL        (1<<5)
#define GETADDR_MSG_VIRT_OUT          (1<<6)
#define GETADDR_TRY_ONCE              (1<<7)
#define GETADDR_UPDATE_MANAGEMENT_STATE (1<<8)
#define GETADDR_RANDOMIZE             (1<<9)

#define OIA_HOSTNAME   0
#define OIA_IP         1
#define OIA_ERROR     -1


# define SF_USE_IP_PKTINFO (1<<0)
# define SF_TCP_NODELAY (1<<1)
# define SF_PORT_SHARE (1<<2)
# define SF_HOST_RANDOMIZE (1<<3)
# define SF_GETADDRINFO_DGRAM (1<<4)

#define IPV4_INVALID_ADDR 0xffffffff

#if 0
struct openvpn_sockaddr
{
	union {
		struct sockaddr sa;
		struct sockaddr_in in4;
		struct sockaddr_in6 in6;
	} addr;
};

struct link_socket_actual
{
	struct openvpn_sockaddr dest;
#if 0
	union {
		struct in_pktinfo in4;
		struct in_addr in4;
		struct in6_pktinfo in6;
	} pi;
#endif
};

struct link_socket_addr
{
	struct openvpn_sockaddr local;
	struct openvpn_sockaddr remote;   /* initial remote */
	struct link_socket_actual actual; /* reply to this address */
};

struct link_socket_info
{
	struct link_socket_addr *lsa;
	bool connection_established;
	const char *ipchange_command;
	const struct plugin_list *plugins;
	bool remote_float;
	int proto;                    /* Protocol (PROTO_x defined below) */
	int mtu_changed;              /* Set to true when mtu value is changed */
};
#endif


bool ip_addr_dotted_quad_safe (const char *dotted_quad);
bool legal_ipv4_port (int port);
bool ipv6_addr_safe (const char *ipv6_text_addr);
in_addr_t getaddr (unsigned int flags, const char *hostname,int resolve_retry_seconds,bool *succeeded,int *signal_received);
char *print_in_addr_t (in_addr_t addr, unsigned int flags,char *str);
char * print_in6_addr (struct in6_addr a6, unsigned int flags);
struct in6_addr add_in6_addr( struct in6_addr base, uint32_t add );
int tcp_server(char *local_ip, int port);
int tcp_connect(char *addr, int port,struct main_data *md);
//int tcp_connect(char *addr, int port);
bool proto_is_net(int proto);
bool proto_is_udp(int proto);
bool proto_is_dgram(int proto);
bool proto_is_tcp(int proto);
bool mac_addr_safe (const char *mac_addr);
bool ip_or_dns_addr_safe (char *addr,bool allow_fqdn);
int ascii2proto (const char* proto_name);
int proto_remote (int proto, bool remote);
char * proto2ascii (int proto, bool display_form);
int openvpn_getaddrinfo (unsigned int flags, const char *hostname,int resolve_retry_seconds,int *signal_received,int ai_family,struct addrinfo **res);
in_addr_t link_socket_current_remote (struct main_data *md);
