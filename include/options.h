
#define PACKAGE_STRING "Drizzle VPN"
#define TARGET_ALIAS "i686-linux"
#define IPROUTE_PATH "/usr/sbin/ip"

#define OPENVPN_PORT 2222

#define MAX_PARMS 16


#define AR_NONE       0
#define AR_INTERACT   1
#define AR_NOINTERACT 2

#define OPTION_PARM_SIZE 256
#define OPTION_LINE_SIZE 256


#define OPT_P_GENERAL         (1<<0)
#define OPT_P_UP              (1<<1)
#define OPT_P_ROUTE           (1<<2)
#define OPT_P_IPWIN32         (1<<3)
#define OPT_P_SCRIPT          (1<<4)
#define OPT_P_SETENV          (1<<5)
#define OPT_P_SHAPER          (1<<6)
#define OPT_P_TIMER           (1<<7)
#define OPT_P_PERSIST         (1<<8)
#define OPT_P_PERSIST_IP      (1<<9)
#define OPT_P_COMP            (1<<10) /* TODO */
#define OPT_P_MESSAGES        (1<<11)
#define OPT_P_CRYPTO          (1<<12) /* TODO */
#define OPT_P_TLS_PARMS       (1<<13) /* TODO */
#define OPT_P_MTU             (1<<14) /* TODO */
#define OPT_P_NICE            (1<<15)
#define OPT_P_PUSH            (1<<16)
#define OPT_P_INSTANCE        (1<<17)
#define OPT_P_CONFIG          (1<<18)
#define OPT_P_EXPLICIT_NOTIFY (1<<19)
#define OPT_P_ECHO            (1<<20)
#define OPT_P_INHERIT         (1<<21)
#define OPT_P_ROUTE_EXTRAS    (1<<22)
#define OPT_P_PULL_MODE       (1<<23)
#define OPT_P_PLUGIN          (1<<24)
#define OPT_P_SOCKBUF         (1<<25)
#define OPT_P_SOCKFLAGS       (1<<26)
#define OPT_P_CONNECTION      (1<<27)

#define OPT_P_DEFAULT   (~(OPT_P_INSTANCE|OPT_P_PULL_MODE))

#define PACKAGE_VERSION "v0.0.1"

#define streq(x, y) (!strcmp((x), (y)))
#define SIZE(x) (sizeof(x)/sizeof(x[0]))
#define BOOL_CAST(x) ((x) ? (true) : (false))


#define CONNECTION_LIST_SIZE 64


#define PA_BRACKET (1<<0)

#define TLS_CLIENT (o->tls_client)
#define TLS_SERVER (o->tls_server)

#define PULL_DEFINED(opt) ((opt)->pull)
#define PUSH_DEFINED(opt) ((opt)->push_list)

#ifndef PULL_DEFINED
#define PULL_DEFINED(opt) (false)
#endif

#ifndef PUSH_DEFINED
#define PUSH_DEFINED(opt) (false)
#endif


#ifdef ENABLE_PLUGIN
#define PLUGIN_OPTION_LIST(opt) ((opt)->plugin_list)
#else
#define PLUGIN_OPTION_LIST(opt) (NULL)
#endif

#ifdef MANAGEMENT_DEF_AUTH
#define MAN_CLIENT_AUTH_ENABLED(opt) ((opt)->management_flags & MF_CLIENT_AUTH)
#else
#define MAN_CLIENT_AUTH_ENABLED(opt) (false)
#endif

struct tuntap_options {
  int txqueuelen;
};



struct options_pre_pull
{
	bool tuntap_options_defined;
	struct tuntap_options tuntap_options;

	bool routes_defined;
	struct route_option_list *routes;

	bool routes_ipv6_defined;
	struct route_ipv6_option_list *routes_ipv6;
#if 0
#ifdef ENABLE_CLIENT_NAT
	bool client_nat_defined;
	struct client_nat_option_list *client_nat;
#endif
#endif

	int foreign_option_index;
};



struct remote_entry
{
	char *remote;
	int remote_port;
	int proto;
};

struct remote_list
{
	int len;
	struct remote_entry *array[CONNECTION_LIST_SIZE];
};

struct connection_list
{
	int len;
	int current;
	int n_cycles;
	bool no_advance;
	struct connection_entry *array[CONNECTION_LIST_SIZE];
};

enum proto_num {
        PROTO_NONE,
        PROTO_UDPv4,
        PROTO_TCPv4_SERVER,
        PROTO_TCPv4_CLIENT,
        PROTO_TCPv4,
        PROTO_UDPv6,
        PROTO_TCPv6_SERVER,
        PROTO_TCPv6_CLIENT,
        PROTO_TCPv6,
        PROTO_N
};



struct connection_entry
{
	int proto;
	int local_port;
	bool local_port_defined;
	int remote_port;
	char *local;
	char *remote;
	bool remote_float;
	bool bind_defined;
	bool bind_local;
	int connect_retry_seconds;
	bool connect_retry_defined;
	int connect_retry_max;
	int connect_timeout;
	bool connect_timeout_defined;
#if 0
#ifdef ENABLE_HTTP_PROXY
	struct http_proxy_options *http_proxy_options;
#endif
#ifdef ENABLE_SOCKS
	const char *socks_proxy_server;
	int socks_proxy_port;
	const char *socks_proxy_authfile;
	bool socks_proxy_retry;
#endif
#endif

	int tun_mtu;           /* MTU of tun device */
	bool tun_mtu_defined;  /* true if user overriding parm with command line option */
	int tun_mtu_extra;
	bool tun_mtu_extra_defined;
	int link_mtu;          /* MTU of device over which tunnel packets pass via TCP/UDP */
	bool link_mtu_defined; /* true if user overriding parm with command line option */

	/* Advanced MTU negotiation and datagram fragmentation options */
	int mtu_discover_type; /* used if OS supports setting Path MTU discovery options on socket */

	int fragment;          /* internal fragmentation size */
	int mssfix;            /* Upper bound on TCP MSS */
	bool mssfix_default;   /* true if --mssfix was supplied without a parameter */
#if 1
//#ifdef ENABLE_OCC
	int explicit_exit_notification;  /* Explicitly tell peer when we are exiting via OCC_EXIT message */
//#endif
#endif

# define CE_DISABLED (1<<0)
# define CE_MAN_QUERY_PROXY (1<<1)
# define CE_MAN_QUERY_REMOTE_UNDEF  0
# define CE_MAN_QUERY_REMOTE_QUERY  1
# define CE_MAN_QUERY_REMOTE_ACCEPT 2
# define CE_MAN_QUERY_REMOTE_MOD    3
# define CE_MAN_QUERY_REMOTE_SKIP   4
# define CE_MAN_QUERY_REMOTE_MASK   (0x07)
# define CE_MAN_QUERY_REMOTE_SHIFT  (2)
	unsigned int flags;


	char if_name[IFNAMSIZ];
	int tuntap_flags;

};

/* Command line options */
struct options
{
	//struct main_data *md;
#if 0
	struct rb_table *tree;
	pthread_mutex_t tree_mutex;
#endif
	struct rb_table *client_tree;
	pthread_mutex_t client_tree_mutex;

	struct rb_table *user_ip_tree;
	pthread_mutex_t user_ip_tree_mutex;

	struct rb_table *user_tree;
	pthread_mutex_t user_tree_mutex;

	struct rb_table *ts_tree;
	pthread_mutex_t ts_tree_mutex;

	struct rb_table *ct_tree;
	pthread_mutex_t ct_tree_mutex;

	unsigned int core;
	unsigned int mempool_cnt;

	const char *config;

	int mode;
	/* enable forward compatibility for post-2.1 features */
	bool forward_compatible;
	/* list of options that should be ignored even if unkown */
	const char **  ignore_unknown_option;

	/* persist parms */
	bool persist_config;
	int persist_mode;

	const char *key_pass_file;
	bool show_ciphers;
	bool show_digests;
	bool show_engines;
	bool show_tls_ciphers;
	bool genkey;

	/* Networking parms */
	struct connection_entry ce;
	char *remote_ip_hint;
	struct connection_list *connection_list;
	struct remote_list *remote_list;
	bool force_connection_list;
#if 0
#if HTTP_PROXY_OVERRIDE
	struct http_proxy_options *http_proxy_override;
#endif

	struct remote_host_store *rh_store;
#endif

	bool remote_random;
	const char *ipchange;
	const char *dev;
	const char *dev_type;
	const char *dev_node;
	const char *lladdr;
	int topology; /* one of the TOP_x values from proto.h */

	char ifconfig_local[65];
	char ifconfig_remote_netmask[65];

	const char *ifconfig_ipv6_local;
	int         ifconfig_ipv6_netbits;
	const char *ifconfig_ipv6_remote;
	bool ifconfig_noexec;
	bool ifconfig_nowarn;
#if 0
#ifdef ENABLE_FEATURE_SHAPER
	int shaper;
#endif
#endif

	int proto_force;
#if 1
//#ifdef ENABLE_OCC
	bool mtu_test;
//#endif

//#ifdef ENABLE_MEMSTATS
//	char *memstats_fn;
//#endif
#endif

	bool mlock;

	int keepalive_ping;           /* a proxy for ping/ping-restart */
	int keepalive_timeout;

	int inactivity_timeout;       /* --inactive */
	int inactivity_minimum_bytes;

	int ping_send_timeout;        /* Send a TCP/UDP ping to remote every n seconds */
	int ping_rec_timeout;         /* Expect a TCP/UDP ping from remote at least once every n seconds */
	bool ping_timer_remote;       /* Run ping timer only if we have a remote address */
	bool tun_ipv6;                /* Build tun dev that supports IPv6 */

# define PING_UNDEF   0
# define PING_EXIT    1
# define PING_RESTART 2
	int ping_rec_timeout_action;  /* What action to take on ping_rec_timeout (exit or restart)? */

	bool persist_tun;             /* Don't close/reopen TUN/TAP dev on SIGUSR1 or PING_RESTART */
	bool persist_local_ip;        /* Don't re-resolve local address on SIGUSR1 or PING_RESTART */
	bool persist_remote_ip;       /* Don't re-resolve remote address on SIGUSR1 or PING_RESTART */
	bool persist_key;             /* Don't re-read key files on SIGUSR1 or PING_RESTART */

#if PASSTOS_CAPABILITY
	bool passtos;
#endif

	int resolve_retry_seconds;    /* If hostname resolve fails, retry for n seconds */

	struct tuntap_options tuntap_options;

	/* Misc parms */
	const char *username;
	const char *groupname;
	const char *chroot_dir;
	const char *cd_dir;
#if 0
#ifdef ENABLE_SELINUX
	char *selinux_context;
#endif
#endif
	const char *writepid;
	const char *up_script;
	const char *down_script;
	bool user_script_used;
	bool down_pre;
	bool up_delay;
	bool up_restart;
	bool daemon;

	int remap_sigusr1;

	/* inetd modes defined in socket.h */
	int inetd;

	bool log;
	bool suppress_timestamps;
	int nice;
	int verbosity;
	int mute;
#if 0
#ifdef ENABLE_DEBUG
	int gremlin;
#endif
#endif

	const char *status_file;
	int status_file_version;
	int status_file_update_freq;

	/* optimize TUN/TAP/UDP writes */
	bool fast_io;
#if 0
#ifdef ENABLE_LZO
	/* LZO_x flags from lzo.h */
	unsigned int lzo;
#endif
#endif

	/* buffer sizes */
	int rcvbuf;
	int sndbuf;

	/* mark value */
	int mark;

	/* socket flags */
	unsigned int sockflags;

	/* route management */
	const char *route_script;
	const char *route_predown_script;
	//const char *route_default_gateway;

	char route_default_gateway[64];
	int route_default_metric;
	bool route_noexec;
	int route_delay;
	int route_delay_window;
	bool route_delay_defined;
	int max_routes;
	struct route_option_list *routes;
	struct route_ipv6_option_list *routes_ipv6;                   /* IPv6 */
	bool route_nopull;
	bool route_gateway_via_dhcp;
	bool allow_pull_fqdn; /* as a client, allow server to push a FQDN for certain parameters */
#if 0
#ifdef ENABLE_CLIENT_NAT
	struct client_nat_option_list *client_nat;
#endif
#endif

#if 1
//#ifdef ENABLE_OCC
	/* Enable options consistency check between peers */
	bool occ;
//#endif
#endif

#ifdef ENABLE_MANAGEMENT
	struct management *man;
	const char *management_addr;
	int management_port;
	const char *management_user_pass;
	int management_log_history_cache;
	int management_echo_buffer_size;
	int management_state_buffer_size;
	const char *management_write_peer_info_file;

	const char *management_client_user;
	const char *management_client_group;

	/* Mask of MF_ values of manage.h */
	unsigned int management_flags;
#endif
#if 0
#ifdef ENABLE_PLUGIN
	struct plugin_option_list *plugin_list;
#endif
#endif

	/* the tmp dir is for now only used in the P2P server context */
	const char *tmp_dir;
	bool server_defined;
	in_addr_t server_network;
	in_addr_t server_netmask;
	bool server_ipv6_defined;                             /* IPv6 */
	struct in6_addr server_network_ipv6;                  /* IPv6 */
	unsigned int    server_netbits_ipv6;                  /* IPv6 */

	in_addr_t server_pool_start;
	in_addr_t server_pool_current;
	in_addr_t server_pool_end;

# define SF_NOPOOL (1<<0)
# define SF_TCP_NODELAY_HELPER (1<<1)
# define SF_NO_PUSH_ROUTE_GATEWAY (1<<2)
	unsigned int server_flags;

	bool server_bridge_proxy_dhcp;

	bool server_bridge_defined;
	in_addr_t server_bridge_ip;
	in_addr_t server_bridge_netmask;
	in_addr_t server_bridge_pool_start;
	in_addr_t server_bridge_pool_current;
	in_addr_t server_bridge_pool_end;

	struct push_list push_list;

	bool ifconfig_pool_defined;
	in_addr_t ifconfig_pool_start;
	in_addr_t ifconfig_pool_end;
	in_addr_t ifconfig_pool_netmask;
	const char *ifconfig_pool_persist_filename;
	int ifconfig_pool_persist_refresh_freq;

	bool   ifconfig_ipv6_pool_defined;                    /* IPv6 */
	struct in6_addr ifconfig_ipv6_pool_base;              /* IPv6 */
	int    ifconfig_ipv6_pool_netbits;                    /* IPv6 */

	int real_hash_size;
	int virtual_hash_size;
	const char *client_connect_script;
	const char *client_disconnect_script;
	const char *learn_address_script;
	const char *client_config_dir;
	bool ccd_exclusive;
	bool disable;
	int n_bcast_buf;
	int tcp_queue_limit;
	struct iroute *iroutes;
	struct iroute_ipv6 *iroutes_ipv6;                     /* IPv6 */
	bool push_ifconfig_defined;
	in_addr_t push_ifconfig_local;
	in_addr_t push_ifconfig_remote_netmask;
#if 0
#ifdef ENABLE_CLIENT_NAT
	in_addr_t push_ifconfig_local_alias;
#endif
#endif
	bool push_ifconfig_constraint_defined;
	in_addr_t push_ifconfig_constraint_network;
	in_addr_t push_ifconfig_constraint_netmask;
	bool            push_ifconfig_ipv6_defined;           /* IPv6 */
	struct in6_addr push_ifconfig_ipv6_local;             /* IPv6 */
	int             push_ifconfig_ipv6_netbits;           /* IPv6 */
	struct in6_addr push_ifconfig_ipv6_remote;            /* IPv6 */
	bool enable_c2c;
	bool duplicate_cn;
	int cf_max;
	int cf_per;
	int max_clients;
	int max_routes_per_client;
	int stale_routes_check_interval;
	int stale_routes_ageing_time;

	const char *auth_user_pass_verify_script;
	bool auth_user_pass_verify_script_via_file;
#if 0
#if PORT_SHARE
	char *port_share_host;
	int port_share_port;
	const char *port_share_journal_dir;
#endif
#endif

	bool client;
	bool pull; /* client pull of config options from server */
	int push_continuation;
	unsigned int push_option_types_found;
	const char *auth_user_pass_file;
	struct options_pre_pull *pre_pull;

	int server_poll_timeout;

	int scheduled_exit_interval;
#if 0
#ifdef ENABLE_CLIENT_CR
	struct static_challenge_info sc_info;
#endif
#endif

	/* Cipher parms */
	const char *shared_secret_file;
	const char *shared_secret_file_inline;
	int key_direction;
	bool ciphername_defined;
	const char *ciphername;
	bool authname_defined;
	const char *authname;
	int keysize;
	const char *prng_hash;
	int prng_nonce_secret_len;
	const char *engine;
	bool replay;
	bool mute_replay_warnings;
	int replay_window;
	int replay_time;
	const char *packet_id_file;
	bool use_iv;
	bool test_crypto;
	bool use_prediction_resistance;

	/* TLS (control channel) parms */
	bool tls_server;
	bool tls_client;
	const char *ca_file;
	const char *ca_path;
	const char *dh_file;
	const char *cert_file;
	const char *extra_certs_file;
	const char *priv_key_file;
	const char *pkcs12_file;
	const char *cipher_list;
	const char *tls_verify;
	int verify_x509_type;
	const char *verify_x509_name;
	const char *tls_export_cert;
	const char *crl_file;

	const char *ca_file_inline;
	const char *cert_file_inline;
	const char *extra_certs_file_inline;
	char *priv_key_file_inline;
	const char *dh_file_inline;
	const char *pkcs12_file_inline; /* contains the base64 encoding of pkcs12 file */

	int ns_cert_type; /* set to 0, NS_CERT_CHECK_SERVER, or NS_CERT_CHECK_CLIENT */
	unsigned remote_cert_ku[MAX_PARMS];
	const char *remote_cert_eku;
	uint8_t *verify_hash;
	unsigned int ssl_flags; /* set to SSLF_x flags from ssl.h */

	const char *pkcs11_providers[MAX_PARMS];
	unsigned pkcs11_private_mode[MAX_PARMS];
	bool pkcs11_protected_authentication[MAX_PARMS];
	bool pkcs11_cert_private[MAX_PARMS];
	int pkcs11_pin_cache_period;
	const char *pkcs11_id;
	bool pkcs11_id_management;

	const char *cryptoapi_cert;

	/* data channel key exchange method */
	int key_method;

	/* Per-packet timeout on control channel */
	int tls_timeout;

	/* Data channel key renegotiation parameters */
	int renegotiate_bytes;
	int renegotiate_packets;
	int renegotiate_seconds;

	/* Data channel key handshake must finalize
	 *      within n seconds of handshake initiation. */
	int handshake_window;

	/* Field used to be the username in X509 cert. */
	char *x509_username_field;

	/* Old key allowed to live n seconds after new key goes active */
	int transition_window;

	/* Special authentication MAC for TLS control channel */
	const char *tls_auth_file;            /* shared secret */
	const char *tls_auth_file_inline;
	/* Allow only one session */
	bool single_session;

	bool push_peer_info;

	bool tls_exit;

	const struct x509_track *x509_track;

	/* special state parms */
	int foreign_option_index;

	char str[4096];
	bool verify_user_pass_enable;
	unsigned int ende_flags;
	int txqueuelen;
	
	struct route_list *route_list;
	struct route_ipv6_list *route_ipv6_list;
}options_t;


bool string_defined_equal (const char *s1, const char *s2);
void init_options (struct options *o,bool debug);
void parse_argv (struct options *options, const int argc,char *argv[],const unsigned int permission_mask,unsigned int *option_types_found);
void options_postprocess (struct options *options);
void show_settings (const struct options *o);
char * print_topology (const int topology);
void rol_check_alloc (struct options *opt);
void pre_pull_save (struct options *o);
bool char_parse (char *buf, const int delim, char *line, const int size);
void chomp (char *str);
int string_array_len(char **array);
in_addr_t get_ip_addr(const char *ip_string, bool *error);
bool apply_push_options (struct options *options,char *buf, int len ,unsigned int permission_mask,unsigned int *option_types_found);
char * options_string (struct epoll_ptr_data *epd,bool remote,char *out);
bool get_ipv6_addr( const char * prefix_str, struct in6_addr *network, unsigned int * netbits, char ** printable_ipv6);
int parse_line (const char *line, char *p[],const int n,const char *file,const int line_num);
void add_option(struct options *options, char *p[],char *file,int line,const unsigned int permission_mask,unsigned int *option_types_found,struct epoll_ptr_data *epd);
void options_server_import (struct options *o, char *filename,unsigned int permission_mask,unsigned int *option_types_found,struct epoll_ptr_data *epd); 
void option_iroute (struct options *o, const char *network_str,const char *netmask_str,struct epoll_ptr_data *epd);
