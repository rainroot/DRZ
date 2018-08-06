
#ifdef ENABLE_MANAGEMENT
# define MF_EXTERNAL_KEY    (1<<9)

#define M_DEBUG_LEVEL     (0x0F)
#define M_INFO				  0
#define M_FATAL           (1<<4)
#define M_NONFATAL        (1<<5)
#define M_WARN            (1<<6)
#define M_DEBUG           (1<<7)

#define M_ERRNO           (1<<8)

#define M_NOMUTE          (1<<11)
#define M_NOPREFIX        (1<<12)
#define M_USAGE_SMALL     (1<<13)
#define M_MSG_VIRT_OUT    (1<<14)
#define M_OPTERR          (1<<15)
#define M_NOLF            (1<<16)
#define M_NOIPREFIX       (1<<17)

#define M_ERR     (M_FATAL | M_ERRNO)
#define M_USAGE   (M_USAGE_SMALL | M_NOPREFIX | M_OPTERR)
#define M_CLIENT  (M_MSG_VIRT_OUT | M_NOMUTE | M_NOIPREFIX)


#define ERR_BUF_SIZE 8192

#define MANAGEMENT_VERSION                      1
#define MANAGEMENT_N_PASSWORD_RETRIES           3
#define MANAGEMENT_LOG_HISTORY_INITIAL_SIZE   100
#define MANAGEMENT_ECHO_BUFFER_SIZE           100
#define MANAGEMENT_STATE_BUFFER_SIZE          100

#ifdef MANAGEMENT_DEF_AUTH
struct man_def_auth_context {
	unsigned long cid;

#define DAF_CONNECTION_ESTABLISHED (1<<0)
#define DAF_CONNECTION_CLOSED      (1<<1)
#define DAF_INITIAL_AUTH           (1<<2)
	unsigned int flags;

	unsigned int mda_key_id_counter;

	time_t bytecount_last_update;
};
#endif

struct command_line
{
	char *buf;
	int buf_len;
	char *residual;
	int residual_len;
};

union log_entry_union {
  unsigned int msg_flags;
  int state;
  int intval;
};

struct log_entry
{
  time_t timestamp;
  const char *string;
  in_addr_t local_ip;
  in_addr_t remote_ip;
  union log_entry_union u;
};

#define LOG_PRINT_LOG_PREFIX   (1<<0)
#define LOG_PRINT_ECHO_PREFIX  (1<<1)
#define LOG_PRINT_STATE_PREFIX (1<<2)

#define LOG_PRINT_INT_DATE     (1<<3)
#define LOG_PRINT_MSG_FLAGS    (1<<4)
#define LOG_PRINT_STATE        (1<<5)
#define LOG_PRINT_LOCAL_IP     (1<<6)

#define LOG_PRINT_CRLF         (1<<7)
#define LOG_FATAL_NOTIFY       (1<<8)

#define LOG_PRINT_INTVAL       (1<<9)

#define LOG_PRINT_REMOTE_IP    (1<<10)

#define LOG_ECHO_TO_LOG        (1<<11)

struct log_history
{
  int base;
  int size;
  int capacity;
  struct log_entry *array;
};

struct management_callback
{
	void *arg;

# define MCF_SERVER (1<<0)
	unsigned int flags;

	//void (*status) (void *arg, const int version, struct status_output *so);
	void (*status) (void *arg, const int version);
	void (*show_net) (void *arg, const int msglevel);
	int (*kill_by_cn) (void *arg, const char *common_name);
	int (*kill_by_addr) (void *arg, const in_addr_t addr, const int port);
	//void (*delete_event) (void *arg, event_t event);
	void (*delete_event) (void *arg);
	int (*n_clients) (void *arg);
#ifdef MANAGEMENT_DEF_AUTH
	bool (*kill_by_cid) (void *arg, const unsigned long cid, const char *kill_msg);
	bool (*client_auth) (void *arg,
			const unsigned long cid,
			const unsigned int mda_key_id,
			const bool auth,
			const char *reason,
			const char *client_reason,
			struct buffer_list *cc_config);
	char *(*get_peer_info) (void *arg, const unsigned long cid);
#endif
#ifdef MANAGEMENT_PF
	bool (*client_pf) (void *arg,
			const unsigned long cid,
			struct buffer_list *pf_config);   /* ownership transferred */
#endif
	bool (*proxy_cmd) (void *arg, const char **p);
	bool (*remote_cmd) (void *arg, const char **p);
};
struct man_persist {
	bool defined;

	struct log_history *log;
	//struct virtual_output vout;

	bool standalone_disabled;
	struct management_callback callback;

	struct log_history *echo;
	struct log_history *state;

	bool hold_release;

	const char *special_state_msg;

	//counter_type bytes_in;
	//counter_type bytes_out;
	unsigned long long  bytes_in;
	unsigned long long  bytes_out;
};

struct man_settings {
	bool defined;
	unsigned int flags;
//	struct openvpn_sockaddr local;
	struct sockaddr local_sa;
   struct sockaddr_in local_in4;
   struct sockaddr_in6 local_in6;

#if UNIX_SOCK_SUPPORT
	struct sockaddr_un local_unix;
#endif
	bool management_over_tunnel;
	struct user_pass up;
	int log_history_cache;
	int echo_buffer_size;
	int state_buffer_size;
	char *write_peer_info_file;
	int client_uid;
	int client_gid;

# define MANSIG_IGNORE_USR1_HUP  (1<<0)
# define MANSIG_MAP_USR1_TO_HUP  (1<<1)
# define MANSIG_MAP_USR1_TO_TERM (1<<2)
	unsigned int mansig;
};

#define UP_QUERY_DISABLED  0
#define UP_QUERY_USER_PASS 1
#define UP_QUERY_PASS      2
#define UP_QUERY_NEED_OK   3
#define UP_QUERY_NEED_STR  4

#define MS_INITIAL          0
#define MS_LISTEN           1
#define MS_CC_WAIT_READ     2
#define MS_CC_WAIT_WRITE    3

struct man_connection {
	int state;

	//socket_descriptor_t sd_top;
	//socket_descriptor_t sd_cli;
	int sd_top;
	int sd_cli;
	//struct openvpn_sockaddr remote;
	struct sockaddr remote_sa;
	struct sockaddr_in remote_in4;
	struct sockaddr_in6 remote_in6;

	bool halt;
	bool password_verified;
	int password_tries;

	struct command_line *in;
	//struct buffer_list *out;
	char *out;
	int out_len;

#ifdef MANAGEMENT_IN_EXTRA
# define IEC_UNDEF       0
# define IEC_CLIENT_AUTH 1
# define IEC_CLIENT_PF   2
# define IEC_RSA_SIGN    3
	int in_extra_cmd;
	//struct buffer_list *in_extra;
	char *in_extra;
	int in_extra_len;
#ifdef MANAGEMENT_DEF_AUTH
	unsigned long in_extra_cid;
	unsigned int in_extra_kid;
#endif
#ifdef MANAGMENT_EXTERNAL_KEY
# define EKS_UNDEF   0
# define EKS_SOLICIT 1
# define EKS_INPUT   2
# define EKS_READY   3
	int ext_key_state;
	//struct buffer_list *ext_key_input;
	char *ext_key_input;
	int ext_key_input_len;
#endif
#endif
	struct event_set *es;
	int env_filter_level;

	bool state_realtime;
	bool log_realtime;
	bool echo_realtime;
	int bytecount_update_seconds;
	time_t bytecount_last_update;

	const char *up_query_type;
	int up_query_mode;
	struct user_pass up_query;

#ifdef MANAGMENT_EXTERNAL_KEY
	//struct buffer_list *rsa_sig;
	char *rsa_sig;
	int rsa_sig_len;
#endif
};

struct management
{
  struct man_persist persist;
  struct man_settings settings;
  struct man_connection connection;
};

//extern struct management *management;
//struct user_pass;

#define MWCC_PASSWORD_WAIT (1<<0)
#define MWCC_HOLD_WAIT     (1<<1)
#define MWCC_OTHER_WAIT    (1<<2)
# define MF_SERVER            (1<<0)
# define MF_QUERY_PASSWORDS   (1<<1)
# define MF_HOLD              (1<<2)
# define MF_SIGNAL            (1<<3)
# define MF_FORGET_DISCONNECT (1<<4)
# define MF_CONNECT_AS_CLIENT (1<<5)
#ifdef MANAGEMENT_DEF_AUTH
# define MF_CLIENT_AUTH       (1<<6)
#endif
#ifdef MANAGEMENT_PF
# define MF_CLIENT_PF         (1<<7)
#endif
# define MF_UNIX_SOCK       (1<<8)
#ifdef MANAGMENT_EXTERNAL_KEY
# define MF_EXTERNAL_KEY    (1<<9)
#endif
#define MF_UP_DOWN          (1<<10)
#define MF_QUERY_REMOTE     (1<<11)
#define MF_QUERY_PROXY      (1<<12)

#define OPENVPN_STATE_INITIAL       0
#define OPENVPN_STATE_CONNECTING    1
#define OPENVPN_STATE_ASSIGN_IP     2
#define OPENVPN_STATE_ADD_ROUTES    3
#define OPENVPN_STATE_CONNECTED     4
#define OPENVPN_STATE_RECONNECTING  5
#define OPENVPN_STATE_EXITING       6

#define OPENVPN_STATE_WAIT          7
#define OPENVPN_STATE_AUTH          8
#define OPENVPN_STATE_GET_CONFIG    9
#define OPENVPN_STATE_RESOLVE       10
#define OPENVPN_STATE_TCP_CONNECT   11

#define OPENVPN_STATE_CLIENT_BASE   7


bool management_open (struct management *man,const char *addr,const int port,const char *pass_file,const char *client_user,const char *client_group,const int log_history_cache,const int echo_buffer_size,const int state_buffer_size,const char *write_peer_info_file,const int remap_sigusr1,const unsigned int flags);
struct management * management_init (void);
int mngt_server_process(struct pth_timer_data *p_t_d);
const struct log_entry * log_history_ref (const struct log_history *h, const int index);
void log_history_resize (struct log_history *h, const int capacity);
struct log_histrory * log_history_init (const int capacity);
void log_history_close (struct log_history *h);
void log_history_add (struct log_history *h, const struct log_entry *le);
const char * man_state_name (const int state);
const char * log_entry_print (const struct log_entry *e, unsigned int flags);
void command_line_next (struct command_line *cl);
const unsigned char * command_line_get (struct command_line *cl);
void command_line_free (struct command_line *cl);
struct command_line * command_line_new (const int buf_len);
void command_line_reset (struct command_line *cl);
void command_line_add (struct command_line *cl, const unsigned char *buf, const int len);
#endif

