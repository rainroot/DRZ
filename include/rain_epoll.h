#include <sys/epoll.h>

#define MAX_CLIENT 100000
#if 0
#define NET_TUN_MAX_EVENTS 256
#define PIPE_MAX_EVENTS 256
#define SERVER_MAX_EVENTS 64
#else
#define NET_TUN_MAX_EVENTS 64
#define PIPE_MAX_EVENTS 64
#define SERVER_MAX_EVENTS 64

#endif
#define THREAD_NET 1
#define THREAD_TUN 2
#define THREAD_PIPE_IN_OUT 3
#define THREAD_PIPE_OUT_IN 4
#define THREAD_MNGT 5
#define THREAD_SEND_NET 6
#define THREAD_SEND_TUN 7


#define THREAD_MODE_NET 	0
#define THREAD_MODE_TUN		1
#define THREAD_MODE_NET_PIPE 	2
#define THREAD_STATUS 3

#define RET_EPOLL_ERR 0xf000
#define RET_EPOLL_RECV_ERR  0xf100
#define RET_EPOLL_WRITE_ERR  0xf200
#define RET_EPOLL_NORMAL 0
#define RET_EPOLL_IN 1
#define RET_EPOLL_OUT 2

struct key_source2;

struct ip_info{
	char iface[32];
	unsigned int  ipaddr;
	unsigned int  netmask;
	unsigned int  gateway;
}ip_info_t;

struct ssl_key{
	char *prb;
	int prb_len;
	char *pwb;
	int pwb_len;
	int state;
	bool authenticated;
	struct key_source2 k2;
	struct key_state_ssl *ks_ssl;
	struct key_ctx_bi key;
}ssl_key_t;

struct ssl_state{
	bool renego_success;
	int renego_keyid;
	int keyid;
	int lame_keyid;
	bool renego_again;
	int renego_failcnt;

	struct cert_hash_set *cert_hash_set;
	char *x509_username_field;
	char *common_name;
	int common_name_length;

	char remote_session_id[8];
	struct ssl_key sk[8];
	bool verified;	
	int verify_maxlevel;
#if 0
	pthread_mutex_t ss_mutex;
	pthread_mutex_t ping_keyid_change_mutex;
	bool ping_keyid_change;
#endif
}ssl_state_t;

struct net_fd_data{
	bool live;
	int net_fd;
	int net_rfd;
	int net_wfd;
	pthread_mutex_t net_w_mutex;
	pthread_mutex_t net_r_mutex;
	pthread_mutex_t net_mutex;
	unsigned long net_idx;
}net_fd_data_t;

struct tun_fd_data{
	bool live;
	int tun_fd;
	int tun_rfd;
	int tun_wfd;
	pthread_mutex_t tun_w_mutex;
	pthread_mutex_t tun_r_mutex;
	pthread_mutex_t tun_mutex;
	unsigned long tun_idx;
}tun_fd_data_t;

struct pipe_fd_data{
	bool live;
	int pipe_fd[2];
	int pipe_rfd;
	int pipe_wfd;
	pthread_mutex_t pipe_w_mutex;
	pthread_mutex_t pipe_r_mutex;
	pthread_mutex_t pipe_mutex;
}pipe_fd_data_t;

struct ping_state{
	bool ping_check;
	bool ready;
	struct timeval ping_f_last_time;
	struct timeval ping_l_last_time;
	pthread_mutex_t ping_check_mutex;
}ping_state_t;

struct packet_id_idx{
	unsigned int ssl_recv_idx;
	unsigned int ssl_send_idx;
	pthread_mutex_t ssl_send_idx_mutex;
	unsigned int data_recv_idx;
	unsigned int data_send_idx;
	pthread_mutex_t data_send_idx_mutex;
}packet_id_idx_t;

struct push_state{
	bool push_request;
	bool push_reply;
	pthread_mutex_t ps_mutex;
}push_state_t;


struct net_idx_tree{
	unsigned long net_idx;
	pthread_mutex_t net_idx_mutex;
	struct rb_table *net_idx_tree;
	pthread_mutex_t net_idx_tree_mutex;
}net_idx_tree_t;

struct epoll_ptr_data{
	uint32_t ipaddress;
	pthread_mutex_t mutex;
	int idx;
	long all_packet_cnt;
	pthread_mutex_t all_packet_cnt_mutex;
	bool openvpn;
	bool keynego;
	pthread_mutex_t keynego_mutex;

	unsigned long send_idx;
	pthread_mutex_t send_idx_mutex;

	//struct net_idx_tree *nit;

	struct net_fd_data *n_fdd;
	struct tun_fd_data *t_fdd;
	struct pipe_fd_data *p_fdd;
	struct pipe_fd_data *np_fdd;
	struct pipe_fd_data *tp_fdd;
	struct ssl_state *ss;
	struct ping_state *pc;
	struct packet_id_idx *pii;
	struct push_state *ps;
	int fd;
	int thd_mode;

	int epoll_fd;
	int epoll_pipe_fd;

	int epoll_thd;
	int server_sock;
	char *gl_var;
	int stop;
	char name[1024];
	bool kill;
	int ((*in_handle_func)(struct epoll_ptr_data *));
	int ((*out_handle_func)(struct epoll_ptr_data *,char *,int));
	int ((*pipe_in_handle_func)(struct epoll_ptr_data *));
	int ((*pipe_out_handle_func)(struct epoll_ptr_data *,char *,int));
	int ((*err_handle_func)(struct epoll_ptr_data *));
}epoll_ptr_data_t;

int get_sec(struct timeval *ptime);
int epoll_init(int epoll_cnt);
int epoll_add(int epoll_fd,int fd,int flags);
int epoll_svr_prcss(int epoll_fd,int server_fd,int tun_fd,void *hand_func,char *gl_var);
int epoll_cli_prcss(int epoll_fd,int net_fd,int tun_fd,void *hand_func,char *gl_var);
int epoll_server_recv_thd(struct pth_timer_data *p_t_d);
int epoll_client_recv_thd(struct pth_timer_data *p_t_d);
unsigned long epoll_event_exec(struct epoll_ptr_data *epd,int net_tun_pipe_fd);
