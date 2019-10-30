
struct key_type;

#if 0
struct ns_tree_data{
	unsigned long key;
	int packet_len;
	char *packet_data;
}ns_tree_data_t;


struct ts_tree_data{
	unsigned long key;
	int packet_len;
	char *packet_data;
}ts_tree_data_t;
#endif


struct user_tree_data{
	unsigned int key;
	
	char cn_buf[128];
	unsigned int ipaddr;
	unsigned int netmask;
}user_tree_data_t;

struct user_data{
	unsigned int key;
	unsigned int netmask;
	int rfd;
	int wfd;
	int thd_mode;
	struct epoll_ptr_data *epd;
	struct packet_idx_tree_data *pitd;
}user_data_t;


struct internal_header{
	uint16_t size;
	uint16_t reserve0;
	uint16_t fd;
	uint16_t ping_send;
	uint32_t packet_type;
	uint32_t packet_idx;
}internal_header_t;

#define NETWORK_TO_TUN		1
#define TUN_TO_NETWORK		2
#define NETWORK_TO_NETWORK	3

#define PACKET_SEND		1
#define PACKET_DROP		2
#define PACKET_F_SEND	3

#define SEND_WAIT			0
#define SEND_OK 			1
#define SEND_OK_DONE 	2

#define NETWORK_PACKET	0x77
#define TUN_PACKET 		0x88

#define MAX_WORK_CNT 128

struct network_info_sec{
	uint64_t bps;
	uint64_t cps;
	uint64_t pps;

	uint64_t s_64B;
	uint64_t s_128B;
	uint64_t s_256B;
	uint64_t s_1024B;
	uint64_t s_1500B;
	pthread_mutex_t nis_mutex;
}network_info_sec_t;


struct packet_idx_tree_data{
	uint32_t key; //packet index
	int src_fd;
	int dst_fd;
	uint32_t packet_type; // network to tun , network to network, tun to network
	uint16_t ping_send;
	uint32_t TPT_send_ok;
	uint32_t TPT_packet_status; // send, drop
	uint32_t NPT_send_ok;
	uint32_t NPT_packet_status; // send, drop
	uint8_t normal_packet_data[MAX_PKT_SIZE];
	uint32_t normal_packet_data_len;
	
	uint8_t encrypt_packet_data[MAX_PKT_SIZE];
	uint32_t encrypt_packet_data_len;
	pthread_mutex_t pitd_mutex;
	//struct timeval recv_time;
	long long recv_mil;
	unsigned int data_send_idx;
	unsigned int mempool_idx;
	struct epoll_ptr_data *net_epd;
}packet_idx_tree_data_t;


struct main_data{
	struct list_head *li;
	pthread_mutex_t li_mutex;

	struct list_head *ip_li;
	pthread_mutex_t ip_li_mutex;

	struct network_info_sec *T_nis;
	struct network_info_sec *N_nis;

	struct options *opt;
	int stop;
	struct tls_root_ctx *ctx;
	struct key_type key_type;
	char session_id[8];

	struct sockaddr_in server_addr;

	struct epoll_ptr_data *work_in_out_epd[MAX_WORK_CNT];
	pthread_mutex_t work_in_out_mutex;
	unsigned int in_out_idx;

	struct epoll_ptr_data *work_out_in_epd[MAX_WORK_CNT];
	pthread_mutex_t work_out_in_mutex;
	unsigned int out_in_idx;

	struct epoll_ptr_data *tun_epd; // use only Client mode
	struct epoll_ptr_data *net_epd; // use only Client mode

   struct epoll_ptr_data *tun_send_epd;
   struct epoll_ptr_data *net_send_epd;

	struct rb_table *TPT_idx_tree;
	pthread_mutex_t TPT_tree_mutex;
	unsigned long TPT_idx; // TUN PIPE THREAD
	pthread_mutex_t TPT_idx_mutex;
	unsigned long T_TPT_idx;
	pthread_mutex_t T_TPT_idx_mutex;

	struct rb_table *NPT_idx_tree;
	pthread_mutex_t NPT_tree_mutex;
	unsigned long NPT_idx; // NETWORK PIPE THREAD
	pthread_mutex_t NPT_idx_mutex;
	unsigned long T_NPT_idx;
	pthread_mutex_t T_NPT_idx_mutex;

	long long T_NPT_last_mil;
	long long T_TPT_last_mil;

	struct mempool *pitd_mp;
	bool loop_epoll;
	bool recv_wait;
	pthread_mutex_t print_mutex;
}main_data_t;


int user_compare(void *ad, void *bd,void *rb_param);

void dump_print(int length, char *data);
size_t array_mult_safe (size_t m1, size_t m2, size_t extra);
bool compat_flag (unsigned int flag);
int max_int (int x, int y);
void run_up_down (struct options *opt, char *context);
bool gen_path (char *directory, char *filename,char *out);
void dump_print_hex(char* data, int size);
int ns_compare(void *ad, void *bd,void *rb_param);
int ts_compare(void *ad, void *bd,void *rb_param);
void MM(char *fmt, ...);
int min_int (int x, int y);
int limit_max_set(void);

