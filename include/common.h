

//#define sfree(a) if(a != NULL){free(a); a=NULL;}
//#define sfree(a) if(a != NULL){free(a); }

					//printf("## sfree() %s %d %d ##\n",__func__,__LINE__,b); 

#define sfree(a,b) { \
					if(b == 0){ memset(a,0x00,b); } \
					free(a); \
				}


//if(a != NULL){free(a); }
//#define MAX_PKT_SIZE 16384
#define MAX_PKT_SIZE 2048
struct socket_fd{
        int net_fd;
        int tun_fd;
        int server_fd;
        int epoll_fd;
}socket_fd_t;


#define MAX_HMAC_KEY_LENGTH      64
#define MAX_CIPHER_KEY_LENGTH    64

//#define PKT_TIMEOUT 20
#define PKT_TIMEOUT 500
#define LOOP_TIMEOUT 1000

#if 0
struct options{
	int mode;
	int port;
	char remote_ip[1024];
	char if_name[IFNAMSIZ];
	int tuntap_flags;

	char *dh_file;
	char *dh_file_inline;
	char *cert_file;
	char *cert_file_inline;
	char *priv_key_file;
	char *priv_key_file_inline;
	char *ca_file;
	char *ca_file_inline;
	char *ca_path;
	unsigned int ssl_flags;
	bool verify_user_pass_enable;
	char str[4096];
	bool keepalive;
	unsigned int ende_flags;

	char ciphername[512];
	char authname[512];
	int keysize;
	char key_method;

	int renego_sec_time;
}options_t;
#endif


