
#define TUN_MTU_DEFAULT    1500

#define TAP_MTU_EXTRA_DEFAULT  32

#define DEV_TYPE_UNDEF 0
#define DEV_TYPE_NULL  1
#define DEV_TYPE_TUN   2
#define DEV_TYPE_TAP   3

#define TOP_UNDEF   0
#define TOP_NET30   1
#define TOP_P2P     2
#define TOP_SUBNET  3

int tun_open(char *dev, int flags);
int tun_close(int fd);
int dev_type_enum (const char *dev, const char *dev_type);
void do_ifconfig(struct epoll_ptr_data *epd);
char * ifconfig_options_string (struct epoll_ptr_data *epd,bool remote);;
char * dev_type_string (const char *dev, const char *dev_type);
