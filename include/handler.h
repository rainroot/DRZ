#define SERVER 0
#define CLIENT 1

#define SEND_NET 1
#define SEND_TUN 2
#define SEND_NETNET 3




int net_handler(int net_fd,int tun_fd,int event_flags,void *data);
int tun_rev(int sock ,char *req,int size);
int tun_send(int sock,char *data,int size);
int tcp_send(int sock,char *data,int size);
int tcp_rev(int sock ,char *req,int size);
int net_hand_thd(struct epoll_ptr_data *epd);
int pipe_send(int sock,char *data,int size);
int pipe_rev(int sock ,char *req,int size);
