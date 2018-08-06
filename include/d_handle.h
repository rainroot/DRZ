
int tun_FD_recv_handle(struct epoll_ptr_data *epd);
int net_FD_recv_handle(struct epoll_ptr_data *epd);
int net_PIPE_recv_handle(struct epoll_ptr_data *epd);
int tun_PIPE_recv_handle(struct epoll_ptr_data *epd);
int net_PIPE_send_handle(struct epoll_ptr_data *epd);
int tun_PIPE_send_handle(struct epoll_ptr_data *epd);
int pipe_RECV_handle(struct epoll_ptr_data *epd);
int pipe_SEND_handle(struct epoll_ptr_data *epd,char *write_buff,int write_len);
int ping_SEND_handle(struct epoll_ptr_data *epd);
int ALL_SEND_handle(struct epoll_ptr_data *epd,int fd,char *data,int len);
int NPT_sync_handle(struct epoll_ptr_data *epd,unsigned int idx);
int TPT_sync_handle(struct epoll_ptr_data *epd,unsigned int idx);
//int pipe_RECV_handle(struct pth_timer_data *p_t_d);
