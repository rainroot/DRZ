int tun_in_out_handle(struct epoll_ptr_data *epd);
int tun_out_in_handle(struct epoll_ptr_data *epd,char *write_buff,int write_len);

int pipe_tun_in_out_handle(struct epoll_ptr_data *epd);
int pipe_tun_out_in_handle(struct epoll_ptr_data *epd,char *write_buff,int write_len);

int net_in_out_handle(struct epoll_ptr_data *epd);
int net_out_in_handle(struct epoll_ptr_data *epd,char *write_buff,int write_len);

int pipe_net_in_out_handle(struct epoll_ptr_data *epd);
int pipe_net_out_in_handle(struct epoll_ptr_data *epd,char *write_buff,int write_len);

int pipe_in_out_handle(struct epoll_ptr_data *epd);
int pipe_out_in_handle(struct epoll_ptr_data *epd,char *write_buf,int write_len);

int TPT_sync_thd(struct pth_timer_data *p_t_d);
int NPT_sync_thd(struct pth_timer_data *p_t_d);

int dz_pthread_mutex_destroy(pthread_mutex_t *mutex);
