
int packet_thd(struct pth_timer_data *p_t_d);
int net_process(struct main_data *md,int net_fd,char *thread_name,uint32_t ipaddress);
int tun_process(struct main_data *md);
int pipe_process(struct main_data *md);
int server_process(struct main_data *md,int epoll_fd,int server_fd);
int client_process(struct main_data *md,int client_fd);
int send_thread_process(struct main_data *md,int type);

