int work_to_devfd(struct epoll_ptr_data *epd,char *data,int len,bool ts);
#if 0
int route_tun_in_out(struct epoll_ptr_data *epd,char *data,int len,struct packet_idx_tree_data *get_pitd);
int route_tun_out_in(struct epoll_ptr_data *epd,char *data,int len,struct packet_idx_tree_data *get_pitd);
int route_tap_in_out(struct epoll_ptr_data *epd,char *data,int len,struct packet_idx_tree_data *get_pitd);
int route_tap_out_in(struct epoll_ptr_data *epd,char *data,int len,struct packet_idx_tree_data *get_pitd);
#endif

int tunfd_route_tun_in_out(struct epoll_ptr_data *epd,struct packet_idx_tree_data *get_pitd,struct internal_header *ih);
int tunfd_route_tun_out_in(struct epoll_ptr_data *epd,struct packet_idx_tree_data *get_pitd,struct internal_header *ih);
int tunfd_route_tap_in_out(struct epoll_ptr_data *epd,struct packet_idx_tree_data *get_pitd,struct internal_header *ih);
int tunfd_route_tap_out_in(struct epoll_ptr_data *epd,struct packet_idx_tree_data *get_pitd,struct internal_header *ih);
