
struct push_entry {
	struct push_entry *next;
	bool enable;
	//const char *option;
	char option[2048];
};

struct push_list {
	struct push_entry *head;
	struct push_entry *tail;
};

int ctl_msg_process(struct epoll_ptr_data *epd,char *out);
int ctl_msg_request_process(struct epoll_ptr_data *epd,char *out,int cmd);
void clone_push_list (struct options *o);
void push_option (struct options *o, const char *opt);
void push_options (struct options *o, char **p);
void push_reset (struct options *o);
