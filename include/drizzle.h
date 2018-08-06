#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <netinet/tcp.h>
#include <linux/socket.h>
#include <net/if.h>
#include <linux/if_tun.h>


#include <sys/types.h>
#include <sys/ioctl.h>
#include <linux/types.h>
#include <ctype.h>
#include <inttypes.h>
#include <stdbool.h>

#include <sys/stat.h>

#include <dirent.h>
#include <fcntl.h>
#include <net/ethernet.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <pthread.h>
#include <sys/time.h>

#include <assert.h>
#include <stdarg.h>
#include <signal.h>
#include <errno.h>

#include <pwd.h>

#include <grp.h>

#include <sys/mman.h>

#include <limits.h>
#include <netinet/ip.h>
#include <netdb.h>

#include <libgen.h>

#include <sys/wait.h>
#include <syslog.h>

#include <sys/un.h> 
#include <time.h>

#include <sched.h>
#include <sys/resource.h>
#if 0
struct user_data{
	unsigned int key;
	struct epoll_ptr_data *epd;
}user_data_t;


struct main_data{
	struct list_head *li;
	struct rb_table *tree;
	struct options *opt;
	pthread_mutex_t tree_mutex;
	int stop;
	struct tls_root_ctx *ctx;
	struct key_type key_type;
	char session_id[8];
}main_data_t;
#endif

