#include <rain_common.h>

#ifdef ENABLE_MANAGEMENT

#define MANAGEMENT_ECHO_PULL_INFO 0

#if MANAGEMENT_ECHO_PULL_INFO
#define MANAGEMENT_ECHO_FLAGS LOG_PRINT_INTVAL
#else
#define MANAGEMENT_ECHO_FLAGS 0
#endif

int mngt_process(struct main_data *md){
printf("============================================ %s %d ============================\n",__func__,__LINE__);
	struct options *opt = NULL;
	opt = md->opt;

	opt->man = management_init(opt->man);
	printf("## %s %d %08x %08x ##\n",__func__,__LINE__,opt->man->connection.in,opt->man);
	struct pth_timer_data *p_t_d = NULL;
	p_t_d = malloc(sizeof(struct pth_timer_data));
	if(p_t_d == NULL){
		MM("## ERR: EXIT %s %d ##\n",__func__,__LINE__);
		exit(0);
	}
	memset(p_t_d,0x00,sizeof(struct pth_timer_data));
	struct epoll_ptr_data *epd = NULL;
	epd = malloc(sizeof(struct epoll_ptr_data));
	if(epd == NULL){
		printf("## ERR: EXIT %s %d ##\n",__func__,__LINE__);
		exit(0);
	}
	memset(epd,0x00,sizeof(struct epoll_ptr_data));

	struct net_fd_data *n_fdd=NULL;
	n_fdd = malloc(sizeof(struct net_fd_data));
	if(n_fdd == NULL){
		printf("## ERR: EXIT %s %d ##\n",__func__,__LINE__);
		exit(0);
	}
	memset(n_fdd,0x00,sizeof(struct net_fd_data));

	n_fdd->net_fd = tcp_server(opt->management_addr,opt->management_port);
	if(n_fdd->net_fd < 0){
		printf("ERR: server fd %s %d ##\n",__func__,__LINE__);
		exit(0);
	}
	epd->epoll_fd = epoll_init(NET_TUN_MAX_EVENTS);
	if(epoll_add(epd->epoll_fd,n_fdd->net_fd,0) < 0){
		printf("##ERR: EXIT %s %d epoll_fd %d net_rfd %d ##\n",__func__,__LINE__,epd->epoll_fd,n_fdd->net_rfd);
		exit(0);
	}

	epd->n_fdd = n_fdd;
	epd->gl_var = (void *)md;
	epd->thd_mode = THREAD_MNGT;

	p_t_d->func          = rain_timer_start;
	p_t_d->start_func    = (void *)mngt_server_process;
	p_t_d->sec           = 0;
	p_t_d->nsec          = 0;
	p_t_d->ptr           = (void *)epd;
	sprintf(p_t_d->name,"mngt_thread");
	sprintf(epd->name,"mngt_thread");

	unsigned int flags = opt->management_flags;
	if (opt->mode == SERVER){
		flags |= MF_SERVER;
	}
	printf("## %s %d %08x %08x ##\n",__func__,__LINE__,opt->man->connection.in,opt->man);
	if (management_open (opt->man,
				opt->management_addr,
				opt->management_port,
				opt->management_user_pass,
				opt->management_client_user,
				opt->management_client_group,
				opt->management_log_history_cache,
				opt->management_echo_buffer_size,
				opt->management_state_buffer_size,
				opt->management_write_peer_info_file,
				opt->remap_sigusr1,
				flags))
	{
	printf("## %s %d %08x %08x ##\n",__func__,__LINE__,opt->man->connection.in,opt->man);
		management_set_state(epd,opt->man, OPENVPN_STATE_CONNECTING,NULL,(in_addr_t)0,(in_addr_t)0);
	}

	printf("## %s %d %08x %08x ##\n",__func__,__LINE__,opt->man->connection.in,opt->man);
	//p_t_d->timer_status  = 1;
	rain_timer_init(p_t_d);
	return 0;
}


int mngt_server_process(struct pth_timer_data *p_t_d)
{
	int ret=0;
	int nfds=0;
	int i=0;
	int net_fd=0;
	int cli_len =0;
	bool loop = true;
	struct epoll_event events[SERVER_MAX_EVENTS];
	struct sockaddr_in cli_addr;

	struct epoll_ptr_data *epd = NULL;
	epd = (struct epoll_ptr_data *)p_t_d->ptr;

	struct main_data *md = NULL;
	md = (struct main_data *)epd->gl_var;
	struct options *opt = md->opt;

	int recv_len = 0;

	int connecting_count = 0;
	while(loop){
		nfds=epoll_wait(epd->epoll_fd,events,SERVER_MAX_EVENTS,1);
		if(nfds < 0){
			MM("##ERR: %s %d ###\n",__func__,__LINE__);
		}else if(nfds == 0){
			continue;
		}else{
			for(i = 0 ; i < nfds ; i++){
				if(events[i].data.fd == epd->n_fdd->net_fd){
					memset((char *)&cli_addr,0x00,sizeof(cli_addr));
					cli_len =  sizeof(cli_addr);
					net_fd = accept(epd->n_fdd->net_fd, (struct sockaddr *)&cli_addr,(socklen_t *)&cli_len);
					if(net_fd <= 0){
						MM("##ERR: %s %d server_fd %d net_fd %d ###\n",__func__,__LINE__,epd->n_fdd->net_fd,net_fd);
					}else{
						if(connecting_count == 0){
							printf("%03d_%03d_%03d_%03d\n",
									cli_addr.sin_addr.s_addr     & 0x000000ff,
									cli_addr.sin_addr.s_addr>>8  & 0x000000ff,
									cli_addr.sin_addr.s_addr>>16 & 0x000000ff,
									cli_addr.sin_addr.s_addr>>24 & 0x000000ff
									);
							opt->man->connection.sd_cli = net_fd;
							if(epoll_add(epd->epoll_fd,net_fd,0) < 0){
								printf("##ERR: EXIT %s %d epoll_fd %d net_rfd %d ##\n",__func__,__LINE__,epd->epoll_fd,net_fd);
								exit(0);
							}
							connecting_count = 1;
							man_read(epd,opt->man);
						}else{
							close(net_fd);
						}
					}
				}else if(events[i].data.fd == opt->man->connection.sd_cli){

					//printf("## %s %d %08x %08x ##\n",__func__,__LINE__,opt->man->connection.in,opt->man);
					recv_len =  man_read(epd,opt->man);
					if(recv_len <= 0){
						connecting_count = 0;
						opt->man->welcome = false;
						if(epoll_ctl(epd->epoll_fd,EPOLL_CTL_DEL,events[i].data.fd,&events[i]) < 0){
							MM("epoll_ctl error \n");
						}
						printf("### %s %d CLOSE ##\n",__func__,__LINE__);
						close(net_fd);
					}
				}
			}
		}

		if(connecting_count == 1){
			if(opt->man->connection.halt == true){
				man_connection_settings_reset(opt->man);
				printf("### %s %d CLOSE ##\n",__func__,__LINE__);
				connecting_count = 0;
				opt->man->welcome = false;
				if(epoll_ctl(epd->epoll_fd,EPOLL_CTL_DEL,events[i].data.fd,&events[i]) < 0){
					MM("epoll_ctl error \n");
				}
				close(net_fd);
			}
		}
	}
	return ret;
}



void msg(struct management *man,int M, char *fmt, ...)
{
	va_list ap;
	char msg[4096]={0,};

	if(M){}

	va_start(ap,fmt);
	vsprintf(msg+strlen(msg),fmt,ap);
	va_end(ap);
	//syslog(LOG_INFO,"%s",msg);
	printf("%s",msg);
	tcp_send(man->connection.sd_cli,msg,strlen(msg));
}

static inline int modulo_add(int x, int y, int mod)
{
	int sum = x + y;
	assert(0 <= x && x < mod && -mod <= y && y <= mod);
	if (sum >= mod){
		sum -= mod;
	}
	if (sum < 0){
		sum += mod;
	}
	return sum;
}

const char * msg_flags_string (const unsigned int flags)
{
	char * out = malloc(16);
	int sht=0;
	memset(out,0x00,16);

	if (flags == M_INFO){
		sht += sprintf(out+sht,"I");
	}
	if (flags & M_FATAL){
		sht += sprintf(out+sht,"F");
	}
	if (flags & M_NONFATAL){
		sht += sprintf(out+sht,"N");
	}
	if (flags & M_WARN){
		sht += sprintf(out+sht,"W");
	}
	if (flags & M_DEBUG){
		sht += sprintf(out+sht,"D");
	}
	return out;
}

static inline int log_history_size (const struct log_history *h)
{
	return h->size;
}

static inline int log_history_capacity (const struct log_history *h)
{
	return h->capacity;
}

static inline bool management_connected (const struct management *man)
{
	return man->connection.state == MS_CC_WAIT_READ || man->connection.state == MS_CC_WAIT_WRITE;
}

static inline bool management_query_user_pass_enabled (const struct management *man)
{
	return BOOL_CAST(man->settings.flags & MF_QUERY_PASSWORDS);
}

static inline bool management_query_remote_enabled (const struct management *man)
{
	return BOOL_CAST(man->settings.flags & MF_QUERY_REMOTE);
}

static inline bool management_query_proxy_enabled (const struct management *man)
{
	return BOOL_CAST(man->settings.flags & MF_QUERY_PROXY);
}

#ifdef MANAGEMENT_PF
static inline bool management_enable_pf (const struct management *man)
{
	return man && BOOL_CAST(man->settings.flags & MF_CLIENT_PF);
}
#endif

#ifdef MANAGEMENT_DEF_AUTH
static inline bool management_enable_def_auth (const struct management *man)
{
	return man && BOOL_CAST(man->settings.flags & MF_CLIENT_AUTH);
}
#endif

static inline void man_bytecount_possible_output_client (struct management *man)
{
	if (man->connection.bytecount_update_seconds > 0 ){
		man_bytecount_output_client (man);
	}
}

static inline void management_bytes_out_client (struct management *man, const int size)
{
	man->persist.bytes_out += size;
	man_bytecount_possible_output_client (man);
}

static inline void management_bytes_in_client (struct management *man, const int size)
{
	man->persist.bytes_in += size;
	man_bytecount_possible_output_client (man);
}

static inline void management_bytes_out (struct management *man, const int size)
{
	if (!(man->persist.callback.flags & MCF_SERVER)){
		management_bytes_out_client (man, size);
	}
}

static inline void management_bytes_in (struct management *man, const int size)
{
	if (!(man->persist.callback.flags & MCF_SERVER)){
		management_bytes_in_client (man, size);
	}
}

#ifdef MANAGEMENT_DEF_AUTH
static inline void management_bytes_server (struct management *man,unsigned long long bytes_in_total,unsigned long long  bytes_out_total,struct man_def_auth_context *mdac)
{
#if 0
	void man_bytecount_output_server (struct management *man,
			const counter_type *bytes_in_total,
			const counter_type *bytes_out_total,
			struct man_def_auth_context *mdac);
#endif
	if (man->connection.bytecount_update_seconds > 0
			//&& now >= mdac->bytecount_last_update + man->connection.bytecount_update_seconds
			&& (mdac->flags & (DAF_CONNECTION_ESTABLISHED|DAF_CONNECTION_CLOSED)) == DAF_CONNECTION_ESTABLISHED){
		man_bytecount_output_server (man, bytes_in_total, bytes_out_total, mdac);
	}
}
#endif


static const char blank_up[] = "[[BLANK]]";
static const char title_string[] = "Drizzle VPN Management";
struct management *management; /* GLOBAL */

static void man_reset_client_socket (struct management *man, const bool exiting);

static void man_help(struct management *m)
{
	msg(m,M_CLIENT, "Management Interface for %s\n", title_string);
	msg(m,M_CLIENT, "Commands:\n");
	msg(m,M_CLIENT, "auth-retry t           : Auth failure retry mode (none,interact,nointeract).\n");
	msg(m,M_CLIENT, "bytecount n            : Show bytes in/out, update every n secs (0=off).\n");
	msg(m,M_CLIENT, "echo [on|off] [N|all]  : Like log, but only show messages in echo buffer.\n");
	msg(m,M_CLIENT, "exit|quit              : Close management session.\n");
	msg(m,M_CLIENT, "forget-passwords       : Forget passwords entered so far.\n");
	msg(m,M_CLIENT, "help                   : Print this message.\n");
	msg(m,M_CLIENT, "hold [on|off|release]  : Set/show hold flag to on/off state, or\n"); 
	msg(m,M_CLIENT, "                         release current hold and start tunnel.\n"); 
	msg(m,M_CLIENT, "kill cn                : Kill the client instance(s) having common name cn.\n");
	msg(m,M_CLIENT, "kill IP:port           : Kill the client instance connecting from IP:port.\n");
	msg(m,M_CLIENT, "load-stats             : Show global server load stats.\n");
	msg(m,M_CLIENT, "log [on|off] [N|all]   : Turn on/off realtime log display.\n");
	msg(m,M_CLIENT, "                         + show last N lines or 'all' for entire history.\n");
	msg(m,M_CLIENT, "mute [n]               : Set log mute level to n, or show level if n is absent.\n");
	msg(m,M_CLIENT, "needok type action     : Enter confirmation for NEED-OK request of 'type',\n");
	msg(m,M_CLIENT, "                         where action = 'ok' or 'cancel'.\n");
	msg(m,M_CLIENT, "needstr type action    : Enter confirmation for NEED-STR request of 'type',\n");
	msg(m,M_CLIENT, "                         where action is reply string.\n");
	msg(m,M_CLIENT, "net                    : (Windows only) Show network info and routing table.\n");
	msg(m,M_CLIENT, "password type p        : Enter password p for a queried OpenVPN password.\n");
	msg(m,M_CLIENT, "remote type [host port] : Override remote directive, type=ACCEPT|MOD|SKIP.\n");
	msg(m,M_CLIENT, "proxy type [host port flags] : Enter dynamic proxy server info.\n");
	msg(m,M_CLIENT, "pid                    : Show process ID of the current OpenVPN process.\n");
#ifdef ENABLE_PKCS11
	msg(m,M_CLIENT, "pkcs11-id-count        : Get number of available PKCS#11 identities.\n");
	msg(m,M_CLIENT, "pkcs11-id-get index    : Get PKCS#11 identity at index.\n");
#endif
#ifdef MANAGEMENT_DEF_AUTH
	msg(m,M_CLIENT, "client-auth CID KID    : Authenticate client-id/key-id CID/KID (MULTILINE)\n");
	msg(m,M_CLIENT, "client-auth-nt CID KID : Authenticate client-id/key-id CID/KID\n");
	msg(m,M_CLIENT, "client-deny CID KID R [CR] : Deny auth client-id/key-id CID/KID with log reason\n");
	msg(m,M_CLIENT, "                             text R and optional client reason text CR\n");
	msg(m,M_CLIENT, "client-kill CID [M]    : Kill client instance CID with message M (def=RESTART)\n");
	msg(m,M_CLIENT, "env-filter [level]     : Set env-var filter level\n");
#ifdef MANAGEMENT_PF
	msg(m,M_CLIENT, "client-pf CID          : Define packet filter for client CID (MULTILINE)\n");
#endif
#endif
#ifdef MANAGMENT_EXTERNAL_KEY
	msg(m,M_CLIENT, "rsa-sig                : Enter an RSA signature in response to >RSA_SIGN challenge\n");
	msg(m,M_CLIENT, "                         Enter signature base64 on subsequent lines followed by END\n");
#endif
	msg(m,M_CLIENT, "signal s               : Send signal s to daemon,\n");
	msg(m,M_CLIENT, "                         s = SIGHUP|SIGTERM|SIGUSR1|SIGUSR2.\n");
	msg(m,M_CLIENT, "state [on|off] [N|all] : Like log, but show state history.\n");
	msg(m,M_CLIENT, "status [n]             : Show current daemon status info using format #n.\n");
	msg(m,M_CLIENT, "test n                 : Produce n lines of output for testing/debugging.\n");
	msg(m,M_CLIENT, "username type u        : Enter username u for a queried OpenVPN username.\n");
	msg(m,M_CLIENT, "verb [n]               : Set log verbosity level to n, or show if n is absent.\n");
	msg(m,M_CLIENT, "version                : Show current version number.\n");
	msg(m,M_CLIENT, "END\n");
}

const char * man_state_name (const int state)
{
	switch (state)
	{
		case OPENVPN_STATE_INITIAL:
			return "INITIAL";
		case OPENVPN_STATE_CONNECTING:
			return "CONNECTING";
		case OPENVPN_STATE_WAIT:
			return "WAIT";
		case OPENVPN_STATE_AUTH:
			return "AUTH";
		case OPENVPN_STATE_GET_CONFIG:
			return "GET_CONFIG";
		case OPENVPN_STATE_ASSIGN_IP:
			return "ASSIGN_IP";
		case OPENVPN_STATE_ADD_ROUTES:
			return "ADD_ROUTES";
		case OPENVPN_STATE_CONNECTED:
			return "CONNECTED";
		case OPENVPN_STATE_RECONNECTING:
			return "RECONNECTING";
		case OPENVPN_STATE_EXITING:
			return "EXITING";
		case OPENVPN_STATE_RESOLVE:
			return "RESOLVE";
		case OPENVPN_STATE_TCP_CONNECT:
			return "TCP_CONNECT";
		default:
			return "?";
	}
}

static void man_welcome (struct management *man)
{
	msg(man,M_CLIENT, ">INFO:OpenVPN Management Interface Version %d -- type 'help' for more info\n", MANAGEMENT_VERSION);
	if (man->persist.special_state_msg){
		msg(man,M_CLIENT, "%s", man->persist.special_state_msg);
	}
}

inline bool man_password_needed (struct management *man)
{
	return man->settings.up.defined && !man->connection.password_verified;
}

static void man_check_password (struct management *man, const char *line)
{
	if (man_password_needed (man))
	{
		if (streq (line, man->settings.up.password))
		{
			man->connection.password_verified = true;
			msg (man,M_CLIENT, "SUCCESS: password is correct");
			man_welcome (man);
		}
		else
		{
			man->connection.password_verified = false;
			msg (man,M_CLIENT, "ERROR: bad password");
			if (++man->connection.password_tries >= MANAGEMENT_N_PASSWORD_RETRIES)
			{
				MM("MAN: client connection rejected after %d failed password attempts", MANAGEMENT_N_PASSWORD_RETRIES);
				man->connection.halt = true;
			}
		}
	}
}

static void man_update_io_state (struct management *man)
{
		MM("## %s %d ##\n",__func__,__LINE__);
#if 0
	if (socket_defined (man->connection.sd_cli))
	{
		if (buffer_list_defined (man->connection.out))
		{
			man->connection.state = MS_CC_WAIT_WRITE;
		}
		else
		{
			man->connection.state = MS_CC_WAIT_READ;
		}
	}
#endif
}

void man_output_list_push_finalize (struct epoll_ptr_data *epd,struct management *man)
{
	if (management_connected (man))
	{
		man_update_io_state (man);
		if (!man->persist.standalone_disabled)
		{
			volatile int signal_received = 0;
			man_output_standalone (epd,man, &signal_received);
		}
	}
}

static void man_output_list_push_str (struct epoll_ptr_data *epd,struct management *man, const char *str)
{
	if (management_connected (man) && str)
	{
		MM("## %s %d ##\n",__func__,__LINE__);
		//buffer_list_push (man->connection.out, (const unsigned char *) str);
	}
}

void man_output_list_push (struct epoll_ptr_data *epd,struct management *man, const char *str)
{
	man_output_list_push_str (epd,man, str);
	man_output_list_push_finalize (epd,man);
}

void man_prompt (struct epoll_ptr_data *epd,struct management *man)
{
	if (man_password_needed (man))
		man_output_list_push (epd,man, "ENTER PASSWORD:");
#if 0 /* should we use prompt? */
	else
		man_output_list_push (man, ">");
#endif
}
#if 0
static void man_delete_unix_socket (struct management *man)
{
#if UNIX_SOCK_SUPPORT
	if ((man->settings.flags & (MF_UNIX_SOCK|MF_CONNECT_AS_CLIENT)) == MF_UNIX_SOCK)
		socket_delete_unix (&man->settings.local_unix);
#endif
}
#endif

//static void man_close_socket (struct management *man, const socket_descriptor_t sd)
static void man_close_socket (struct management *man, const int fd)
{
	if (man->persist.callback.delete_event){
		MM("## %s %d ##\n",__func__,__LINE__);
		//(*man->persist.callback.delete_event) (man->persist.callback.arg, sd);
		//(*man->persist.callback.delete_event) (man->persist.callback.arg, fd);
	}
	//openvpn_close_socket (sd);
	close(fd);
}

static void virtual_output_callback_func (struct epoll_ptr_data *epd,void *arg, const unsigned int flags, const char *str)
{
	struct management *man = (struct management *) arg;
	static int recursive_level = 0; /* GLOBAL */

	time_t now;
# define AF_DID_PUSH  (1<<0)
# define AF_DID_RESET (1<<1)

	if (!recursive_level) /* don't allow recursion */
	{
		struct log_entry e;
		const char *out = NULL;
		unsigned int action_flags = 0;

		++recursive_level;

		memset(&e,0x00,sizeof(struct log_entry));

		e.timestamp = now;
		e.u.msg_flags = flags;
		e.string = str;
		MM("## %s %d ##\n",__func__,__LINE__);
#if 0
		if (flags & M_FATAL)
			man->persist.standalone_disabled = false;
#endif
		if (flags != M_CLIENT)
			log_history_add (man->persist.log, &e);

		if (!man_password_needed (man))
		{
			if (flags == M_CLIENT){
				out = log_entry_print (&e, LOG_PRINT_CRLF);
			}else if (man->connection.log_realtime){
				out = log_entry_print (&e, LOG_PRINT_INT_DATE
						|   LOG_PRINT_MSG_FLAGS
						|   LOG_PRINT_LOG_PREFIX
						|   LOG_PRINT_CRLF);
			}
			if (out)
			{
				man_output_list_push_str (epd,man, out);
				action_flags |= AF_DID_PUSH;
			}
			MM("## %s %d ##\n",__func__,__LINE__);
#if 0
			if (flags & M_FATAL)
			{
				out = log_entry_print (&e, LOG_FATAL_NOTIFY|LOG_PRINT_CRLF);
				if (out)
				{
					man_output_list_push_str (man, out);
					action_flags |= (AF_DID_PUSH|AF_DID_RESET);
				}
			}
#endif
		}


		if (action_flags & AF_DID_PUSH){
			man_output_list_push_finalize (epd,man);
		}
		if (action_flags & AF_DID_RESET){
			man_reset_client_socket (man, true);
		}

		--recursive_level;
	}
}

/*
 * Given a signal, return the signal with possible remapping applied,
 * or -1 if the signal should be ignored.
 */
	static int
man_mod_signal (const struct management *man, const int signum)
{
	const unsigned int flags = man->settings.mansig;
	int s = signum;
	if (s == SIGUSR1)
	{
		if (flags & MANSIG_MAP_USR1_TO_HUP)
			s = SIGHUP;
		if (flags & MANSIG_MAP_USR1_TO_TERM)
			s = SIGTERM;
	}
	if (flags & MANSIG_IGNORE_USR1_HUP)
	{
		if (s == SIGHUP || s == SIGUSR1)
			s = -1;
	}
	return s;
}

static void man_signal (struct management *man, const char *name)
{
	MM("## %s %d ##\n",__func__,__LINE__); 
#if 0
	const int sig = parse_signal (name);
	if (sig >= 0)
	{
		const int sig_mod = man_mod_signal (man, sig);
		if (sig_mod >= 0)
		{
			MM("## %s %d ##\n",__func__,__LINE__); 
#if 0
			throw_signal (sig_mod);
			msg (M_CLIENT, "SUCCESS: signal %s thrown", signal_name (sig_mod, true));
#endif
		}
		else
		{
			if (man->persist.special_state_msg){
				msg (M_CLIENT, "%s", man->persist.special_state_msg);
			}else{
				msg (M_CLIENT, "ERROR: signal '%s' is currently ignored", name);
			}
		}
	}
	else
	{
		msg (M_CLIENT, "ERROR: signal '%s' is not a known signal type", name);
	}
#endif
}

static void man_status (struct management *man, const int version, struct status_output *so)
{
	if (man->persist.callback.status)
	{
		MM("## %s %d ##\n",__func__,__LINE__);
		//(*man->persist.callback.status) (man->persist.callback.arg, version, so);
	}
	else
	{
		msg (man,M_CLIENT, "ERROR: The 'status' command is not supported by the current daemon mode");
	}
}

static void man_bytecount (struct management *man, const int update_seconds)
{
	if (update_seconds >= 0){
		man->connection.bytecount_update_seconds = update_seconds;
	}else{
		man->connection.bytecount_update_seconds = 0;
	}
	msg (man,M_CLIENT, "SUCCESS: bytecount interval changed");
}

void man_bytecount_output_client (struct management *man)
{
	char in[32];
	char out[32];
	time_t now;
	/* do in a roundabout way to work around possible mingw or mingw-glibc bug */
	//openvpn_snprintf (in, sizeof (in), counter_format, man->persist.bytes_in);
	//openvpn_snprintf (out, sizeof (out), counter_format, man->persist.bytes_out);
	msg (man,M_CLIENT, ">BYTECOUNT:%s,%s", in, out);
	man->connection.bytecount_last_update = now;
}

#ifdef MANAGEMENT_DEF_AUTH

void man_bytecount_output_server (struct management *man, unsigned long long bytes_in_total,unsigned long long bytes_out_total,struct man_def_auth_context *mdac)
{
	msg (man,M_CLIENT, ">BYTECOUNT_CLI:%lu,%lld,%lld", mdac->cid, bytes_in_total, bytes_out_total);
	//mdac->bytecount_last_update = now;
}

#endif

static void man_kill (struct management *man, const char *victim)
{
#if 0
	if (man->persist.callback.kill_by_cn && man->persist.callback.kill_by_addr)
	{
		char p1[128];
		char p2[128];
		int n_killed;

		buf_set_read (&buf, (uint8_t*) victim, strlen (victim) + 1);
		buf_parse (&buf, ':', p1, sizeof (p1));
		buf_parse (&buf, ':', p2, sizeof (p2));

		if (strlen (p1) && strlen (p2))
		{
			bool status;
			const in_addr_t addr = getaddr (GETADDR_HOST_ORDER|GETADDR_MSG_VIRT_OUT, p1, 0, &status, NULL);
			if (status)
			{
				const int port = atoi (p2);
				if (port > 0 && port < 65536)
				{
					n_killed = (*man->persist.callback.kill_by_addr) (man->persist.callback.arg, addr, port);
					if (n_killed > 0)
					{
						msg (M_CLIENT, "SUCCESS: %d client(s) at address %s:%d killed",
								n_killed,
								print_in_addr_t (addr, 0, NULL),
								port);
					}
					else
					{
						msg (M_CLIENT, "ERROR: client at address %s:%d not found",
								print_in_addr_t (addr, 0, NULL),
								port);
					}
				}
				else
				{
					msg (M_CLIENT, "ERROR: port number is out of range: %s", p2);
				}
			}
			else
			{
				msg (M_CLIENT, "ERROR: error parsing IP address: %s", p1);
			}
		}
		else if (strlen (p1))
		{
			n_killed = (*man->persist.callback.kill_by_cn) (man->persist.callback.arg, p1);
			if (n_killed > 0)
			{
				msg (M_CLIENT, "SUCCESS: common name '%s' found, %d client(s) killed", p1, n_killed);
			}
			else
			{
				msg (M_CLIENT, "ERROR: common name '%s' not found", p1);
			}
		}
		else
		{
			msg (M_CLIENT, "ERROR: kill parse");
		}
	}
	else
	{
		msg (M_CLIENT, "ERROR: The 'kill' command is not supported by the current daemon mode");
	}
#endif
}

static void man_history (struct management *man,const char *parm,const char *type,struct log_history *log,bool *realtime,const unsigned int lep_flags)
{
	int n = 0;

	if (streq (parm, "on"))
	{
		*realtime = true;
		msg (man,M_CLIENT, "SUCCESS: real-time %s notification set to ON", type);
	}
	else if (streq (parm, "off"))
	{
		*realtime = false;
		msg (man,M_CLIENT, "SUCCESS: real-time %s notification set to OFF", type);
	}
	else if (streq (parm, "all") || (n = atoi (parm)) > 0)
	{
		const int size = log_history_size (log);
		const int start = (n ? n : size) - 1;
		int i;

		for (i = start; i >= 0; --i)
		{
			const struct log_entry *e = log_history_ref (log, i);
			if (e)
			{
				const char *out = log_entry_print (e, lep_flags);
				//virtual_output_callback_func (man, M_CLIENT, out);
			}
		}
		msg (man,M_CLIENT, "END");
	}
	else
	{
		msg (man,M_CLIENT, "ERROR: %s parameter must be 'on' or 'off' or some number n or 'all'", type);
	}
}

static void man_log (struct management *man, const char *parm)
{
	man_history (man,
			parm,
			"log",
			man->persist.log,
			&man->connection.log_realtime,
			LOG_PRINT_INT_DATE|LOG_PRINT_MSG_FLAGS);
}

static void man_echo (struct management *man, const char *parm)
{
	man_history (man,
			parm,
			"echo",
			man->persist.echo,
			&man->connection.echo_realtime,
			LOG_PRINT_INT_DATE|MANAGEMENT_ECHO_FLAGS);
}

static void man_state (struct management *man, const char *parm)
{
	man_history (man,
			parm,
			"state",
			man->persist.state,
			&man->connection.state_realtime,
			LOG_PRINT_INT_DATE|LOG_PRINT_STATE|
			LOG_PRINT_LOCAL_IP|LOG_PRINT_REMOTE_IP);
}

static void man_up_finalize (struct management *man)
{
	switch (man->connection.up_query_mode)
	{
		case UP_QUERY_USER_PASS:
			if (!strlen (man->connection.up_query.username))
				break;
			/* fall through */
		case UP_QUERY_PASS:
		case UP_QUERY_NEED_OK:
		case UP_QUERY_NEED_STR:
			if (strlen (man->connection.up_query.password))
				man->connection.up_query.defined = true;
			break;
		case UP_QUERY_DISABLED:
			man->connection.up_query.defined = false;
			break;
		default:
			assert(0);
	}
}

static void man_query_user_pass (struct management *man,
		const char *type,
		const char *string,
		const bool needed,
		const char *prompt,
		char *dest,
		int len)
{
	if (needed)
	{
		assert(man->connection.up_query_type);
		if (streq (man->connection.up_query_type, type))
		{
			strncpynt (dest, string, len);
			man_up_finalize (man);
			msg (man,M_CLIENT, "SUCCESS: '%s' %s entered, but not yet verified",
					type,
					prompt);
		}
		else
			msg (man,M_CLIENT, "ERROR: %s of type '%s' entered, but we need one of type '%s'",
					prompt,
					type,
					man->connection.up_query_type);
	}
	else
	{
		msg (man,M_CLIENT, "ERROR: no %s is currently needed at this time", prompt);
	}
}

	static void
man_query_username (struct management *man, const char *type, const char *string)
{
	const bool needed = ((man->connection.up_query_mode == UP_QUERY_USER_PASS
				) && man->connection.up_query_type);
	man_query_user_pass (man, type, string, needed, "username", man->connection.up_query.username, USER_PASS_LEN);
}

	static void
man_query_password (struct management *man, const char *type, const char *string)
{
	const bool needed = ((man->connection.up_query_mode == UP_QUERY_PASS
				|| man->connection.up_query_mode == UP_QUERY_USER_PASS
				) && man->connection.up_query_type);
	if (!string[0]) /* allow blank passwords to be passed through using the blank_up tag */
		string = blank_up;
	man_query_user_pass (man, type, string, needed, "password", man->connection.up_query.password, USER_PASS_LEN);
}

	static void
man_query_need_ok (struct management *man, const char *type, const char *action)
{
	const bool needed = ((man->connection.up_query_mode == UP_QUERY_NEED_OK) && man->connection.up_query_type);
	man_query_user_pass (man, type, action, needed, "needok-confirmation", man->connection.up_query.password, USER_PASS_LEN);
}

	static void
man_query_need_str (struct management *man, const char *type, const char *action)
{
	const bool needed = ((man->connection.up_query_mode == UP_QUERY_NEED_STR) && man->connection.up_query_type);
	man_query_user_pass (man, type, action, needed, "needstr-string", man->connection.up_query.password, USER_PASS_LEN);
}

void man_forget_passwords (struct management *man)
{
#if 0
#if defined(ENABLE_CRYPTO) && defined(ENABLE_SSL)
	ssl_purge_auth (false);
	msg (man,M_CLIENT, "SUCCESS: Passwords were forgotten");
#endif
#endif
}

static void man_net (struct management *man)
{
	if (man->persist.callback.show_net)
	{
		(*man->persist.callback.show_net) (man->persist.callback.arg, M_CLIENT);
	}
	else
	{
		msg (man,M_CLIENT, "ERROR: The 'net' command is not supported by the current daemon mode");
	}
}

#ifdef ENABLE_PKCS11

	static void
man_pkcs11_id_count (struct management *man)
{
	msg (man,M_CLIENT, ">PKCS11ID-COUNT:%d", pkcs11_management_id_count ());
}

	static void
man_pkcs11_id_get (struct management *man, const int index)
{
	char *id = NULL;
	char *base64 = NULL;

	if (pkcs11_management_id_get (index, &id, &base64))
		msg (man,M_CLIENT, ">PKCS11ID-ENTRY:'%d', ID:'%s', BLOB:'%s'", index, id, base64);
	else
		msg (man,M_CLIENT, ">PKCS11ID-ENTRY:'%d'", index);

	if (id != NULL)
		free (id);
	if (base64 != NULL)
		free (base64);
}

#endif

static void man_hold (struct management *man, const char *cmd)
{
	if (cmd)
	{
		if (streq (cmd, "on"))
		{
			man->settings.flags |= MF_HOLD;
			msg (man,M_CLIENT, "SUCCESS: hold flag set to ON");
		}
		else if (streq (cmd, "off"))
		{
			man->settings.flags &= ~MF_HOLD;
			msg (man,M_CLIENT, "SUCCESS: hold flag set to OFF");
		}
		else if (streq (cmd, "release"))
		{
			man->persist.hold_release = true;
			msg (man,M_CLIENT, "SUCCESS: hold release succeeded");
		}
		else
		{
			msg (man,M_CLIENT, "ERROR: bad hold command parameter");
		}
	}
	else
		msg (man,M_CLIENT, "SUCCESS: hold=%d", BOOL_CAST(man->settings.flags & MF_HOLD));
}

#ifdef MANAGEMENT_IN_EXTRA

#define IER_RESET      0
#define IER_NEW        1

static void in_extra_reset (struct man_connection *mc, const int mode)
{
	printf("## %s %d ##\n",__func__,__LINE__);
	if (mc)
	{
		if (mode != IER_NEW)
		{
			mc->in_extra_cmd = IEC_UNDEF;
#ifdef MANAGEMENT_DEF_AUTH
			mc->in_extra_cid = 0;
			mc->in_extra_kid = 0;
#endif
		}
		if (mc->in_extra)
		{
#if 0
			buffer_list_free (mc->in_extra);
#endif
			mc->in_extra = NULL;
		}
		if (mode == IER_NEW){
#if 0
			mc->in_extra = buffer_list_new (0);
#endif
		}
	}
}

static void in_extra_dispatch (struct management *man)
{
	switch (man->connection.in_extra_cmd)
	{
#ifdef MANAGEMENT_DEF_AUTH
		case IEC_CLIENT_AUTH:
			if (man->persist.callback.client_auth)
			{
#if 0
				const bool status = (*man->persist.callback.client_auth)
					(man->persist.callback.arg,
					 man->connection.in_extra_cid,
					 man->connection.in_extra_kid,
					 true,
					 NULL,
					 NULL,
					 man->connection.in_extra);

#else
				const bool status = (*man->persist.callback.client_auth)
					(man->persist.callback.arg,
					 man->connection.in_extra_cid,
					 man->connection.in_extra_kid,
					 true,
					 NULL,
					 NULL);
#endif
				man->connection.in_extra = NULL;
				if (status)
				{
					msg (man,M_CLIENT, "SUCCESS: client-auth command succeeded");
				}
				else
				{
					msg (man,M_CLIENT, "ERROR: client-auth command failed");
				}
			}
			else
			{
				msg (man,M_CLIENT, "ERROR: The client-auth command is not supported by the current daemon mode");
			}
			break;
#endif
#ifdef MANAGEMENT_PF
		case IEC_CLIENT_PF:
			if (man->persist.callback.client_pf)
			{
				const bool status = (*man->persist.callback.client_pf)
					(man->persist.callback.arg,
					 man->connection.in_extra_cid,
					 man->connection.in_extra);
				man->connection.in_extra = NULL;
				if (status)
				{
					msg (man,M_CLIENT, "SUCCESS: client-pf command succeeded");
				}
				else
				{
					msg (man,M_CLIENT, "ERROR: client-pf command failed");
				}
			}
			else
			{
				msg (man,M_CLIENT, "ERROR: The client-pf command is not supported by the current daemon mode");
			}
			break;
#endif
#ifdef MANAGMENT_EXTERNAL_KEY
		case IEC_RSA_SIGN:
			man->connection.ext_key_state = EKS_READY;
			buffer_list_free (man->connection.ext_key_input);
			man->connection.ext_key_input = man->connection.in_extra;
			man->connection.in_extra = NULL;
			return;
#endif
	}
	in_extra_reset (&man->connection, IER_RESET);
}

#endif /* MANAGEMENT_IN_EXTRA */

#ifdef MANAGEMENT_DEF_AUTH

static bool parse_cid (struct management *man,const char *str, unsigned long *cid)
{
	if (sscanf (str, "%lu", cid) == 1)
		return true;
	else
	{
		msg (man,M_CLIENT, "ERROR: cannot parse CID");
		return false;
	}
}

static bool parse_kid (struct management *man,const char *str, unsigned int *kid)
{
	if (sscanf (str, "%u", kid) == 1){
		return true;
	}else
	{
		msg (man,M_CLIENT, "ERROR: cannot parse KID");
		return false;
	}
}

static void man_client_auth (struct management *man, const char *cid_str, const char *kid_str, const bool extra)
{
	struct man_connection *mc = &man->connection;
	mc->in_extra_cid = 0;
	mc->in_extra_kid = 0;
	if (parse_cid (man,cid_str, &mc->in_extra_cid)
			&& parse_kid (man,kid_str, &mc->in_extra_kid))
	{
		mc->in_extra_cmd = IEC_CLIENT_AUTH;
		in_extra_reset (mc, IER_NEW);
		if (!extra)
			in_extra_dispatch (man);
	}
}

static void man_client_deny (struct management *man, const char *cid_str, const char *kid_str, const char *reason, const char *client_reason)
{
	unsigned long cid = 0;
	unsigned int kid = 0;
	if (parse_cid (man,cid_str, &cid) && parse_kid (man,kid_str, &kid))
	{
		if (man->persist.callback.client_auth)
		{
#if 0
			const bool status = (*man->persist.callback.client_auth)
				(man->persist.callback.arg,
				 cid,
				 kid,
				 false,
				 reason,
				 client_reason,
				 NULL);

#else
			const bool status = (*man->persist.callback.client_auth)
				(man->persist.callback.arg,
				 cid,
				 kid,
				 false,
				 reason,
				 client_reason);
#endif
			if (status)
			{
				msg (man,M_CLIENT, "SUCCESS: client-deny command succeeded");
			}
			else
			{
				msg (man,M_CLIENT, "ERROR: client-deny command failed");
			}
		}
		else
		{
			msg (man,M_CLIENT, "ERROR: The client-deny command is not supported by the current daemon mode");
		}
	}
}

static void man_client_kill (struct management *man, const char *cid_str, const char *kill_msg)
{
	unsigned long cid = 0;
	if (parse_cid (man,cid_str, &cid))
	{
		if (man->persist.callback.kill_by_cid)
		{
			const bool status = (*man->persist.callback.kill_by_cid) (man->persist.callback.arg, cid, kill_msg);
			if (status)
			{
				msg (man,M_CLIENT, "SUCCESS: client-kill command succeeded");
			}
			else
			{
				msg (man,M_CLIENT, "ERROR: client-kill command failed");
			}
		}
		else
		{
			msg (man,M_CLIENT, "ERROR: The client-kill command is not supported by the current daemon mode");
		}
	}
}

static void man_client_n_clients (struct management *man)
{
	if (man->persist.callback.n_clients)
	{
		const int nclients = (*man->persist.callback.n_clients) (man->persist.callback.arg);
		msg (man,M_CLIENT, "SUCCESS: nclients=%d", nclients);
	}
	else
	{
		msg (man,M_CLIENT, "ERROR: The nclients command is not supported by the current daemon mode");
	}
}
#if 0
static void man_env_filter (struct management *man, const int level)
{
	man->connection.env_filter_level = level;
	msg (man,M_CLIENT, "SUCCESS: env_filter_level=%d", level);
}
#endif

#ifdef MANAGEMENT_PF

static void man_client_pf (struct management *man, const char *cid_str)
{
	struct man_connection *mc = &man->connection;
	mc->in_extra_cid = 0;
	mc->in_extra_kid = 0;
	if (parse_cid (man,cid_str, &mc->in_extra_cid))
	{
		mc->in_extra_cmd = IEC_CLIENT_PF;
		in_extra_reset (mc, IER_NEW);
	}
}

#endif /* MANAGEMENT_PF */
#endif /* MANAGEMENT_DEF_AUTH */

#ifdef MANAGMENT_EXTERNAL_KEY

static void man_rsa_sig (struct management *man)
{
	struct man_connection *mc = &man->connection;
	if (mc->ext_key_state == EKS_SOLICIT)
	{
		mc->ext_key_state = EKS_INPUT;
		mc->in_extra_cmd = IEC_RSA_SIGN;
		in_extra_reset (mc, IER_NEW);
	}
	else{
		msg (M_CLIENT, "ERROR: The rsa-sig command is not currently available");
	}
}

#endif

static void man_load_stats (struct management *man)
{
	MM("## %s %d ##\n",__func__,__LINE__);
#if 0
	extern counter_type link_read_bytes_global;
	extern counter_type link_write_bytes_global;
	int nclients = 0;

	if (man->persist.callback.n_clients){
		nclients = (*man->persist.callback.n_clients) (man->persist.callback.arg);
	}
	msg (M_CLIENT, "SUCCESS: nclients=%d,bytesin=" counter_format ",bytesout=" counter_format,
			nclients,
			link_read_bytes_global,
			link_write_bytes_global);
#endif
}

#define MN_AT_LEAST (1<<0)

static bool man_need (struct management *man, const char **p, const int n, unsigned int flags)
{
	int i;
	assert(p[0]);
	for (i = 1; i <= n; ++i)
	{
		if (!p[i])
		{
			msg (man,M_CLIENT, "ERROR: the '%s' command requires %s%d parameter%s",
					p[0],
					(flags & MN_AT_LEAST) ? "at least " : "",
					n,
					n > 1 ? "s" : "");
			return false;
		}
	}
	return true;
}

static void man_proxy (struct management *man, const char **p)
{
	if (man->persist.callback.proxy_cmd)
	{
		const bool status = (*man->persist.callback.proxy_cmd)(man->persist.callback.arg, p);
		if (status){
			msg (man,M_CLIENT, "SUCCESS: proxy command succeeded");
		}else{
			msg (man,M_CLIENT, "ERROR: proxy command failed");
		}
	}
	else{
		msg (man,M_CLIENT, "ERROR: The proxy command is not supported by the current daemon mode");
	}
}

static void man_remote (struct management *man, const char **p)
{
	if (man->persist.callback.remote_cmd)
	{
		const bool status = (*man->persist.callback.remote_cmd)(man->persist.callback.arg, p);
		if (status)
		{
			msg (man,M_CLIENT, "SUCCESS: remote command succeeded");
		}
		else
		{
			msg (man,M_CLIENT, "ERROR: remote command failed");
		}
	}
	else
	{
		msg (man,M_CLIENT, "ERROR: The remote command is not supported by the current daemon mode");
	}
}

static void man_dispatch_command (struct management *man, struct status_output *so, const char **p, const int nparms)
{

	assert(p[0]);
	printf("## %s %d %s ##\n",__func__,__LINE__,p[0]);
	if (streq (p[0], "exit") || streq (p[0], "quit"))
	{
		man->connection.halt = true;
		return;
	}
	else if (streq (p[0], "help"))
	{
		man_help (man);
		printf("## %s %d ##\n",__func__,__LINE__);
	}
	else if (streq (p[0], "version"))
	{
		msg (man,M_CLIENT, "%s : ", title_string);
		msg (man,M_CLIENT, "Management Version: %d \n", MANAGEMENT_VERSION);
		msg (man,M_CLIENT, "END");
	}
	else if (streq (p[0], "pid"))
	{
		msg (man,M_CLIENT, "SUCCESS: pid=%d", getpid ());
	}
#ifdef MANAGEMENT_DEF_AUTH
	else if (streq (p[0], "nclients"))
	{
		man_client_n_clients (man);
	}
#if 0
	else if (streq (p[0], "env-filter"))
	{
		int level = 0;
		if (p[1])
			level = atoi (p[1]);
		man_env_filter (man, level);

	}
#endif
#endif
	else if (streq (p[0], "signal"))
	{
		if (man_need (man, p, 1, 0))
			man_signal (man, p[1]);
	}
	else if (streq (p[0], "load-stats"))
	{
		man_load_stats (man);
	}
	else if (streq (p[0], "status"))
	{
		int version = 0;
		if (p[1])
			version = atoi (p[1]);
		man_status (man, version, so);
	}
	else if (streq (p[0], "kill"))
	{
		if (man_need (man, p, 1, 0))
			man_kill (man, p[1]);
	}
	else if (streq (p[0], "verb"))
	{
		MM("## %s %d ##\n",__func__,__LINE__);
#if 0
		if (p[1])
		{
			const int level = atoi(p[1]);
			if (set_debug_level (level, 0))
				msg (M_CLIENT, "SUCCESS: verb level changed");
			else
				msg (M_CLIENT, "ERROR: verb level is out of range");
		}
		else{
			msg (M_CLIENT, "SUCCESS: verb=%d", get_debug_level ());
		}
#endif
	}
	else if (streq (p[0], "mute"))
	{
		MM("## %s %d ##\n",__func__,__LINE__);
#if 0
		if (p[1])
		{
			const int level = atoi(p[1]);
			if (set_mute_cutoff (level))
				msg (M_CLIENT, "SUCCESS: mute level changed");
			else
				msg (M_CLIENT, "ERROR: mute level is out of range");
		}
		else{
			//msg (M_CLIENT, "SUCCESS: mute=%d", get_mute_cutoff ());
			MM("## %s %d ##\n",__func__,__LINE__);
		}
#endif
	}
	else if (streq (p[0], "auth-retry"))
	{
#if P2MP
		if (p[1])
		{
			if (auth_retry_set (M_CLIENT, p[1])){
				msg (man,M_CLIENT, "SUCCESS: auth-retry parameter changed");
			}else{
				msg (man,M_CLIENT, "ERROR: bad auth-retry parameter");
			}
		}
		else{
			msg (man,M_CLIENT, "SUCCESS: auth-retry=%s", auth_retry_print ());	
		}
#else
		msg (man,M_CLIENT, "ERROR: auth-retry feature is unavailable");
#endif
	}
	else if (streq (p[0], "state"))
	{
		if (!p[1])
		{
			man_state (man, "1");
		}
		else
		{
			if (p[1])
				man_state (man, p[1]);
			if (p[2])
				man_state (man, p[2]);
		}
	}
	else if (streq (p[0], "log"))
	{
		if (man_need (man, p, 1, MN_AT_LEAST))
		{
			if (p[1])
				man_log (man, p[1]);
			if (p[2])
				man_log (man, p[2]);
		}
	}
	else if (streq (p[0], "echo"))
	{
		if (man_need (man, p, 1, MN_AT_LEAST))
		{
			if (p[1])
				man_echo (man, p[1]);
			if (p[2])
				man_echo (man, p[2]);
		}
	}
	else if (streq (p[0], "username"))
	{
		if (man_need (man, p, 2, 0))
			man_query_username (man, p[1], p[2]);
	}
	else if (streq (p[0], "password"))
	{
		if (man_need (man, p, 2, 0))
			man_query_password (man, p[1], p[2]);
	}
	else if (streq (p[0], "forget-passwords"))
	{
		man_forget_passwords (man);
	}
	else if (streq (p[0], "needok"))
	{
		if (man_need (man, p, 2, 0))
			man_query_need_ok (man, p[1], p[2]);
	}
	else if (streq (p[0], "needstr"))
	{
		if (man_need (man, p, 2, 0))
			man_query_need_str (man, p[1], p[2]);
	}
	else if (streq (p[0], "net"))
	{
		man_net (man);
	}
	else if (streq (p[0], "hold"))
	{
		man_hold (man, p[1]);
	}
	else if (streq (p[0], "bytecount"))
	{
		if (man_need (man, p, 1, 0))
			man_bytecount (man, atoi(p[1]));
	}
#ifdef MANAGEMENT_DEF_AUTH
	else if (streq (p[0], "client-kill"))
	{
		if (man_need (man, p, 1, MN_AT_LEAST))
			man_client_kill (man, p[1], p[2]);
	}
	else if (streq (p[0], "client-deny"))
	{
		if (man_need (man, p, 3, MN_AT_LEAST))
			man_client_deny (man, p[1], p[2], p[3], p[4]);
	}
	else if (streq (p[0], "client-auth-nt"))
	{
		if (man_need (man, p, 2, 0))
			man_client_auth (man, p[1], p[2], false);
	}
	else if (streq (p[0], "client-auth"))
	{
		if (man_need (man, p, 2, 0))
			man_client_auth (man, p[1], p[2], true);
	}
#ifdef MANAGEMENT_PF
	else if (streq (p[0], "client-pf"))
	{
		if (man_need (man, p, 1, 0))
			man_client_pf (man, p[1]);
	}
#endif
#endif
#ifdef MANAGMENT_EXTERNAL_KEY
	else if (streq (p[0], "rsa-sig"))
	{
		man_rsa_sig (man);
	}
#endif
#ifdef ENABLE_PKCS11
	else if (streq (p[0], "pkcs11-id-count"))
	{
		man_pkcs11_id_count (man);
	}
	else if (streq (p[0], "pkcs11-id-get"))
	{
		if (man_need (man, p, 1, 0))
			man_pkcs11_id_get (man, atoi(p[1]));
	}
#endif
	else if (streq (p[0], "proxy"))
	{
		if (man_need (man, p, 1, MN_AT_LEAST))
			man_proxy (man, p);
	}
	else if (streq (p[0], "remote"))
	{
		if (man_need (man, p, 1, MN_AT_LEAST))
			man_remote (man, p);
	}
#if 1
	else if (streq (p[0], "test"))
	{
		if (man_need (man, p, 1, 0))
		{
			int i;
			const int n = atoi (p[1]);
			for (i = 0; i < n; ++i)
			{
				msg (M_CLIENT, "[%d] The purpose of this command is to generate large amounts of output.", i);
			}
		}
	}
#endif
	else
	{
		msg (man,M_CLIENT, "ERROR: unknown command, enter 'help' for more options");
	}

}

static void man_record_peer_info (struct management *man)
{
	if (man->settings.write_peer_info_file)
	{
		bool success = false;
#ifdef HAVE_GETSOCKNAME
		if (socket_defined (man->connection.sd_cli))
		{
			struct sockaddr_in addr;
			socklen_t addrlen = sizeof (addr);
			int status;

			memset(&addr,0x00,sizeof(struct sockaddr_in));
			status = getsockname (man->connection.sd_cli, (struct sockaddr *)&addr, &addrlen);
			if (!status && addrlen == sizeof (addr))
			{
				const in_addr_t a = ntohl (addr.sin_addr.s_addr);
				const int p = ntohs (addr.sin_port);
				FILE *fp = fopen (man->settings.write_peer_info_file, "w");
				if (fp)
				{
					fprintf (fp, "%s\n%d\n", print_in_addr_t (a, 0,NULL), p);
					if (!fclose (fp)){
						success = true;
					}
				}
			}
		}
#endif
		if (!success)
		{
			MM("MANAGEMENT: failed to write peer info to file %s", man->settings.write_peer_info_file);
			//throw_signal_soft (SIGTERM, "management-connect-failed");
		}
	}
}

void man_connection_settings_reset (struct management *man)
{
	man->connection.state_realtime = false;
	man->connection.log_realtime = false;
	man->connection.echo_realtime = false;
	man->connection.bytecount_update_seconds = 0;
	man->connection.password_verified = false;
	man->connection.password_tries = 0;
	man->connection.halt = false;
	man->connection.state = MS_CC_WAIT_WRITE;
}

static void man_new_connection_post (struct epoll_ptr_data *epd,struct management *man, const char *description)
{

	//set_nonblock (man->connection.sd_cli);
	//set_cloexec (man->connection.sd_cli);

	man_connection_settings_reset (man);

#if UNIX_SOCK_SUPPORT
	if (man->settings.flags & MF_UNIX_SOCK)
	{
		MM("MANAGEMENT: %s %s",
			description,
			sockaddr_unix_name (&man->settings.local_unix, "NULL"));
	}
	else
#endif
	{
#if 0
		MM("MANAGEMENT: %s %s",
				description,
				print_sockaddr (&man->settings.local, &gc));
#endif
	}
	//buffer_list_reset (man->connection.out);

	if (!man_password_needed (man)){
		man_welcome (man);
	}
	man_prompt (epd,man);
	man_update_io_state (man);

}

#if UNIX_SOCK_SUPPORT
static bool man_verify_unix_peer_uid_gid (struct management *man, const socket_descriptor_t sd)
{
	if (socket_defined (sd) && (man->settings.client_uid != -1 || man->settings.client_gid != -1))
	{
		static const char err_prefix[] = "MANAGEMENT: unix domain socket client connection rejected --";
		int uid, gid;
		if (unix_socket_get_peer_uid_gid (man->connection.sd_cli, &uid, &gid))
		{
			if (man->settings.client_uid != -1 && man->settings.client_uid != uid)
			{
				MM("%s UID of socket peer (%d) doesn't match required value (%d) as given by --management-client-user", err_prefix, uid, man->settings.client_uid);
				return false;
			}
			if (man->settings.client_gid != -1 && man->settings.client_gid != gid)
			{
				MM("%s GID of socket peer (%d) doesn't match required value (%d) as given by --management-client-group",err_prefix, gid, man->settings.client_gid);
				return false;
			}
		}
		else
		{
			MM("%s cannot get UID/GID of socket peer", err_prefix);
			return false;
		}
	}
	return true;
}
#endif

static void man_accept (struct management *man)
{
	MM("## %s %d ##\n",__func__,__LINE__);
#if 0
	struct link_socket_actual act;
	CLEAR (act);

#if UNIX_SOCK_SUPPORT
	if (man->settings.flags & MF_UNIX_SOCK)
	{
		struct sockaddr_un remote;
		man->connection.sd_cli = socket_accept_unix (man->connection.sd_top, &remote);
		if (!man_verify_unix_peer_uid_gid (man, man->connection.sd_cli)){
			sd_close (&man->connection.sd_cli);
		}
	}
	else
#endif
		man->connection.sd_cli = socket_do_accept (man->connection.sd_top, &act, false);

	if (socket_defined (man->connection.sd_cli))
	{
		man->connection.remote = act.dest;

		if (socket_defined (man->connection.sd_top))
		{
		}

		man_new_connection_post (man, "Client connected from");
	}
#endif
}

static void man_listen (struct management *man)
{
	MM("## %s %d ##\n",__func__,__LINE__);
#if 0
	man->connection.state = MS_LISTEN;
	man->connection.sd_cli = SOCKET_UNDEFINED;

	if (man->connection.sd_top == SOCKET_UNDEFINED)
	{
#if UNIX_SOCK_SUPPORT
		if (man->settings.flags & MF_UNIX_SOCK)
		{
			man_delete_unix_socket (man);
			man->connection.sd_top = create_socket_unix ();
			socket_bind_unix (man->connection.sd_top, &man->settings.local_unix, "MANAGEMENT");
		}
		else
#endif
		{
			man->connection.sd_top = create_socket_tcp (AF_INET);
			socket_bind (man->connection.sd_top, &man->settings.local, "MANAGEMENT");
		}

		if (listen (man->connection.sd_top, 1)){
			MM("MANAGEMENT: listen() failed");
		}

		set_nonblock (man->connection.sd_top);
		set_cloexec (man->connection.sd_top);

#if UNIX_SOCK_SUPPORT
		if (man->settings.flags & MF_UNIX_SOCK)
		{
			MM("MANAGEMENT: unix domain socket listening on %s", sockaddr_unix_name (&man->settings.local_unix, "NULL"));
		}
		else
#endif
			//MM("MANAGEMENT: TCP Socket listening on %s",print_sockaddr (&man->settings.local,NULL));
	}
#endif
}

static void man_connect (struct management *man)
{
	int status;
	int signal_received = 0;
#if 0
	man->connection.state = MS_INITIAL;
	man->connection.sd_top = SOCKET_UNDEFINED;

#if UNIX_SOCK_SUPPORT
	if (man->settings.flags & MF_UNIX_SOCK)
	{
		man->connection.sd_cli = create_socket_unix ();
		status = socket_connect_unix (man->connection.sd_cli, &man->settings.local_unix);
		if (!status && !man_verify_unix_peer_uid_gid (man, man->connection.sd_cli))
		{
#ifdef EPERM
			status = EPERM;
#else
			status = 1;
#endif
			sd_close (&man->connection.sd_cli);
		}
	}
	else
#endif
	{
		man->connection.sd_cli = create_socket_tcp (AF_INET);
		status = openvpn_connect (man->connection.sd_cli, &man->settings.local,5,&signal_received);
	}

	if (signal_received)
	{
		throw_signal (signal_received);
		goto done;
	}

	if (status)
	{
#if UNIX_SOCK_SUPPORT
		if (man->settings.flags & MF_UNIX_SOCK)
		{
			MM("MANAGEMENT: connect to unix socket %s failed: %s",
					sockaddr_unix_name (&man->settings.local_unix, "NULL"),
					strerror_ts (status, &gc));
		}
		else{
#endif
			MM("MANAGEMENT: connect to %s failed: %s",
					print_sockaddr (&man->settings.local,NULL),
					strerror_ts (status));
		}
		throw_signal_soft (SIGTERM, "management-connect-failed");
		goto done;
	}

	man_record_peer_info (man);
	man_new_connection_post (man, "Connected to management server at");

done:
#endif
}

static void man_reset_client_socket (struct management *man, const bool exiting)
{

	MM("## %s %d ##\n",__func__,__LINE__);
#if 0
	if (socket_defined (man->connection.sd_cli))
	{
		man_close_socket (man, man->connection.sd_cli);
		man->connection.sd_cli = SOCKET_UNDEFINED;
		man->connection.state = MS_INITIAL;
		command_line_reset (man->connection.in);
		//buffer_list_reset (man->connection.out);
#ifdef MANAGEMENT_IN_EXTRA
		in_extra_reset (&man->connection, IER_RESET);
#endif
		MM("MANAGEMENT: Client disconnected");
	}
	if (!exiting)
	{
#if defined(ENABLE_CRYPTO) && defined(ENABLE_SSL)
		if (man->settings.flags & MF_FORGET_DISCONNECT){
			ssl_purge_auth (false);
		}
#endif
		if (man->settings.flags & MF_SIGNAL) {
			int mysig = man_mod_signal (man, SIGUSR1);
			if (mysig >= 0)
			{
				MM("MANAGEMENT: Triggering management signal");
				//throw_signal_soft (mysig, "management-disconnect");
			}
		}

		if (man->settings.flags & MF_CONNECT_AS_CLIENT)
		{
			MM("MANAGEMENT: Triggering management exit");
			//throw_signal_soft (SIGTERM, "management-exit");
		}
		else{
			man_listen (man);
		}
	}
#endif
}

static void man_process_command (struct management *man, const char *line)
{
	int nparms;
	char *parms[MAX_PARMS+1];

#ifdef MANAGEMENT_IN_EXTRA
	in_extra_reset (&man->connection, IER_RESET);
#endif

	if (man_password_needed (man))
	{
		man_check_password (man, line);
	}
	else
	{
		nparms = parse_line (line, parms, MAX_PARMS, "TCP", 0);
		if (parms[0] && streq (parms[0], "password")){
			MM("MANAGEMENT: CMD 'password [...]'");
		}else if (!streq (line, "load-stats")){
			MM("MANAGEMENT: CMD '%s'", line);
		}
		if (nparms > 0){
			man_dispatch_command (man, NULL, (const char **)parms, nparms);
		}
	}

}

static bool man_io_error (struct management *man, const char *prefix)
{

	MM("## %s %d ##\n",__func__,__LINE__);
#if 0
	const int err = openvpn_errno ();

	if (!ignore_sys_error (err))
	{
		MM("MANAGEMENT: TCP %s error: %s",prefix ,strerror_ts (err));

		return true;
	}
	else{
		return false;
	}
#else
	return false;
#endif
}

int man_read (struct epoll_ptr_data *epd,struct management *man)
{
	unsigned char buf[256];
	int len = 0;

	if (!man_password_needed (man)){
		if(man->welcome == false){
			man_welcome (man);
			man->welcome = true;
		}
	}
	len = recv (man->connection.sd_cli, buf, sizeof (buf), MSG_NOSIGNAL);
	if (len == 0)
	{
		man_reset_client_socket (man, false);
	}
	else if (len > 0)
	{
		bool processed_command = false;
		unsigned char *line;

		assert (len <= (int) sizeof (buf));
		command_line_add (man->connection.in, buf, len);

		memset(man->connection.out,0x00,4096);
#if 0
		{
			const unsigned char *line;
			while ((line = command_line_get (man->connection.in)))
			{
#ifdef MANAGEMENT_IN_EXTRA
				if (man->connection.in_extra)
				{
					if (!strcmp ((char *)line, "END"))
						in_extra_dispatch (man);
					else
						buffer_list_push (man->connection.in_extra, line);
				}
				else
#endif
					man_process_command (man, (char *) line);
				if (man->connection.halt)
					break;
				command_line_next (man->connection.in);
				processed_command = true;
			}

		}

		if (man->connection.halt)
		{
			man_reset_client_socket (man, false);
			len = 0;
		}
		else
		{
			if (processed_command){
				man_prompt (epd,man);
			}
			man_update_io_state (man);
		}


#else
		{

#ifdef MANAGEMENT_IN_EXTRA
			if (man->connection.in_extra)
			{
				if (!strcmp ((char *)line, "END")){
					in_extra_dispatch (man);
				}else{
#if 0
					buffer_list_push (man->connection.in_extra, line);
#endif
				}
			}
			else
#endif
			{
				printf("## %s %d %d ##\n",__func__,__LINE__,len);
				man_process_command (man, man->connection.in);
				processed_command = true;
			}
			if (processed_command){
				man_prompt (epd,man);
			}
		}
#endif
	}
	else /* len < 0 */
	{
		printf("## %s %d %d ##\n",__func__,__LINE__,len);
		if (man_io_error (man, "recv")){
			man_reset_client_socket (man, false);
		}
	}
	printf("## %s %d %d ##\n",__func__,__LINE__,len);
	return len;
}

static int man_write (struct management *man)
{
	const int size_hint = 1024;
	int sent = 0;
	const struct buffer *buf;
	MM("## %s %d ##\n",__func__,__LINE__);
#if 0
	buffer_list_aggregate(man->connection.out, size_hint);
	buf = buffer_list_peek (man->connection.out);
	if (buf && BLEN (buf))
	{
		const int len = min_int (size_hint, BLEN (buf));
		sent = send (man->connection.sd_cli, BPTR (buf), len, MSG_NOSIGNAL);
		if (sent >= 0)
		{
			buffer_list_advance (man->connection.out, sent);
		}
		else if (sent < 0)
		{
			if (man_io_error (man, "send"))
				man_reset_client_socket (man, false);
		}
	}

	man_update_io_state (man);
#endif
	return sent;
}

static void man_connection_clear (struct man_connection *mc)
{
	//memset(mc,0x00,sizeof(struct man_connection));
	mc->state = MS_INITIAL;

	mc->sd_top = SOCKET_UNDEFINED;
	mc->sd_cli = SOCKET_UNDEFINED;
}

static void man_persist_init (struct management *man, const int log_history_cache,const int echo_buffer_size,const int state_buffer_size)
{
	struct man_persist *mp = &man->persist;
	if (!mp->defined)
	{
		memset(mp,0x00,sizeof(struct man_persist));

		mp->log = log_history_init (log_history_cache);  
#if 0
		mp->vout.func = virtual_output_callback_func;
		mp->vout.arg = man;
		mp->vout.flags_default = M_CLIENT;
		msg_set_virtual_output (&mp->vout);
#endif
		man->persist.echo = log_history_init (echo_buffer_size);
		man->persist.state = log_history_init (state_buffer_size);

		man->connection.in = malloc(sizeof(struct command_line));
		memset(man->connection.in,0x00,sizeof(struct command_line));
printf("########## %s %d %08x ##############\n",__func__,__LINE__,man->connection.in);
		mp->defined = true;
	}
}

static void man_persist_close (struct man_persist *mp)
{
	if (mp->log)
	{
		//msg_set_virtual_output (NULL);
		log_history_close (mp->log);
	}

	if (mp->echo){
		log_history_close (mp->echo);
	}

	if (mp->state){
		log_history_close (mp->state);
	}

	memset(mp,0x00,sizeof(struct man_persist));
}

static void man_settings_init (struct man_settings *ms,
		const char *addr,
		const int port,
		const char *pass_file,
		const char *client_user,
		const char *client_group,
		const int log_history_cache,
		const int echo_buffer_size,
		const int state_buffer_size,
		const char *write_peer_info_file,
		const int remap_sigusr1,
		const unsigned int flags)
{
	if (!ms->defined)
	{
		memset(ms,0x00,sizeof(struct man_settings));
		ms->flags = flags;
		ms->client_uid = -1;
		ms->client_gid = -1;

		if (pass_file != NULL){
			MM("## %s %d ##\n",__func__,__LINE__);
#if 0
			get_user_pass (&ms->up, pass_file, "Management", GET_USER_PASS_PASSWORD_ONLY);
#endif
		}

		if (client_user)
		{
			MM("## %s %d ##\n",__func__,__LINE__);
#if 0
			struct platform_state_user s;
			platform_user_get (client_user, &s);
			ms->client_uid = platform_state_user_uid (&s);
#endif
			MM("MANAGEMENT: client_uid=%d", ms->client_uid);
			assert(ms->client_uid >= 0);
		}
		if (client_group)
		{
			MM("## %s %d ##\n",__func__,__LINE__);
#if 0
			struct platform_state_group s;
			platform_group_get (client_group, &s);
			ms->client_gid = platform_state_group_gid (&s);
#endif
			MM( "MANAGEMENT: client_gid=%d", ms->client_gid);
			assert(ms->client_gid >= 0);
		}
#if 0
		ms->write_peer_info_file = string_alloc (write_peer_info_file, NULL);
#endif

#if 0
#if UNIX_SOCK_SUPPORT
		if (ms->flags & MF_UNIX_SOCK){
			sockaddr_unix_init (&ms->local_unix, addr);
		}else
#endif
		{
			ms->local_in4.sin_family = AF_INET;
			ms->local_in4.sin_addr.s_addr = 0;
			ms->local_in4.sin_port = htons (port);

			if (streq (addr, "tunnel") && !(flags & MF_CONNECT_AS_CLIENT))
			{
				ms->management_over_tunnel = true;
			}
			else
			{
				ms->local_in4.sin_addr.s_addr = getaddr (GETADDR_RESOLVE|GETADDR_WARN_ON_SIGNAL|GETADDR_FATAL, addr, 0, NULL, NULL);
			}
		}
#endif

		ms->log_history_cache = log_history_cache;
		ms->echo_buffer_size = echo_buffer_size;
		ms->state_buffer_size = state_buffer_size;
#if 0
		if (remap_sigusr1 == SIGHUP){
			ms->mansig |= MANSIG_MAP_USR1_TO_HUP;
		}else if (remap_sigusr1 == SIGTERM){
			ms->mansig |= MANSIG_MAP_USR1_TO_TERM;
		}
#endif
		ms->defined = true;
	}
}

static void man_settings_close (struct man_settings *ms)
{
	free (ms->write_peer_info_file);
	memset(ms,0x00,sizeof(struct man_settings));
}


static void man_connection_init (struct management *man)
{
	printf("################################################## %s %d ##########################\n",__func__,__LINE__);
	if (man->connection.state == MS_INITIAL)
	{
		man->connection.in = command_line_new (1024);
#if 0
		man->connection.out = buffer_list_new (0);
		{
			int maxevents = 1;
			man->connection.es = event_set_init (&maxevents, EVENT_METHOD_FAST);
		}
#endif
		if (man->settings.flags & MF_CONNECT_AS_CLIENT){
			man_connect (man);
		}else{
			man_listen (man);
		}
	}
}

static void man_connection_close (struct management *man)
{
	struct man_connection *mc = &man->connection;
#if 0
	if (mc->es){
		event_free (mc->es);
	}
	if (socket_defined (mc->sd_top))
	{
		man_close_socket (man, mc->sd_top);
		man_delete_unix_socket (man);
	}
	if (socket_defined (mc->sd_cli)){
		man_close_socket (man, mc->sd_cli);
	}
	if (mc->in){
		command_line_free (mc->in);
	}
	if (mc->out){
		buffer_list_free (mc->out);
	}
#endif
#ifdef MANAGEMENT_IN_EXTRA
	in_extra_reset (&man->connection, IER_RESET);
#endif
#ifdef MANAGMENT_EXTERNAL_KEY
	buffer_list_free (mc->ext_key_input);
#endif
	man_connection_clear (mc);
}

struct management * management_init (struct management *man)
{
	//ALLOC_OBJ_CLEAR (man, struct management);
	man = malloc(sizeof(struct management));
	memset(man,0x00,sizeof(struct management));
	man_persist_init (man,
			MANAGEMENT_LOG_HISTORY_INITIAL_SIZE,
			MANAGEMENT_ECHO_BUFFER_SIZE,
			MANAGEMENT_STATE_BUFFER_SIZE);

	man_connection_clear (&man->connection);

	return man;
}

bool management_open (struct management *man,
		const char *addr,
		const int port,
		const char *pass_file,
		const char *client_user,
		const char *client_group,
		const int log_history_cache,
		const int echo_buffer_size,
		const int state_buffer_size,
		const char *write_peer_info_file,
		const int remap_sigusr1,
		const unsigned int flags)
{
	bool ret = false;

	printf("## %s %d %08x %08x ##\n",__func__,__LINE__,man->connection.in,man);
	man_settings_init (&man->settings,
			addr,
			port,
			pass_file,
			client_user,
			client_group,
			log_history_cache,
			echo_buffer_size,
			state_buffer_size,
			write_peer_info_file,
			remap_sigusr1,
			flags);

	printf("## %s %d %08x %08x ##\n",__func__,__LINE__,man->connection.in,man);
	log_history_resize (man->persist.log, man->settings.log_history_cache);
	log_history_resize (man->persist.echo, man->settings.echo_buffer_size);
	log_history_resize (man->persist.state, man->settings.state_buffer_size);

	printf("## %s %d %08x %08x ##\n",__func__,__LINE__,man->connection.in,man);
	if (man->connection.state == MS_INITIAL)
	{
		if (!man->settings.management_over_tunnel)
		{
			//man_connection_init (man);
			ret = true;
		}
	}

	printf("## %s %d %08x %08x ##\n",__func__,__LINE__,man->connection.in,man);
	return ret;
}

void management_close (struct epoll_ptr_data *epd,struct management *man)
{
	man_output_list_push_finalize (epd,man);
	man_connection_close (man);
	man_settings_close (&man->settings);
	man_persist_close (&man->persist);
	free (man);
}

void management_set_callback (struct management *man, const struct management_callback *cb)
{
	man->persist.standalone_disabled = true;
	man->persist.callback = *cb;
}

void management_clear_callback (struct epoll_ptr_data *epd,struct management *man)
{
	man->persist.standalone_disabled = false;
	man->persist.hold_release = false;
	memset(&man->persist.callback,0x00,sizeof(struct management_callback));
	man_output_list_push_finalize (epd,man);
}

void management_set_state (struct epoll_ptr_data *epd,struct management *man, const int state,const char *detail,const in_addr_t tun_local_ip,const in_addr_t tun_remote_ip)
{
	printf("## %s %d %08x %08x ##\n",__func__,__LINE__,man->connection.in,man);
	time_t now;
	if (man->persist.state && (!(man->settings.flags & MF_SERVER) || state < OPENVPN_STATE_CLIENT_BASE))
	{
		struct log_entry e;
		const char *out = NULL;

		memset(&e,0x00,sizeof(struct log_entry));
		e.timestamp = now;
		e.u.state = state;
		e.string = detail;
		e.local_ip = tun_local_ip;
		e.remote_ip = tun_remote_ip;

		log_history_add (man->persist.state, &e);

	printf("## %s %d %08x %08x ##\n",__func__,__LINE__,man->connection.in,man);
		if (man->connection.state_realtime)
			out = log_entry_print (&e, LOG_PRINT_STATE_PREFIX
					|   LOG_PRINT_INT_DATE
					|   LOG_PRINT_STATE
					|   LOG_PRINT_LOCAL_IP
					|   LOG_PRINT_REMOTE_IP
					|   LOG_PRINT_CRLF
					|   LOG_ECHO_TO_LOG);

		if (out){
	printf("## %s %d %08x %08x ##\n",__func__,__LINE__,man->connection.in,man);
			man_output_list_push (epd,man, out);
	printf("## %s %d %08x %08x ##\n",__func__,__LINE__,man->connection.in,man);
		}

	}
}

#if 0
static bool env_filter_match (const char *env_str, const int env_filter_level)
{
	static const char *env_names[] = {
		"username=",
		"password=",
		"X509_0_CN=",
		"tls_serial_",
		"untrusted_ip=",
		"ifconfig_local=",
		"ifconfig_netmask=",
		"daemon_start_time=",
		"daemon_pid=",
		"dev=",
		"ifconfig_pool_remote_ip=",
		"ifconfig_pool_netmask=",
		"time_duration=",
		"bytes_sent=",
		"bytes_received="
	};

	if (env_filter_level == 0){
		return true;
	}else if (env_filter_level <= 1 && !strncmp(env_str, "X509_", 5)){
		return true;
	}else if (env_filter_level <= 2){
		size_t i;
		for (i = 0; i < SIZE(env_names); ++i)
		{
			const char *en = env_names[i];
			const size_t len = strlen(en);
			if (!strncmp(env_str, en, len))
				return true;
		}
		return false;
	}
	return false;
}

static void man_output_env (const struct env_set *es, const bool tail, const int env_filter_level, const char *prefix)
{
	if (es)
	{
		struct env_item *e;
		for (e = es->list; e != NULL; e = e->next)
		{
			if (e->string && (!env_filter_level || env_filter_match(e->string, env_filter_level)))
				msg (M_CLIENT, ">%s:ENV,%s", prefix, e->string);
		}
	}
	if (tail){
		msg (M_CLIENT, ">%s:ENV,END", prefix);
	}
}

static void man_output_extra_env (struct management *man, const char *prefix)
{
	struct gc_arena gc = gc_new ();
	struct env_set *es = env_set_create (&gc);
	if (man->persist.callback.n_clients)
	{
		const int nclients = (*man->persist.callback.n_clients) (man->persist.callback.arg);
		setenv_int (es, "n_clients", nclients);
	}
	man_output_env (es, false, man->connection.env_filter_level, prefix);
	gc_free (&gc);
}

void management_up_down(struct management *man, const char *updown, const struct env_set *es)
{
	if (man->settings.flags & MF_UP_DOWN)
	{
		msg (M_CLIENT, ">UPDOWN:%s", updown);
		man_output_env (es, true, 0, "UPDOWN");
	}
}
#endif

void management_notify(struct management *man, const char *severity, const char *type, const char *text)
{
	msg (man,M_CLIENT, ">NOTIFY:%s,%s,%s", severity, type, text);
}

void management_notify_generic (struct management *man, const char *str)
{
	msg (man,M_CLIENT, "%s", str);
}

#ifdef MANAGEMENT_DEF_AUTH
static bool validate_peer_info_line(const char *line)
{
	uint8_t c;
	int state = 0;
	while ((c=*line++))
	{
		switch (state)
		{
			case 0:
			case 1:
				if (c == '=' && state == 1)
					state = 2;
				else if (isalnum(c) || c == '_')
					state = 1;
				else
					return false;
			case 2:
				if (isprint(c))
					;
				else
					return false;
		}
	}
	return (state == 2);
}

static void man_output_peer_info_env (struct management *man, struct man_def_auth_context *mdac)
{
	char line[256];
	if (man->persist.callback.get_peer_info)
	{
		const char *peer_info = (*man->persist.callback.get_peer_info) (man->persist.callback.arg, mdac->cid);
		if (peer_info)
		{
#if 0
			struct buffer buf;
			buf_set_read (&buf, (const uint8_t *) peer_info, strlen(peer_info));
			while (buf_parse (&buf, '\n', line, sizeof (line)))
			{
				chomp (line);
				if (validate_peer_info_line(line))
				{
					msg (man,M_CLIENT, ">CLIENT:ENV,%s", line);
				}
				else{
					MM("validation failed on peer_info line received from client");
				}
			}
#endif
		}
	}
}

void management_notify_client_needing_auth (struct management *management, const unsigned int mda_key_id,struct man_def_auth_context *mdac,const struct env_set *es)
{
	if (!(mdac->flags & DAF_CONNECTION_CLOSED))
	{
		const char *mode = "CONNECT";
		if (mdac->flags & DAF_CONNECTION_ESTABLISHED){
			mode = "REAUTH";
		}
		msg (management,M_CLIENT, ">CLIENT:%s,%lu,%u", mode, mdac->cid, mda_key_id);
#if 0
		man_output_extra_env (management, "CLIENT");
		man_output_peer_info_env(management, mdac);
		man_output_env (es, true, management->connection.env_filter_level, "CLIENT");
#endif
		mdac->flags |= DAF_INITIAL_AUTH;
	}
}

void management_connection_established (struct management *management,struct man_def_auth_context *mdac,const struct env_set *es)
{
	mdac->flags |= DAF_CONNECTION_ESTABLISHED;
	msg (management,M_CLIENT, ">CLIENT:ESTABLISHED,%lu", mdac->cid);
#if 0
	man_output_extra_env (management, "CLIENT");
	man_output_env (es, true, management->connection.env_filter_level, "CLIENT");
#endif
}

void management_notify_client_close (struct management *management, struct man_def_auth_context *mdac,const struct env_set *es)
{
	if ((mdac->flags & DAF_INITIAL_AUTH) && !(mdac->flags & DAF_CONNECTION_CLOSED))
	{
		msg (management,M_CLIENT, ">CLIENT:DISCONNECT,%lu", mdac->cid);
#if 0
		man_output_env (es, true, management->connection.env_filter_level, "CLIENT");
#endif
		mdac->flags |= DAF_CONNECTION_CLOSED;
	}
}

void management_learn_addr (struct management *management, struct man_def_auth_context *mdac,const struct mroute_addr *addr,const bool primary)
{
	if ((mdac->flags & DAF_INITIAL_AUTH) && !(mdac->flags & DAF_CONNECTION_CLOSED))
	{
		printf("## %s %d ##\n",__func__,__LINE__);
#if 0
		msg (management,M_CLIENT, ">CLIENT:ADDRESS,%lu,%s,%d",
				mdac->cid,
				mroute_addr_print_ex (addr, MAPF_SUBNET, &gc),
				BOOL_CAST (primary));
#endif
	}
}

#endif /* MANAGEMENT_DEF_AUTH */

void management_echo (struct epoll_ptr_data *epd,struct management *man, const char *string, const bool pull)
{
	time_t now;
	if (man->persist.echo)
	{
		struct log_entry e;
		const char *out = NULL;

		memset(&e,0x00,sizeof(struct log_entry));
		e.timestamp = now;
		e.string = string;
		e.u.intval = BOOL_CAST (pull);

		log_history_add (man->persist.echo, &e);

		if (man->connection.echo_realtime){
			out = log_entry_print (&e, LOG_PRINT_INT_DATE|LOG_PRINT_ECHO_PREFIX|LOG_PRINT_CRLF|MANAGEMENT_ECHO_FLAGS);
		}

		if (out){
			man_output_list_push (epd,man, out);
		}

	}
}

void management_post_tunnel_open (struct management *man, const in_addr_t tun_local_ip)
{
	if (man->settings.management_over_tunnel
			&& man->connection.state == MS_INITIAL)
	{
		man->settings.local_in4.sin_addr.s_addr = htonl (tun_local_ip);
		//man_connection_init (man);
	}

}

void management_pre_tunnel_close (struct management *man)
{
	if (man->settings.management_over_tunnel)
		man_connection_close (man);
}

void management_auth_failure (struct management *man, const char *type, const char *reason)
{
	if (reason){
		msg (man,M_CLIENT, ">PASSWORD:Verification Failed: '%s' ['%s']", type, reason);
	}else{
		msg (man,M_CLIENT, ">PASSWORD:Verification Failed: '%s'", type);
	}
}

void management_auth_token (struct management *man, const char *token)
{
	msg (man,M_CLIENT, ">PASSWORD:Auth-Token:%s", token);  
}

static inline bool man_persist_state (unsigned int *persistent, const int n)
{
	if (persistent)
	{
		if (*persistent == (unsigned int)n)
			return false;
		*persistent = n;
	}
	return true;
}

void management_socket_set (struct management *man,struct event_set *es,void *arg,unsigned int *persistent)
{
	MM("## %s %d ##\n",__func__,__LINE__);
#if 0
	switch (man->connection.state)
	{
		case MS_LISTEN:
			if (man_persist_state (persistent, 1))
				event_ctl (es, man->connection.sd_top, EVENT_READ, arg);
			break;
		case MS_CC_WAIT_READ:
			if (man_persist_state (persistent, 2))
				event_ctl (es, man->connection.sd_cli, EVENT_READ, arg);
			break;
		case MS_CC_WAIT_WRITE:
			if (man_persist_state (persistent, 3))
				event_ctl (es, man->connection.sd_cli, EVENT_WRITE, arg);
			break;
		case MS_INITIAL:
			break;
		default:
			ASSERT (0);
	}
#endif
}

void management_io (struct epoll_data_ptr *epd,struct management *man)
{
	switch (man->connection.state)
	{
		case MS_LISTEN:
			man_accept (man);
			break;
		case MS_CC_WAIT_READ:
			man_read (epd,man);
			break;
		case MS_CC_WAIT_WRITE:
			man_write (man);
			break;
		case MS_INITIAL:
			break;
		default:
			assert(0);
	}
}

static inline bool man_standalone_ok (const struct management *man)
{
	return !man->settings.management_over_tunnel && man->connection.state != MS_INITIAL;
}

static bool man_check_for_signals (volatile int *signal_received)
{
	MM("## %s %d ##\n",__func__,__LINE__);
#if 0
	if (signal_received)
	{
		get_signal (signal_received);
		if (*signal_received){
			return true;
		}
	}
#endif
	return false;
}

static int man_block (struct management *man, volatile int *signal_received, const time_t expire)
{
	int status = -1;
	MM("## %s %d ##\n",__func__,__LINE__);
#if 0
	struct timeval tv;
	struct event_set_return esr;
	time_t now;
	if (man_standalone_ok (man))
	{
		while (true)
		{
			event_reset (man->connection.es);
			management_socket_set (man, man->connection.es, NULL, NULL);
			tv.tv_usec = 0;
			tv.tv_sec = 1;
			if (man_check_for_signals (signal_received))
			{
				status = -1;
				break;
			}
			status = event_wait (man->connection.es, &tv, &esr, 1);
			update_time ();
			if (man_check_for_signals (signal_received))
			{
				status = -1;
				break;
			}

			if (status > 0){
				break;
			}
			else if (expire && now >= expire)
			{
				status = 0;
				if (signal_received){
					*signal_received = SIGINT;
				}
				break;
			}
		}
	}
#endif
	return status;
}

void man_output_standalone (struct epoll_ptr_data *epd,struct management *man, volatile int *signal_received)
{
	if (man_standalone_ok (man))
	{
		while (man->connection.state == MS_CC_WAIT_WRITE)
		{
			management_io (epd,man);
			if (man->connection.state == MS_CC_WAIT_WRITE){
				man_block (man, signal_received, 0);
			}
			if (signal_received && *signal_received){
				break;
			}
		}
	}
}

int man_standalone_event_loop (struct epoll_ptr_data *epd,struct management *man, volatile int *signal_received, const time_t expire)
{
	int status = -1;
	if (man_standalone_ok (man))
	{
		status = man_block (man, signal_received, expire);
		if (status > 0){
			management_io (epd,man);
		}
	}
	return status;
}


void man_wait_for_client_connection (struct epoll_ptr_data *epd,struct management *man, volatile int *signal_received,const time_t expire,unsigned int flags)
{
	assert(man_standalone_ok (man));
	if (man->connection.state == MS_LISTEN)
	{
		if (flags & MWCC_PASSWORD_WAIT){
			MM("Need password(s) from management interface, waiting...\n");
		}
		if (flags & MWCC_HOLD_WAIT){
			MM("Need hold release from management interface, waiting...\n");
		}
		if (flags & MWCC_OTHER_WAIT){
			MM("Need information from management interface, waiting...\n");
		}
		do {
			man_standalone_event_loop (epd,man, signal_received, expire);
			if (signal_received && *signal_received){
				break;
			}
		} while (man->connection.state == MS_LISTEN || man_password_needed (man));
	}
}

void management_event_loop_n_seconds (struct management *man, int sec)
{
	MM("## %s %d ##\n",__func__,__LINE__);
#if 0
	if (man_standalone_ok (man))
	{
		volatile int signal_received = 0;
		const bool standalone_disabled_save = man->persist.standalone_disabled;
		time_t expire = 0;

		man->persist.standalone_disabled = false;

		update_time ();
		if (sec){
			expire = now + sec;
		}

		man_wait_for_client_connection (man, &signal_received, expire, 0);
		if (signal_received){
			return;
		}

		do
		{
			man_standalone_event_loop (man, &signal_received, expire);
			if (!signal_received){
				man_check_for_signals (&signal_received);
			}
			if (signal_received){
				return;
			}
		} while (expire);

		man->persist.standalone_disabled = standalone_disabled_save;
	}
	else
	{
		sleep (sec);
	}
#endif
}

bool management_query_user_pass (struct management *man, struct user_pass *up,const char *type,const unsigned int flags,const char *static_challenge)
{
	bool ret = false;
	MM("## %s %d ##\n",__func__,__LINE__);
#if 0
	if (man_standalone_ok (man))
	{
		volatile int signal_received = 0;
		const bool standalone_disabled_save = man->persist.standalone_disabled;
		struct buffer alert_msg = alloc_buf_gc (128, &gc);
		const char *alert_type = NULL;
		const char *prefix = NULL;
		unsigned int up_query_mode = 0;
#ifdef ENABLE_CLIENT_CR
		const char *sc = NULL;
#endif
		ret = true;
		man->persist.standalone_disabled = false; /* This is so M_CLIENT messages will be correctly passed through msg() */
		man->persist.special_state_msg = NULL;

		CLEAR (man->connection.up_query);

		if (flags & GET_USER_PASS_NEED_OK)
		{
			up_query_mode = UP_QUERY_NEED_OK;
			prefix= "NEED-OK";
			alert_type = "confirmation";
		}
		else if (flags & GET_USER_PASS_NEED_STR)
		{
			up_query_mode = UP_QUERY_NEED_STR;
			prefix= "NEED-STR";
			alert_type = "string";
		}
		else if (flags & GET_USER_PASS_PASSWORD_ONLY)
		{
			up_query_mode = UP_QUERY_PASS;
			prefix = "PASSWORD";
			alert_type = "password";
		}
		else
		{
			up_query_mode = UP_QUERY_USER_PASS;
			prefix = "PASSWORD";
			alert_type = "username/password";
#ifdef ENABLE_CLIENT_CR
			if (static_challenge)
				sc = static_challenge;
#endif
		}
		buf_printf (&alert_msg, ">%s:Need '%s' %s",
				prefix,
				type,
				alert_type);

		if (flags & (GET_USER_PASS_NEED_OK | GET_USER_PASS_NEED_STR))
			buf_printf (&alert_msg, " MSG:%s", up->username);

#ifdef ENABLE_CLIENT_CR
		if (sc)
			buf_printf (&alert_msg, " SC:%d,%s",
					BOOL_CAST(flags & GET_USER_PASS_STATIC_CHALLENGE_ECHO),
					sc);
#endif

		man_wait_for_client_connection (man, &signal_received, 0, MWCC_PASSWORD_WAIT);
		if (signal_received)
			ret = false;

		if (ret)
		{
			man->persist.special_state_msg = BSTR (&alert_msg);
			msg (M_CLIENT, "%s", man->persist.special_state_msg);

			/* tell command line parser which info we need */
			man->connection.up_query_mode = up_query_mode;
			man->connection.up_query_type = type;

			/* run command processing event loop until we get our username/password/response */
			do
			{
				man_standalone_event_loop (man, &signal_received, 0);
				if (!signal_received)
					man_check_for_signals (&signal_received);
				if (signal_received)
				{
					ret = false;
					break;
				}
			} while (!man->connection.up_query.defined);
		}

		/* revert state */
		man->connection.up_query_mode = UP_QUERY_DISABLED;
		man->connection.up_query_type = NULL;
		man->persist.standalone_disabled = standalone_disabled_save;
		man->persist.special_state_msg = NULL;

		/* pass through blank passwords */
		if (!strcmp (man->connection.up_query.password, blank_up))
			CLEAR (man->connection.up_query.password);

		/*
		 * Transfer u/p to return object, zero any record
		 * we hold in the management object.
		 */
		if (ret)
		{
			man->connection.up_query.nocache = up->nocache; /* preserve caller's nocache setting */
			*up = man->connection.up_query;
		}
		CLEAR (man->connection.up_query);
	}
#endif
	return ret;
}

#ifdef MANAGMENT_EXTERNAL_KEY

char * management_query_rsa_sig (struct management *man, const char *b64_data)
{
	MM("## %s %d ##\n",__func__,__LINE__);
#if 0
	char *ret = NULL;
	volatile int signal_received = 0;
	struct buffer alert_msg = clear_buf();
	struct buffer *buf;
	const bool standalone_disabled_save = man->persist.standalone_disabled;
	struct man_connection *mc = &man->connection;

	if (man_standalone_ok (man))
	{
		man->persist.standalone_disabled = false;
		man->persist.special_state_msg = NULL;

		mc->ext_key_state = EKS_SOLICIT;

		alert_msg = alloc_buf_gc (strlen(b64_data)+64, &gc);
		buf_printf (&alert_msg, ">RSA_SIGN:%s", b64_data);

		man_wait_for_client_connection (man, &signal_received, 0, MWCC_OTHER_WAIT);

		if (signal_received)
			goto done;

		man->persist.special_state_msg = BSTR (&alert_msg);
		msg (M_CLIENT, "%s", man->persist.special_state_msg);

		do
		{
			man_standalone_event_loop (man, &signal_received, 0);
			if (!signal_received)
				man_check_for_signals (&signal_received);
			if (signal_received)
				goto done;
		} while (mc->ext_key_state != EKS_READY);

		if (buffer_list_defined(mc->ext_key_input))
		{
			buffer_list_aggregate (mc->ext_key_input, 2048);
			buf = buffer_list_peek (mc->ext_key_input);
			if (buf && BLEN(buf) > 0)
			{
				ret = (char *) malloc(BLEN(buf)+1);
				check_malloc_return(ret);
				memcpy(ret, buf->data, BLEN(buf));
				ret[BLEN(buf)] = '\0';
			}
		}
	}

done:
	if (mc->ext_key_state == EKS_READY && ret){
		msg (M_CLIENT, "SUCCESS: rsa-sig command succeeded");
	}else if (mc->ext_key_state == EKS_INPUT || mc->ext_key_state == EKS_READY){
		msg (M_CLIENT, "ERROR: rsa-sig command failed");
	}

	man->persist.standalone_disabled = standalone_disabled_save;
	man->persist.special_state_msg = NULL;
	in_extra_reset (mc, IER_RESET);
	mc->ext_key_state = EKS_UNDEF;
	buffer_list_free (mc->ext_key_input);
	mc->ext_key_input = NULL;
#endif
	return ret;
}

#endif

bool management_would_hold (struct management *man)
{
	return (man->settings.flags & MF_HOLD) && !man->persist.hold_release && man_standalone_ok (man);
}

bool management_should_daemonize (struct management *man)
{
	return management_would_hold (man) || (man->settings.flags & MF_QUERY_PASSWORDS);
}

bool management_hold (struct epoll_ptr_data *epd,struct management *man)
{
	if (management_would_hold (man))
	{
		volatile int signal_received = 0;
		const bool standalone_disabled_save = man->persist.standalone_disabled;

		man->persist.standalone_disabled = false;
		man->persist.special_state_msg = NULL;
		man->settings.mansig |= MANSIG_IGNORE_USR1_HUP;

		man_wait_for_client_connection (epd,man, &signal_received, 0, MWCC_HOLD_WAIT);

		if (!signal_received)
		{
			man->persist.special_state_msg = ">HOLD:Waiting for hold release";
			msg (man,M_CLIENT, "%s", man->persist.special_state_msg);

			do
			{
				man_standalone_event_loop (epd,man, &signal_received, 0);
				if (!signal_received){
					man_check_for_signals (&signal_received);
				}
				if (signal_received){
					break;
				}
			} while (!man->persist.hold_release);
		}

		man->persist.standalone_disabled = standalone_disabled_save;
		man->persist.special_state_msg = NULL;
		man->settings.mansig &= ~MANSIG_IGNORE_USR1_HUP;

		return true;
	}
	return false;
}

struct command_line * command_line_new (const int buf_len)
{
	struct command_line *cl;
	MM("## %s %d ##\n",__func__,__LINE__);
#if 0
	ALLOC_OBJ_CLEAR (cl, struct command_line);
	cl->buf = alloc_buf (buf_len);
	cl->residual = alloc_buf (buf_len);
#endif
	return cl;
}

void command_line_reset (struct command_line *cl)
{
	MM("## %s %d ##\n",__func__,__LINE__);
#if 0
	buf_clear (&cl->buf);
	buf_clear (&cl->residual);
#endif
}

void command_line_free (struct command_line *cl)
{
	command_line_reset (cl);
	MM("## %s %d ##\n",__func__,__LINE__);
#if 0
	free_buf (&cl->buf);
	free_buf (&cl->residual);
	free (cl);
#endif
}

void command_line_add (struct command_line *cl, const unsigned char *buf, const int len)
{
	int i;
	memset(cl->buf,0x00,4096);
	for (i = 0; i < len; i++)
	{
		if (buf[i] && (char_class(buf[i], CC_PRINT) || char_class(buf[i], CC_NEWLINE)))
		{
#if 0
			printf("## %s %d ##\n",__func__,__LINE__);
			printf("|%c|%02x|",buf[i],buf[i]);
#endif
			memcpy(cl->buf+i,buf+i,1);
		}
	}
}

const unsigned char * command_line_get (struct command_line *cl)
{
	int i;
	const unsigned char *ret = NULL;

	MM("## %s %d ##\n",__func__,__LINE__);

#if 0
	i = buf_substring_len (&cl->buf, '\n');
	if (i >= 0)
	{
		buf_copy_excess (&cl->residual, &cl->buf, i);
		buf_chomp (&cl->buf);
		ret = (const unsigned char *) BSTR (&cl->buf);
	}
#endif
	return ret;
}

void command_line_next (struct command_line *cl)
{
#if 0
	buf_clear (&cl->buf);
	buf_copy (&cl->buf, &cl->residual);
	buf_clear (&cl->residual);
#endif
	memset(cl->buf,0x00,sizeof(cl->buf));
	sprintf(cl->buf,"%s",cl->residual);
	memset(cl->residual,0x00,sizeof(cl->residual));
}

const char * log_entry_print (const struct log_entry *e, unsigned int flags)
{
	char str_tmp[32]={0,};
	char *out = malloc(ERR_BUF_SIZE);
	int sht = 0;
	memset(out,0x00,ERR_BUF_SIZE);

	if (flags & LOG_FATAL_NOTIFY){
		sht += sprintf(out+sht,">FATAL:");
	}
	if (flags & LOG_PRINT_LOG_PREFIX){
		sht += sprintf(out+sht,">LOG:");
	}
	if (flags & LOG_PRINT_ECHO_PREFIX){
		sht += sprintf(out+sht,">ECHO:");
	}
	if (flags & LOG_PRINT_STATE_PREFIX){
		sht += sprintf(out+sht,">STATE:");
	}
	if (flags & LOG_PRINT_INT_DATE){
		sht += sprintf(out+sht,"%u",(unsigned int)e->timestamp);
	}
	if (flags & LOG_PRINT_MSG_FLAGS){
		sht += sprintf(out+sht,"%s,",msg_flags_string (e->u.msg_flags));
	}
	if (flags & LOG_PRINT_STATE){
		sht += sprintf(out+sht,"%s,",man_state_name (e->u.state));
	}
	if (flags & LOG_PRINT_INTVAL){
		sht += sprintf(out+sht,"%d,",e->u.intval);
	}
	if (e->string != NULL){
		sht += sprintf(out+sht,"%s,",e->string);
	}
	if (flags & LOG_PRINT_LOCAL_IP){
		sht += sprintf(out+sht,"%s,",print_in_addr_t(e->local_ip, IA_EMPTY_IF_UNDEF,str_tmp));
	}
	if (flags & LOG_PRINT_REMOTE_IP){
		sht += sprintf(out+sht,"%s,",print_in_addr_t(e->remote_ip, IA_EMPTY_IF_UNDEF,str_tmp));
	}
	if (flags & LOG_ECHO_TO_LOG){
		MM("MANAGEMENT: %s", out);
	}
	if (flags & LOG_PRINT_CRLF){
		sht += sprintf(out+sht,"\r\n");
	}
	return out;
}

static void log_entry_free_contents (struct log_entry *e)
{
	if (e->string != NULL){
		free ((char *)e->string);
	}
	memset(e,0x00,sizeof(struct log_entry));
	//CLEAR (*e);
}

static inline int log_index (const struct log_history *h, int i)
{
	return modulo_add (h->base, i, h->capacity);
}

static void log_history_obj_init (struct log_history *h, int capacity)
{
	//CLEAR (*h);
	memset(h,0x00,sizeof(struct log_history));
	h->capacity = capacity;
	h->array = calloc(capacity,sizeof(struct log_entry));


	//ALLOC_ARRAY_CLEAR (h->array, struct log_entry, capacity);
}

struct log_histrory * log_history_init (const int capacity)
{
	struct log_history *h;
	assert (capacity > 0);
	h = malloc(sizeof(struct log_history));
	memset(h,0x00,sizeof(struct log_history));
	//ALLOC_OBJ (h, struct log_history);
	log_history_obj_init (h, capacity);
	return (char *)h;
}

static void log_history_free_contents (struct log_history *h)
{
	int i;
	for (i = 0; i < h->size; ++i){
		log_entry_free_contents (&h->array[log_index(h, i)]);
	}
	free (h->array);
}

void log_history_close (struct log_history *h)
{
	log_history_free_contents (h);
	free (h);
}

void log_history_add (struct log_history *h, const struct log_entry *le)
{
	struct log_entry *e;
	assert (h->size >= 0 && h->size <= h->capacity);
	if (h->size == h->capacity)
	{
		e = &h->array[h->base];
		log_entry_free_contents(e);
		h->base = log_index (h, 1);
	}
	else
	{
		e = &h->array[log_index(h, h->size)];
		++h->size;
	}

	if(le != NULL){
		*e = *le;
		if(le->string != NULL && strlen(le->string) > 0){
			e->string = malloc(strlen(le->string));
			snprintf((char*)e->string,strlen(le->string),"%s",le->string);
		}
	}
}

void log_history_resize (struct log_history *h, const int capacity)
{
	if (capacity != h->capacity)
	{
		struct log_history newlog;
		int i;

		assert(capacity > 0);
		log_history_obj_init (&newlog, capacity);

		for (i = 0; i < h->size; ++i){
			log_history_add (&newlog, &h->array[log_index(h, i)]);
		}

		log_history_free_contents (h);
		*h = newlog;
	}
}

const struct log_entry * log_history_ref (const struct log_history *h, const int index)
{
	if (index >= 0 && index < h->size){
		return &h->array[log_index(h, (h->size - 1) - index)];
	}else{
		return NULL;
	}
}

#else
static void dummy(void) {}
#endif /* ENABLE_MANAGEMENT */

