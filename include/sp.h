#define AF_SP           38
#define PF_SP           AF_SP

#define SOCK_PUB        11
#define SOCK_SUB        12
#define SOCK_REQ        13
#define SOCK_REP        14
#define SOCK_PUSH       15
#define SOCK_PULL       16

#define SP_ENDPOINT_MAX   108

struct sockaddr_sp {
	sa_family_t ssp_family;
	char ssp_endpoint[SP_ENDPOINT_MAX];
};
