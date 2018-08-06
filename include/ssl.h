#define KEY_EXPANSION_ID "OpenVPN"


#define SID_SIZE 8

#define P_CONTROL_HARD_RESET_CLIENT_V1 1
#define P_CONTROL_HARD_RESET_SERVER_V1 2
#define P_CONTROL_SOFT_RESET_V1        3
#define P_CONTROL_V1                   4
#define P_ACK_V1                       5
#define P_DATA_V1                      6
#define P_CONTROL_HARD_RESET_CLIENT_V2 7
#define P_CONTROL_HARD_RESET_SERVER_V2 8


#define P_KEY_ID_MASK                  0x07
#define P_OPCODE_SHIFT                 3

#define X509_USERNAME_FIELD_DEFAULT "CN"

#define S_ERROR          -1
#define S_UNDEF           0
#define S_INITIAL         1
#define S_PRE_START       2
#define S_START           3
#define S_SENT_KEY        4
#define S_GOT_KEY         5
#define S_ACTIVE          6
#define S_NORMAL_OP       7

#define SSL_REQUEST 1


#define UP_TYPE_AUTH        "Auth"
#define UP_TYPE_PRIVATE_KEY "Private Key"


#define TM_ACTIVE    0
#define TM_UNTRUSTED 1
#define TM_LAME_DUCK 2
#define TM_SIZE      3

#define KS_PRIMARY    0
#define KS_LAME_DUCK  1
#define KS_SIZE       2
#define KEY_SCAN_SIZE 3

#define SSLF_CLIENT_CERT_NOT_REQUIRED (1<<0)
#define SSLF_USERNAME_AS_COMMON_NAME  (1<<1)
#define SSLF_AUTH_USER_PASS_OPTIONAL  (1<<2)
#define SSLF_OPT_VERIFY               (1<<4)
#define SSLF_CRL_VERIFY_DIR           (1<<5)
#define SSLF_TLS_VERSION_SHIFT        6
#define SSLF_TLS_VERSION_MASK         0xF

#define TLS_VER_BAD    -1
#define TLS_VER_UNSPEC  0
#define TLS_VER_1_0     1
#define TLS_VER_1_1     2
#define TLS_VER_1_2     3
#define INLINE_FILE_TAG "[[INLINE]]"

#define VERIFY_X509_NONE                0
#define VERIFY_X509_SUBJECT_DN          1
#define VERIFY_X509_SUBJECT_RDN         2
#define VERIFY_X509_SUBJECT_RDN_PREFIX  3
#define TLS_REMOTE_SUBJECT_DN           1 + 0x100
#define TLS_REMOTE_SUBJECT_RDN_PREFIX   3 + 0x100

#define TLS_AUTHENTICATION_SUCCEEDED  0
#define TLS_AUTHENTICATION_FAILED     1
#define TLS_AUTHENTICATION_DEFERRED   2
#define TLS_AUTHENTICATION_UNDEFINED  3

#define MAX_CERT_DEPTH 16

#define DECRYPT_KEY_ENABLED(multi, ks) ((ks)->state >= (S_GOT_KEY - (multi)->opt.server))

#define NS_CERT_CHECK_NONE (0)
#define NS_CERT_CHECK_SERVER (1<<0)
#define NS_CERT_CHECK_CLIENT (1<<1)

#define KEY_METHOD_MIN 1
#define KEY_METHOD_MAX 2
#define KEY_METHOD_MASK 0x0F

#define TLS_OPTIONS_LEN 512

#define TLS_CHANNEL_BUF_SIZE 2048

typedef enum { SUCCESS=0, FAILURE=1 } result_t;

struct key_source {
	uint8_t pre_master[48];
	uint8_t random1[32];
	uint8_t random2[32];
}key_source_t;

struct key_source2 {
	struct key_source client;
	struct key_source server;
}key_source2_t;

struct user_pass
{
	bool defined;
	bool nocache;
#ifdef ENABLE_PKCS11
#   define USER_PASS_LEN 4096
#else
#   define USER_PASS_LEN 128
#endif
	char username[USER_PASS_LEN];
	char password[USER_PASS_LEN];
};


int ssl_handle(struct epoll_ptr_data *epd,char *data,int len,char *out);
int pem_password_callback (char *buf, int size, int rwflag, void *u);
bool key_method_2_read (struct epoll_ptr_data *epd);
bool key_method_2_write (struct epoll_ptr_data *epd);
void set_auth_token (struct user_pass *up, const char *token);
int tls_version_min_parse(const char *vstr, const char *extra);
void ssl_set_auth_nocache (void);
void ssl_set_auth_token (const char *token);
void strncpynt (char *dest, const char *src, size_t maxlen);
