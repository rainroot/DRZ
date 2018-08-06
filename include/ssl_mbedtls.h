

#ifdef MBEDTLS_CONF
#include <mbedtls/net.h>
#include <mbedtls/ssl.h>
#include <mbedtls/dhm.h>
#include <mbedtls/x509.h>
#include <mbedtls/x509_crt.h>

//#include <mbedtls/threading.h>


#if defined(ENABLE_PKCS11)
#include <mbedtls/pkcs11.h>
#endif

#include <mbedtls/havege.h>

#include <mbedtls/debug.h>
#include <mbedtls/error.h>
#include <mbedtls/oid.h>
#include <mbedtls/pem.h>
#include <mbedtls/sha256.h>
#include <mbedtls/version.h>


typedef struct _buffer_entry buffer_entry;

struct _buffer_entry {
	size_t length;
	uint8_t *data;
	buffer_entry *next_block;
};

typedef struct {
	size_t data_start;
	buffer_entry *first_block;
	buffer_entry *last_block;
} endless_buffer;

typedef struct {
	endless_buffer in;
	endless_buffer out;
} bio_ctx;

struct tls_root_ctx {
	bool initialised;
	int endpoint;
	mbedtls_dhm_context *dhm_ctx;
	mbedtls_x509_crt *crt_chain;
	mbedtls_x509_crt *ca_chain;
	mbedtls_pk_context *priv_key;
	mbedtls_x509_crl *crl;
#if defined(ENABLE_PKCS11)
	pkcs11_context *priv_key_pkcs11;
#endif
#ifdef MANAGMENT_EXTERNAL_KEY
	struct external_context *external_key;
#endif
	int * allowed_ciphers;
};

struct key_state_ssl {
	mbedtls_ssl_config ssl_config;
	mbedtls_ssl_context *ctx;
	bio_ctx bio_ctx;
};


# define SSLF_CLIENT_CERT_NOT_REQUIRED (1<<0)
# define SSLF_USERNAME_AS_COMMON_NAME  (1<<1)
# define SSLF_AUTH_USER_PASS_OPTIONAL  (1<<2)
# define SSLF_OPT_VERIFY               (1<<4)
# define SSLF_CRL_VERIFY_DIR           (1<<5)
# define SSLF_TLS_VERSION_MIN_SHIFT    6
# define SSLF_TLS_VERSION_MIN_MASK     0xF
# define SSLF_TLS_VERSION_MAX_SHIFT    10
# define SSLF_TLS_VERSION_MAX_MASK     0xF

void tls_init_lib(void);
void tls_ctx_server_new(struct tls_root_ctx *ctx, unsigned int ssl_flags);
void tls_ctx_load_dh_params (struct tls_root_ctx *ctx, const char *dh_file, const char *dh_inline);
void tls_ctx_client_new(struct tls_root_ctx *ctx, unsigned int ssl_flags);
void tls_ctx_set_options (struct tls_root_ctx *ctx, unsigned int ssl_flags);
void tls_ctx_load_cert_file (struct tls_root_ctx *ctx, const char *cert_file, const char *cert_inline);
int tls_ctx_load_priv_file (struct tls_root_ctx *ctx, const char *priv_key_file, const char *priv_key_inline);
void tls_ctx_load_ca (struct tls_root_ctx *ctx, const char *ca_file,const char *ca_inline, const char *ca_path, bool tls_server);
void key_state_ssl_remove(struct epoll_ptr_data *epd,bool all);
void key_state_ssl_init(struct epoll_ptr_data *epd,struct key_state_ssl *ks_ssl, const struct tls_root_ctx *ssl_ctx, int is_server);
int tls_version_max(void);
int key_state_write_ciphertext (struct key_state_ssl *ks, char *buf,int len);
int key_state_read_plaintext (struct key_state_ssl *ks, char *buf,int len, int maxlen);
int key_state_write_plaintext_const (struct key_state_ssl *ks, char *data, int len);
int key_state_write_plaintext (struct key_state_ssl *ks, char *buf,int len);
int key_state_read_ciphertext (struct key_state_ssl *ks, char *buf, int len ,int maxlen);
void key_state_ssl_free(struct key_state_ssl *ks_ssl,bool all);
void tls_clear_error();
const char * get_ssl_library_version(void);





#endif

