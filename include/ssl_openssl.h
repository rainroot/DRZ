#include <openssl/ssl.h>
#include <openssl/err.h>

#include <openssl/err.h>
#include <openssl/pkcs12.h>
#include <openssl/x509.h>
#include <openssl/crypto.h>


struct tls_root_ctx {
        SSL_CTX *ctx;
}tls_root_ctx_t;

struct key_state_ssl {
        SSL *ssl;
        BIO *ssl_bio;
        BIO *ct_in;
        BIO *ct_out;
}key_state_ssl_t;

void tls_ctx_server_new(struct tls_root_ctx *ctx, unsigned int ssl_flags);
void tls_ctx_load_dh_params (struct tls_root_ctx *ctx, const char *dh_file, const char *dh_file_inline);
void tls_ctx_client_new(struct tls_root_ctx *ctx, unsigned int ssl_flags);
void tls_ctx_set_options (struct tls_root_ctx *ctx, unsigned int ssl_flags);
int tls_ctx_load_pkcs12(struct tls_root_ctx *ctx, char *pkcs12_file,char *pkcs12_file_inline,bool load_ca_file);
void tls_ctx_load_cert_file (struct tls_root_ctx *ctx, const char *cert_file,const char *cert_file_inline);
int tls_ctx_load_priv_file (struct tls_root_ctx *ctx, const char *priv_key_file,const char *priv_key_file_inline);
void tls_ctx_load_ca (struct tls_root_ctx *ctx, const char *ca_file,const char *ca_file_inline,const char *ca_path, bool tls_server);
void tls_ctx_load_extra_certs (struct tls_root_ctx *ctx, const char *extra_certs_file,const char *extra_certs_file_inline);
void tls_ctx_restrict_ciphers(struct tls_root_ctx *ctx, const char *ciphers);
void tls_clear_error();
int tls_init_lib(void);
void tls_free_lib(void);

void key_state_ssl_remote(struct epoll_ptr_data *epd,bool all);
void key_state_ssl_free(struct key_state_ssl *ks_ssl,bool all);
int key_state_write_ciphertext (struct key_state_ssl *ks_ssl, char *buf,int size);

int key_state_read_plaintext (struct key_state_ssl *ks_ssl, char *buf,int size, int maxlen);
int key_state_write_ciphertext (struct key_state_ssl *ks_ssl, char *buf,int size);
int key_state_read_ciphertext (struct key_state_ssl *ks_ssl, char *buf, int size ,int maxlen);
int key_state_write_plaintext_const (struct key_state_ssl *ks_ssl, char *data, int len);
int key_state_write_plaintext (struct key_state_ssl *ks_ssl, char *buf,int size);
void key_state_ssl_remove(struct epoll_ptr_data *epd,bool all);

int tls_version_max(void);
const char * get_ssl_library_version(void);
void key_state_ssl_init(struct epoll_ptr_data *epd,struct key_state_ssl *ks_ssl, const struct tls_root_ctx *ssl_ctx, int mode);
