typedef X509 openvpn_x509_cert_t;





#define COMPAT_FLAG_QUERY         0
#define COMPAT_FLAG_SET           (1<<0)
#define COMPAT_NAMES              (1<<1)
#define COMPAT_NO_NAME_REMAPPING  (1<<2)





int verify_callback (int preverify_ok, X509_STORE_CTX * ctx);
unsigned char * x509_get_sha1_hash (X509 *cert);
char * x509_get_subject (X509 *cert);
bool x509_get_username (char *common_name, int cn_len, char * x509_username_field, X509 *peer_cert);
unsigned char * x509_get_sha256_fingerprint(X509 *cert);
#if 0
unsigned char * x509_get_sha1_hash (X509 *cert, struct gc_arena *gc);
char * x509_get_subject (X509 *cert, struct gc_arena *gc);
result_t x509_verify_ns_cert_type(const openvpn_x509_cert_t *peer_cert, const int usage);
result_t x509_verify_cert_ku (X509 *x509, const unsigned * const expected_ku, int expected_len);
result_t x509_verify_cert_eku (X509 *x509, const char * const expected_oid);
void x509_setenv (struct env_set *es, int cert_depth, openvpn_x509_cert_t *peer_cert);
char * backend_x509_get_serial (openvpn_x509_cert_t *cert, struct gc_arena *gc);
char * backend_x509_get_serial_hex (openvpn_x509_cert_t *cert, struct gc_arena *gc);
result_t x509_write_pem(FILE *peercert_file, X509 *peercert);
result_t x509_get_username (char *common_name, int cn_len, char * x509_username_field, X509 *peer_cert);
result_t x509_verify_crl(const char *crl_file, X509 *peer_cert, const char *subject);
#endif



