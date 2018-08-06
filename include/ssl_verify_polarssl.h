#include <polarssl/x509_crt.h>

#include <polarssl/bignum.h>
#include <polarssl/error.h>
#include <polarssl/oid.h>
#include <polarssl/sha1.h>

#define MAX_SUBJECT_LENGTH 256

typedef x509_crt openvpn_x509_cert_t;
#define COMPAT_FLAG_QUERY         0
#define COMPAT_FLAG_SET           (1<<0)
#define COMPAT_NAMES              (1<<1)
#define COMPAT_NO_NAME_REMAPPING  (1<<2)

int verify_callback (void *session_obj, x509_crt *cert, int cert_depth,int *flags);
unsigned char * x509_get_sha1_hash (x509_crt *cert);
char * x509_get_subject(x509_crt *cert);
bool x509_get_username (char *cn, int cn_len,char *x509_username_field, x509_crt *cert);
