#define MAX_CERT_DEPTH 16

#define TLS_USERNAME_LEN 64
#define X509_NAME_CHAR_CLASS   (CC_ALNUM|CC_UNDERBAR|CC_DASH|CC_DOT|CC_AT|CC_SLASH|CC_COLON|CC_EQUAL)
#define COMMON_NAME_CHAR_CLASS (CC_ALNUM|CC_UNDERBAR|CC_DASH|CC_DOT|CC_AT|CC_SLASH)


struct cert_hash {
	unsigned char sha1_hash[SHA_DIGEST_LENGTH];
};

struct cert_hash_set {
	struct cert_hash *ch[MAX_CERT_DEPTH];
};


void cert_hash_remember (struct epoll_ptr_data *epd,int error_depth,unsigned char *sha1_hash);
result_t verify_cert(struct epoll_ptr_data *epd, openvpn_x509_cert_t *cert, int cert_depth);
