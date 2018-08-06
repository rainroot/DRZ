
#define KEY_DIRECTION_BIDIRECTIONAL 0
#define KEY_DIRECTION_NORMAL        1
#define KEY_DIRECTION_INVERSE       2

struct epoll_ptr_data;

struct key_ctx
{
#if 1
	cipher_ctx_t *cipher[128];
	hmac_ctx_t *hmac[128];
#else
	cipher_ctx_t *cipher;
	hmac_ctx_t *hmac;
	pthread_mutex_t kc_mutex;
#endif
}key_ctx_t;

struct key_type
{
	uint8_t cipher_length;
	uint8_t hmac_length;
	const cipher_kt_t *cipher;
	const md_kt_t *digest;
}key_type_t;


struct key
{
	char cipher[MAX_CIPHER_KEY_LENGTH];
	char hmac[MAX_HMAC_KEY_LENGTH];
};

struct key2
{
	int n;
	struct key keys[2];
}key2_t;


struct key_ctx_bi
{
	struct key_ctx encrypt;
	struct key_ctx decrypt;
};

#if 0
struct crypto_options
{
	struct key_ctx_bi *key_ctx_bi;
#define CO_PACKET_ID_LONG_FORM  (1<<0)
#define CO_USE_IV               (1<<1)
#define CO_IGNORE_PACKET_ID     (1<<2)
#define CO_MUTE_REPLAY_WARNINGS (1<<3)
	unsigned int flags;
}crypto_options_t;
#endif

void init_key_ctx (struct key_ctx *ctx, struct key *key,const struct key_type *kt, int enc,const char *prefix,int idx);
bool key_is_zero (struct key *key, const struct key_type *kt);
bool check_key (struct key *key, const struct key_type *kt);
void fixup_key (struct key *key, const struct key_type *kt);
int data_decrypt(struct epoll_ptr_data *epd,char *buf,int buf_size,char *out,int keyid,int idx);
int data_encrypt(struct epoll_ptr_data *epd,char *buf,int buf_size,char *out,int keyid,int idx);
void init_key_type (struct key_type *kt, const char *ciphername, const char *authname,int keysize,bool cfb_ofb_allowed);
void free_key_ctx (struct key_ctx *ctx,int idx);
char * keydirection2ascii (int kd, bool remote);
