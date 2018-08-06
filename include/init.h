
#define CC_ANY                (1<<0)
#define CC_NULL               (1<<1)

#define CC_ALNUM              (1<<2)
#define CC_ALPHA              (1<<3)
#define CC_ASCII              (1<<4)
#define CC_CNTRL              (1<<5)
#define CC_DIGIT              (1<<6)
#define CC_PRINT              (1<<7)
#define CC_PUNCT              (1<<8)
#define CC_SPACE              (1<<9)
#define CC_XDIGIT             (1<<10)

#define CC_BLANK              (1<<11)
#define CC_NEWLINE            (1<<12)
#define CC_CR                 (1<<13)

#define CC_BACKSLASH          (1<<14)
#define CC_UNDERBAR           (1<<15)
#define CC_DASH               (1<<16)
#define CC_DOT                (1<<17)
#define CC_COMMA              (1<<18)
#define CC_COLON              (1<<19)
#define CC_SLASH              (1<<20)
#define CC_SINGLE_QUOTE       (1<<21)
#define CC_DOUBLE_QUOTE       (1<<22)
#define CC_REVERSE_QUOTE      (1<<23)
#define CC_AT                 (1<<24)
#define CC_EQUAL              (1<<25)
#define CC_LESS_THAN          (1<<26)
#define CC_GREATER_THAN       (1<<27)
#define CC_PIPE               (1<<28)
#define CC_QUESTION_MARK      (1<<29)
#define CC_ASTERISK           (1<<30)
#define CC_NAME               (CC_ALNUM|CC_UNDERBAR)
#define CC_CRLF               (CC_CR|CC_NEWLINE)

int eng_init();
int init_ssl(struct tls_root_ctx *ctx,struct options *opt);
bool string_class (const char *str, const unsigned int inclusive, const unsigned int exclusive);
bool string_mod (char *str, unsigned int inclusive, unsigned int exclusive,char replace);
void string_replace_leading (char *str,char match,char replace);
void do_alloc_route_list (struct options *opt);
bool string_mod_const(char *str,unsigned int inclusive, unsigned int exclusive,char replace,char *buf);
