#define MAX_MEMPOOL_CNT 65535*4

#define NORMAL_PKT 0
#define CONTROL_PKT 1
#define DATA_PKT 2

struct mempool{
	int size;
	pthread_mutex_t mp_tree_mutex;
	unsigned int mp_idx;
	pthread_mutex_t mp_idx_mutex;
	unsigned int mp_max_idx;
	struct rb_table *mempool_tree;
}mempool_t;

struct mempool_data{
	uint32_t key;
	bool isuse;
	int pkt_type;
	long long recv_mil;
	char *data;
}mempool_data_t;

int mp_compare(void *ad, void *bd,void *rb_param);
void mp_free(void *ad, void *rb_param);
struct mempool * mempool_create(unsigned int size,unsigned int count);
int mempool_remove(struct mempool *mp);
struct mempool_data * mempool_get(struct mempool *mp);
int  mempool_memset(struct mempool *mp,unsigned int key);
