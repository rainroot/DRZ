#include <linux/types.h>

struct list_head{
        struct list_data *prev;
	struct list_data *next;
	int len;
};

struct list_data{
	struct list_head *head;
        struct list_data *prev;
        struct list_data *next;
	char *data;
};

struct list_head* list_init(void);
int input_list(struct list_head *head, char *data);
int del_list(struct list_head *head, struct list_data *del);
void list_uninit(struct list_head *head);
