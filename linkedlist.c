#include <rain_common.h>

struct list_head * list_init(void)
{
	struct list_head * head=NULL;

	head = (struct list_head * )malloc(sizeof(struct list_head));
	if(head == NULL){
		MM("Ringhead Malloc failed.\n");
		return NULL;
	}

	memset(head,0x00,sizeof(struct list_head));

	return head;
}

int input_list(struct list_head *head,char *data)
{
	struct list_data *new = NULL;
	struct list_data *node = NULL;

	new = (struct list_data *)malloc(sizeof(struct list_data));
	if(new == NULL){
		MM("Ringbuffer Malloc failed.\n");
		return -1;
	}
	memset(new,0x00,sizeof(struct list_data));

	new->head = head;
	new->prev = NULL;
	new->next = NULL;
	new->data = data;

	if(head->len == 0){
		head->next = new;
		head->prev = new;
	}else{
		node = head->next;
		while(node->next != NULL){
			node = node->next;
		}
		new->prev = node;
		node->next = new;
		head->prev = new;
	}

	head->len +=1;	

	return 0;
}

int del_list(struct list_head *head, struct list_data *del)
{
	if(del != NULL){
		if(del->next == NULL && del->prev == NULL){
			head->next = NULL;
			head->prev = NULL;
		}
		if(del->next != NULL && del->prev == NULL){
			head->next = del->next;
			del->next->prev = NULL;
		}
		if(del->next == NULL && del->prev != NULL){
			del->prev->next = NULL;
			head->prev = del->prev;
		}
		if(del->next != NULL && del->prev != NULL){
			del->next->prev = del->prev;
			del->prev->next = del->next;
		}

		del->head->len -=1;

		del->head = NULL;
		del->next = NULL;
		del->prev = NULL;
		free(del->data);
		del->data = NULL;
		free(del);
	}

	return 0;
}

void list_uninit(struct list_head *head)
{
	struct list_data *del = NULL;
	struct list_data *node = NULL;

	if(head->next != NULL){
		node = head->next;
		while(node->next != NULL){
			del = node;
			node = node->next;

			del->head = NULL;
			del->prev = NULL;
			del->next = NULL;
			free(del->data);
			del->data = NULL;
			free(del);

		}
		node->head = NULL;
		node->prev = NULL;
		node->next = NULL;
		free(node->data);
		node->data = NULL;
		free(node);
	}

	free(head);
}

