
struct pth_timer_data{
	void *func;
	void *ptr;
	pthread_t pth_timer;
	pthread_attr_t thdattr;
	pthread_mutex_t mutex;
	int sec;
	int nsec;
	int timer_status;
	int main_stop;
	void ((*start_func)(void *));
	int ((*hand_func)(void *));
	int re;
	char name[32];
}pth_timer_data_t;

int rain_timer_start(void *p_t_d);
int rain_timer_init(struct pth_timer_data *p_t_d);
int rain_timer_stop(struct pth_timer_data *p_t_d);
void rain_cleanup(void *p_t_d);
