#include <rain_common.h>
int pthread_setname_np(pthread_t thread, const char *name);

void rain_cleanup(void *p_t_d)
{
	struct pth_timer_data *ptd=NULL;
	ptd = (struct pth_timer_data *)p_t_d;
	printf("######## %s %d %s END thread ###\n",__func__,__LINE__,ptd->name);
	sfree(p_t_d,sizeof(struct pth_timer_data));
}


int rain_timer_start(void *p_t_d)
{
	struct pth_timer_data *ptd=NULL;
	struct timespec sleeptime;
	int ret=0;
	ptd=(struct pth_timer_data *)p_t_d;
	int status=0;

	ret = pthread_detach(pthread_self());
	if(ret < 0){
		MM("[%s:%d] pthread_detach: %s",__func__,__LINE__,strerror(errno));
		return -5;
	}

#if 0
	cpu_set_t cpuset; 
	int cpu = 2;
	int pid = getpid();
	int i=1;
	CPU_ZERO(&cpuset);
	for(i = 1; i < 24;i++){
		CPU_SET(i, &cpuset);
	}
	sched_setaffinity(pid, sizeof(cpuset), &cpuset);

	int priority = -20;
	int which = PRIO_PROCESS;
	setpriority(which, pid, priority);
#endif


	while(1){
		sleeptime.tv_sec = ptd->sec;
		sleeptime.tv_nsec = ptd->nsec;
		nanosleep(&sleeptime, NULL);
		pthread_mutex_lock(&ptd->mutex);
		status = ptd->timer_status;
		pthread_mutex_unlock(&ptd->mutex);

		switch(status){
			case 0: // start
				ptd->start_func(p_t_d);
				break;
			case 1: // end
				break;
			case 2: 
				break;
		}
		if(status == 1){
			break;
		}
	}

	ret = rain_timer_stop(p_t_d);
	return ret;
}

int rain_timer_init(struct pth_timer_data *p_t_d)
{
	int ret;
	size_t thdstacksize=65535;
	pthread_attr_t thdattr;

	ret=pthread_attr_init(&thdattr);
	if(ret < 0){
		return -1;
	}

	ret=pthread_attr_setstacksize(&thdattr,thdstacksize);
	if(ret < 0){
		return -2;
	}
#if 0
	int newprio = -20;
	struct sched_param param;
	ret = pthread_attr_getschedparam (&thdattr, &param);
	param.sched_priority = newprio;
	ret = pthread_attr_setschedparam (&thdattr, &param);
#endif

	ret = pthread_create(&p_t_d->pth_timer,&thdattr,p_t_d->func,(void*)p_t_d);
	if(ret < 0){
		return -3;
	}
	p_t_d->re= 1;
	ret=pthread_attr_destroy(&thdattr);
	if(ret < 0){
		return -4;
	}


	if(strlen(p_t_d->name) > 0){
		pthread_setname_np(p_t_d->pth_timer,p_t_d->name);
	}
	return 0;
}
int rain_timer_stop(struct pth_timer_data *p_t_d)
{
	int error;
	int ret = 0;
	ret = pthread_mutex_destroy(&p_t_d->mutex);
	if(ret < 0){
		MM("##ERR: %s %d ret : %d ##\n",__func__,__LINE__,ret);
	}
	sfree(p_t_d,sizeof(struct pth_timer_data));
	pthread_exit(&error);
	//muntrace();
	return ret;
}
