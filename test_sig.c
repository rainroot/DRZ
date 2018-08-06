#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <pthread.h>

#define NUM_THREADS 3


typedef struct _thread_args
{
	pthread_t tId;
	void* (*func)();
}thread_args;

void *startSigThread(void*); // signal processing thread func
void *startThread(void*);    // worker thread func

void cleanThread(thread_args* tArgs); // thread 종료 담당 
void sa_handler_usr(int nSigNum);     // signal handler func

thread_args tThreadArgs[NUM_THREADS] = {
	{0, startSigThread},
	{0, startThread},
	{0, startThread}
};

int main()
{
	int i;
	int nRtn;

	sigset_t tSigSetMask;


	sigfillset(&tSigSetMask); //signal set setting 및 sigmask
	sigdelset(&tSigSetMask, SIGINT);
	pthread_sigmask(SIG_SETMASK, &tSigSetMask, NULL);
	printf("*Process PID = %d\n", getpid());


	for(i = 0; i < NUM_THREADS; i++) // thread 들 생성
	{
		nRtn = pthread_create(&tThreadArgs[i].tId, NULL, tThreadArgs[i].func, (void*)&tThreadArgs[i]);
		if(nRtn == -1)
		{
			perror("pthread create error\n");
			return -1;
		}
		printf("Create thread : tid = %lu\n", tThreadArgs[i].tId);
	}


	cleanThread(tThreadArgs); // thread 종료

	return 0;
}

void *startSigThread(void* pArgs)
{
	thread_args* tArgs = (thread_args*)pArgs;
	sigset_t tSigSetMask;
	int nSigNum;
	int nErrno;

	printf("* Start signal thread (tid = %lu)\n", (long)pthread_self());

	sigemptyset(&tSigSetMask); // 수신할 signal set setting
	sigaddset(&tSigSetMask, SIGUSR1);
	sigaddset(&tSigSetMask, SIGUSR2);
	sigaddset(&tSigSetMask, SIGTERM);

	while(1)
	{

		nErrno = sigwait(&tSigSetMask, &nSigNum); // signal 대기
		if(nErrno >  0)
		{
			perror("sigwait error\n");
			return NULL;
		}

		switch(nSigNum) // signal no. 에 따라 signal handler 함수 호출 혹은 종료
		{
			case SIGUSR1:
			case SIGUSR2:
				sa_handler_usr(nSigNum);
				break;
			case SIGTERM:
				printf("[signal SIGTERM]\n");
				exit(EXIT_SUCCESS);
			default:
				break;
		}

	}
	return tArgs;
}

void *startThread(void* pArgs)
{
	thread_args* tArgs= (thread_args*)pArgs;
	while(1)
	{
		sleep(1);
	}
	return tArgs;
}

void cleanThread(thread_args* pArgs)
{
	thread_args* tArgs;
	int i;

	for(i = 0; i < NUM_THREADS; i++)
	{
		pthread_join(pArgs->tId, (void**)&tArgs);
		printf("Thread id(%lu) joined\n", pArgs->tId);
		pArgs++;
	}
}

void sa_handler_usr(int nSigNum)
{
	printf("\t[%lu] Signal(%s)\n", 
			pthread_self(),
			nSigNum == SIGUSR1? "USR1":"USR2");
}

