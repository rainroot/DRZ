#include <rain_common.h>

int block_sigpipe()
{
	sigset_t sigset;
	memset(&sigset, 0, sizeof(sigset));

	if(sigprocmask(SIG_BLOCK, NULL, &sigset) == -1){
		//perror("sigprocmask (get)");
		MM("## %s %d ##\n",__func__,__LINE__);
		return -1;
	}

	if(sigaddset(&sigset, SIGPIPE) == -1){
		MM("## %s %d ##\n",__func__,__LINE__);
		//perror("sigaddset");
		return -1;
	}

	if(sigprocmask(SIG_BLOCK, &sigset, NULL) == -1){
		MM("## %s %d ##\n",__func__,__LINE__);
		//perror("sigprocmask (set)");
		return -1;
	}

	return 0;
}


