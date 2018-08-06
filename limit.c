#include <rain_common.h>
#include <sys/time.h>
#include <sys/resource.h>

/*
	CPU MAX : 18446744073709551615 : 18446744073709551615
	FSiZE MAX : 18446744073709551615 : 18446744073709551615
	DATA MAX : 18446744073709551615 : 18446744073709551615
	STACK MAX : 8388608 : 18446744073709551615
	CORE MAX : 0 : 18446744073709551615
	RSS MAX : 18446744073709551615 : 18446744073709551615
	NPROC MAX : 127615 : 127615
	NOFILE MAX : 65535 : 65535
	OFILE MAX : 65535 : 65535
	MEMLOCK MAX : 65536 : 65536
	LOCKS MAX : 18446744073709551615 : 18446744073709551615
	AS MAX : 18446744073709551615 : 18446744073709551615
	AS MAX : 127615 : 127615
	AS MAX : 819200 : 819200
	AS MAX : 18446744073709551615 : 18446744073709551615
	AS MAX : 18446744073709551615 : 18446744073709551615
*/
int limit_max_set(void){
	struct rlimit rlim;
#if 0
	getrlimit(RLIMIT_CPU, &rlim);
	rlim.rlim_max = RLIM_INFINITY;
	setrlimit(RLIMIT_CPU,&rlim);

	getrlimit(RLIMIT_FSIZE, &rlim);
	rlim.rlim_max = RLIM_INFINITY;
	setrlimit(RLIMIT_FSIZE,&rlim);

	getrlimit(RLIMIT_DATA, &rlim);
	rlim.rlim_max = RLIM_INFINITY;
	setrlimit(RLIMIT_DATA,&rlim);

	getrlimit(RLIMIT_STACK, &rlim);
	rlim.rlim_max = RLIM_INFINITY;
	setrlimit(RLIMIT_STACK,&rlim);

	getrlimit(RLIMIT_CORE, &rlim);
	rlim.rlim_max = 1073741824;
	setrlimit(RLIMIT_CORE,&rlim);

	getrlimit(RLIMIT_RSS, &rlim);
	rlim.rlim_max = RLIM_INFINITY;
	setrlimit(RLIMIT_RSS,&rlim);
#endif
	getrlimit(RLIMIT_NOFILE, &rlim);
	rlim.rlim_max = 1048576;
	setrlimit(RLIMIT_NOFILE,&rlim);
#if 0
	getrlimit(RLIMIT_AS, &rlim);
	rlim.rlim_max = RLIM_INFINITY;
	setrlimit(RLIMIT_AS,&rlim);

#endif
	getrlimit(RLIMIT_NPROC, &rlim);
	rlim.rlim_max = RLIM_INFINITY;
	setrlimit(RLIMIT_NPROC,&rlim);

	getrlimit(RLIMIT_MEMLOCK, &rlim);
	rlim.rlim_max = RLIM_INFINITY;
	setrlimit(RLIMIT_MEMLOCK,&rlim);
#if 0
	getrlimit(RLIMIT_LOCKS, &rlim);
	rlim.rlim_max = RLIM_INFINITY;
	setrlimit(RLIMIT_LOCKS,&rlim);

	getrlimit(RLIMIT_SIGPENDING, &rlim);
	rlim.rlim_max = 127615;
	setrlimit(RLIMIT_SIGPENDING,&rlim);

	getrlimit(RLIMIT_MSGQUEUE, &rlim);
	rlim.rlim_max = 819200;
	setrlimit(RLIMIT_MSGQUEUE,&rlim);
#endif
	getrlimit(RLIMIT_NICE, &rlim);
	rlim.rlim_max = RLIM_INFINITY;
	setrlimit(RLIMIT_NICE,&rlim);

	getrlimit(RLIMIT_RTPRIO, &rlim);
	rlim.rlim_max = RLIM_INFINITY;
	setrlimit(RLIMIT_RTPRIO,&rlim);

	return 0;
}

int limit_set(void){
	struct rlimit rlim;

#if 0
	getrlimit(RLIMIT_NLIMITS, &rlim);
	printf("NLIMITS MAX : %lu : %lu\n", rlim.rlim_cur, rlim.rlim_max);
	if(rlim.rlim_cur < rlim.rlim_max){
		rlim.rlim_cur = rlim.rlim_max;
	}
	setrlimit(RLIMIT_NLIMITS,&rlim);
#endif

	getrlimit(RLIMIT_CPU, &rlim);
	//printf("CPU MAX : %lu : %lu\n", rlim.rlim_cur, rlim.rlim_max);
	if(rlim.rlim_cur < rlim.rlim_max){
		rlim.rlim_cur = rlim.rlim_max;
	}
	setrlimit(RLIMIT_CPU,&rlim);

	getrlimit(RLIMIT_FSIZE, &rlim);
	//printf("FSIZE MAX : %lu : %lu\n", rlim.rlim_cur, rlim.rlim_max);
	if(rlim.rlim_cur < rlim.rlim_max){
		rlim.rlim_cur = rlim.rlim_max;
	}
	setrlimit(RLIMIT_FSIZE,&rlim);

	getrlimit(RLIMIT_DATA, &rlim);
	//printf("DATA MAX : %lu : %lu\n", rlim.rlim_cur, rlim.rlim_max);
	if(rlim.rlim_cur < rlim.rlim_max){
		rlim.rlim_cur = rlim.rlim_max;
	}
	setrlimit(RLIMIT_DATA,&rlim);

	getrlimit(RLIMIT_STACK, &rlim);
	//printf("STACK MAX : %lu : %lu\n", rlim.rlim_cur, rlim.rlim_max);
	if(rlim.rlim_cur < rlim.rlim_max){
		rlim.rlim_cur = rlim.rlim_max;
	}
	setrlimit(RLIMIT_STACK,&rlim);

	getrlimit(RLIMIT_CORE, &rlim);
	//printf("CORE MAX : %lu : %lu\n", rlim.rlim_cur, rlim.rlim_max);
	if(rlim.rlim_cur < rlim.rlim_max){
		rlim.rlim_cur = rlim.rlim_max;
	}
	setrlimit(RLIMIT_CORE,&rlim);

	getrlimit(RLIMIT_RSS, &rlim);
	//printf("RSS MAX : %lu : %lu\n", rlim.rlim_cur, rlim.rlim_max);
	if(rlim.rlim_cur < rlim.rlim_max){
		rlim.rlim_cur = rlim.rlim_max;
	}
	setrlimit(RLIMIT_RSS,&rlim);

	getrlimit(RLIMIT_NPROC, &rlim);
	//printf("NPROC MAX : %lu : %lu\n", rlim.rlim_cur, rlim.rlim_max);
	if(rlim.rlim_cur < rlim.rlim_max){
		rlim.rlim_cur = rlim.rlim_max;
	}
	setrlimit(RLIMIT_NPROC,&rlim);

	getrlimit(RLIMIT_NOFILE, &rlim);
	//printf("NOFILE MAX : %lu : %lu\n", rlim.rlim_cur, rlim.rlim_max);
	if(rlim.rlim_cur < rlim.rlim_max){	
		rlim.rlim_cur = rlim.rlim_max;
	}
	setrlimit(RLIMIT_NOFILE,&rlim);

	getrlimit(RLIMIT_MEMLOCK, &rlim);
	//printf("MEMLOCK MAX : %lu : %lu\n", rlim.rlim_cur, rlim.rlim_max);
	if(rlim.rlim_cur < rlim.rlim_max){
		rlim.rlim_cur = rlim.rlim_max;
	}
	setrlimit(RLIMIT_MEMLOCK,&rlim);

	getrlimit(RLIMIT_AS, &rlim);
	//printf("AS MAX : %lu : %lu\n", rlim.rlim_cur, rlim.rlim_max);
	if(rlim.rlim_cur < rlim.rlim_max){
		rlim.rlim_cur = rlim.rlim_max;
	}
	setrlimit(RLIMIT_AS,&rlim);

	getrlimit(RLIMIT_LOCKS, &rlim);
	//printf("LOCKS MAX : %lu : %lu\n", rlim.rlim_cur, rlim.rlim_max);
	if(rlim.rlim_cur < rlim.rlim_max){
		rlim.rlim_cur = rlim.rlim_max;
	}
	setrlimit(RLIMIT_LOCKS,&rlim);

	getrlimit(RLIMIT_SIGPENDING, &rlim);
	//printf("SIGPENDING MAX : %lu : %lu\n", rlim.rlim_cur, rlim.rlim_max);
	if(rlim.rlim_cur < rlim.rlim_max){
		rlim.rlim_cur = rlim.rlim_max;
	}
	setrlimit(RLIMIT_SIGPENDING,&rlim);

	getrlimit(RLIMIT_MSGQUEUE, &rlim);
	//printf("MSGQUEUE MAX : %lu : %lu\n", rlim.rlim_cur, rlim.rlim_max);
	if(rlim.rlim_cur < rlim.rlim_max){
		rlim.rlim_cur = rlim.rlim_max;
	}
	setrlimit(RLIMIT_MSGQUEUE,&rlim);

	getrlimit(RLIMIT_NICE, &rlim);
	//printf("NICE MAX : %lu : %lu\n", rlim.rlim_cur, rlim.rlim_max);
	if(rlim.rlim_cur < rlim.rlim_max){
		rlim.rlim_cur = rlim.rlim_max;
	}
	setrlimit(RLIMIT_NICE,&rlim);

	getrlimit(RLIMIT_RTPRIO, &rlim);
	//printf("RTPRIO MAX : %lu : %lu\n", rlim.rlim_cur, rlim.rlim_max);
	if(rlim.rlim_cur < rlim.rlim_max){
		rlim.rlim_cur = rlim.rlim_max;
	}
	setrlimit(RLIMIT_RTPRIO,&rlim);
#if 0
	getrlimit(RLIMIT_RTTIME, &rlim);
	//printf("RTTIME MAX : %lu : %lu\n", rlim.rlim_cur, rlim.rlim_max);
	if(rlim.rlim_cur < rlim.rlim_max){
		rlim.rlim_cur = rlim.rlim_max;
	}
	setrlimit(RLIMIT_RTTIME,&rlim);
#endif
	return 0;
}

