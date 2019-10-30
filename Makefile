#O3 not use lock bug..

#CFLAGS= -g -Wall -W  -I./ -I./include ${M_INC}
#CFLAGS= -g -O2 -Wall -W  -I./ -I./include ${M_INC}
#CFLAGS= -march=core-avx-i -pipe -mtune=generic -mfpmath=both -O4 -Wall -W  -I./ -I./include ${M_INC}
#CFLAGS= -O2 -march=core-avx-i -pipe -mtune=generic -mfpmath=both -Wall -W  -I./ -I./include ${M_INC}
CFLAGS= -g -std=gnu99 -march=core-avx-i -pipe -mtune=generic -mfpmath=both -Wall -W  -I./ -I./include ${M_INC}
LDFLAGS= ${M_LIB} 

OBJS = main.o rain_epoll.o  rain_timer.o  rain_tun.o handler.o rain_net.o linkedlist.o \
		 rb.o rb_compare.o \
	init.o proto.o ssl.o crypto.o push.o \
	ssl_openssl.o  crypto_openssl.o ssl_verify_openssl.o \
	ssl_polarssl.o  crypto_polarssl.o ssl_verify_polarssl.o \
	ssl_mbedtls.o  crypto_mbedtls.o ssl_verify_mbedtls.o \
	sig.o \
	ssl_verify.o \
	helper.o pool.o route.o options.o \
	openssl_lock.o  \
	drizzle_handle.o \
	drizzle_thread.o  \
	drizzle_route.o  \
	drizzle_status.o \
	mempool.o \
	limit.o manage.o

	#ssl_mbed.o  crypto_mbed.o ssl_verify_mbed.o 
APP=R031st

.SUFFIXES: .cpp .cxx .cc .C .c

.cpp.o:
	$(CXX) -c $(CXXFLAGS) -o $@ $<

.cxx.o:
	$(CXX) -c $(CXXFLAGS) -o $@ $<

.cc.o:
	$(CXX) -c $(CXXFLAGS) -o $@ $<

.C.o:
	$(CXX) -c $(CXXFLAGS) -o $@ $<

.c.o:
	$(CC) -c $(CFLAGS) -o $@ $<

all: $(APP)

$(APP) :$(OBJS)
	$(CC) $(CFLAGS)  -o $@ $(LDFLAGS) $^  ${S_LIB}
clean:
	rm -f $(OBJS) $(APP)
