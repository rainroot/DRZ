#!/bin/sh

. ../../../rules.mk
. ${PKG_SOURCE_COMMON}/pkg_sc

PKG_NAME=R016st

mkdir -p ${BUILD_TMP}/.${PKG_NAME}/sbin
mkdir -p ${BUILD_TMP}/.${PKG_NAME}_tmp/

PKG_DEF="polarssl-1.3.9 lzo-2.06 zlib-1.2.8"
for X in ${PKG_DEF}; do
    if [ -f ${ROOTRD_DL}/$X.tar.gz ]; then
        tar zxvf ${ROOTRD_DL}/$X.tar.gz -C ${BUILD_TMP}/.${PKG_NAME}_tmp/
    else
	if [ "${X}" == "librain-1.0.1" ];then
		MK_DL_PKG_BUILD $X
	else
		DL_PKG_BUILD $X
	fi
        tar zxvf ${ROOTRD_DL}/$X.tar.gz -C ${BUILD_TMP}/.${PKG_NAME}_tmp/
    fi
done

/home/rainroot/DRIZZLE/v1.0.0B/toolchain_x86_64/bin/x86_64-buildroot-linux-gnu-gcc -g -Wall -W  -I./ -I./include  \
	-I/home/rainroot/DRIZZLE/v1.0.0B/tmp/.R016st_tmp/include \
 	-o R016st  \
	/home/rainroot/DRIZZLE/v1.0.0B/tmp/.R016st_tmp/lib/libpolarssl.a  \
	-L/home/rainroot/DRIZZLE/v1.0.0B/tmp/.R016st_tmp/lib -lpthread -lz \
	main.o rain_epoll.o rain_timer.o rain_tun.o handler.o rain_net.o linkedlist.o rb.o rb_compare.o init.o proto.o ssl.o crypto.o push.o ssl_openssl.o crypto_openssl.o ssl_verify_openssl.o ssl_polarssl.o crypto_polarssl.o ssl_verify_polarssl.o sig.o ssl_verify.o helper.o pool.o route.o options.o openssl_lock.o drizzle_handle.o drizzle_thread.o drizzle_route.o

