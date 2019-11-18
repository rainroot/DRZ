#!/bin/sh

PKG_NAME=R031st
MEMPOOL=1

OPENSSL=1
MBEDTLS=0
POLARSSL=0

make clean



if [ $OPENSSL == 1 ]; then
	M_INC=" $M_INC -DOPENSSL_CONF "
	#M_LIB=" -L${BUILD_TMP}/.${PKG_NAME}_tmp/lib64 -lssl -lcrypto"
	S_LIB=" -lssl -lcrypto -lc -ldl " 
elif [ $POLARSSL == 1 ]; then
	M_INC=" $M_INC -DPOLARSSL_CONF "
	S_LIB=" ${BUILD_TMP}/.${PKG_NAME}_tmp/lib/libpolarssl.a "
elif [ $MBEDTLS == 1 ]; then
	#M_INC=" $M_INC -DMBEDTLS_CONF_ -DMBEDTLS_CONFIG_FILE='<${BUILD_TMP}/.${PKG_NAME}_tmp/include/mbedtls/config.h>' -DMBEDTLS_THREADING_PTHREAD "
	M_INC=" $M_INC -DMBEDTLS_CONF " #-I${BUILD_TMP}/.${PKG_NAME}_tmp/include/mbedtls/ " # -DMBEDTLS_THREADING_PTHREAD "
	S_LIB=" ${BUILD_TMP}/.${PKG_NAME}_tmp/lib/libmbedcrypto.a ${BUILD_TMP}/.${PKG_NAME}_tmp/lib/libmbedx509.a ${BUILD_TMP}/.${PKG_NAME}_tmp/lib/libmbedtls.a "
fi
#M_INC="$M_INC -I${BUILD_TMP}/.${PKG_NAME}_tmp/include -DENABLE_MANAGEMENT " 
#M_LIB=" -L${BUILD_TMP}/.${PKG_NAME}_tmp/lib -lpthread -lz -dl $M_LIB" \
#M_INC="$M_INC -I${BUILD_TMP}/.${PKG_NAME}_tmp/include " \

M_INC="$M_INC " \
M_LIB=" -lpthread -lz -dl $M_LIB" \
S_LIB=" $S_LIB " \
CC=${CROSS_COMPILE}gcc \
CXX=${CROSS_COMPILE}g++ \
LD=${CROSS_COMPILE}ld \
AR="${CROSS_COMPILE}ar  " \
STRIP=${CROSS_COMPILE}strip \
RANLIB=${CROSS_COMPILE}ranlib \
make


#coredumpctl -o target dump /home/user/test/test_program
