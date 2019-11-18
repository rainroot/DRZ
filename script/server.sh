#!/bin/sh

# private key 생성
openssl genrsa -out cert.key 2048

# csr 생성
openssl req -new -key cert.key -out cert.csr -subj "/C=KR/O=My Organization/CN=VPN Server"

# CA 인증서/키로 인증서 생성
echo "basicConstraints = critical, CA:FALSE
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid,issuer
keyUsage = digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth" > cert.ext

openssl x509 -req -days 3650 -extfile cert.ext -CA ca.crt -CAcreateserial -CAkey  ca.key -in cert.csr -out cert.crt

# 필요없는 설정파일과 csr 제거
rm -rf cert.ext cert.csr

# 서버 인증서, 키 등 이동 / 복사
mkdir -p ../openvpn/
cp ca.crt ../openvpn/ca.crt
cp cert.key ../openvpn/server.key
cp ta.key ../openvpn/ta.key
mv cert.crt ../openvpn/server.crt
