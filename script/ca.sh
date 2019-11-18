#!/bin/sh

openssl genrsa -out ca.key 2048

openssl req -new -key ca.key -out ca.csr -subj "/C=KR/O=TIM Lab/CN=My VPN CA"

echo "basicConstraints = critical, CA:TRUE
subjectKeyIdentifier = hash
keyUsage = digitalSignature, keyCertSign, cRLSign" > ca.ext

openssl x509 -req -days 3650 -extfile ca.ext -set_serial 1 -signkey ca.key -in ca.csr -out ca.crt

rm -rf ca.ext ca.csr

