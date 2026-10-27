#!/bin/sh
# Generates odd-shaped certificates for the decoder test into gen/.
set -e
mkdir -p gen && cd gen
k() { openssl genpkey -quiet "$@"; }
k -algorithm ed25519 -out ed.key
k -algorithm ec -pkeyopt ec_paramgen_curve:P-384 -out p384.key
k -algorithm ec -pkeyopt ec_paramgen_curve:P-521 -out p521.key
k -algorithm rsa-pss -pkeyopt rsa_keygen_bits:3072 -out pss.key
k -algorithm rsa -pkeyopt rsa_keygen_bits:1024 -out rsa1k.key
openssl req -x509 -key ed.key -out ed25519.pem -days 30 -utf8 \
    -subj "/CN=Ünïcødé, \"q\" <x>;#/O=a\\+b\\\\c/OU=#hash/OU=trail /DC=example/DC=com/emailAddress=a@b.c/serialNumber=42/street=Main St/title=Dr/GN=Jo/SN=Doe/UID=u1/L=Zürich/ST=ZH/C=CH" \
    -addext "subjectAltName=DNS:a.example,IP:::1,IP:2001:db8::ff00:42:8329,IP:10.0.0.1,email:x@y.z,URI:https://x/y?z,RID:1.2.3.4,dirName:dn" \
    -config /dev/stdin <<CNF
[req]
distinguished_name=d
[d]
[dn]
CN=Dir Name
O=Org
CNF
openssl req -x509 -key p384.key -out p384.pem -days 36500 -set_serial -12345 \
    -multivalue-rdn -subj "/CN=multi+OU=valued/O=Org" \
    -addext "basicConstraints=critical,CA:TRUE,pathlen:2" \
    -addext "authorityInfoAccess=OCSP;URI:http://ocsp.example/,OCSP;URI:http://o2.example/,caIssuers;URI:http://ca.example/c.crt" \
    -addext "crlDistributionPoints=URI:http://crl.example/c.crl" \
    -addext "certificatePolicies=2.23.140.1.2.1" -addext "nameConstraints=permitted;DNS:example.com"
openssl req -x509 -key p521.key -out p521.pem -days 1 -sha512 -set_serial 0 \
    -subj "/CN=p521" -not_before 20510101000000Z -not_after 20991231235959Z
openssl req -x509 -key pss.key -out pss.pem -days 10 -subj "/CN=pss/O=\\ x\\ " \
    -sigopt rsa_padding_mode:pss -set_serial 0x00ff00ff00ff00ff00ff00ff00ff00ff00ff
openssl req -x509 -key rsa1k.key -out rsa1k-sha1.pem -days 10 -sha1 -subj "/" \
    -set_serial 0x7fffffffffffffff
openssl req -x509 -key rsa1k.key -out bmp.pem -days 10 -subj "/CN=bmp ŝtring" \
    -utf8 -set_serial 1 -config /dev/stdin <<CNF
[req]
distinguished_name=d
string_mask=default
[d]
CNF
rm -f *.key
