#!/bin/sh
# Regenerates the test PKI. Run from this directory.
set -e
days=36500
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes \
    -keyout ca-key.pem -out ca-cert.pem -days $days -subj "/C=XX/O=Test/CN=Test CA" \
    -addext basicConstraints=critical,CA:TRUE -addext keyUsage=critical,keyCertSign,cRLSign
leaf() { # name subject san extendedKeyUsage
    openssl req -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes \
        -keyout $1-key.pem -out $1.csr -subj "$2"
    printf 'basicConstraints=CA:FALSE\nsubjectAltName=%s\nextendedKeyUsage=%s\n' "$3" "$4" > $1.ext
    openssl x509 -req -in $1.csr -CA ca-cert.pem -CAkey ca-key.pem -CAcreateserial \
        -out $1-cert.pem -days $days -extfile $1.ext
    rm -f $1.csr $1.ext
}
leaf server "/C=XX/O=Test/CN=localhost" "DNS:localhost,IP:127.0.0.1" serverAuth
leaf client "/C=XX/O=Test/CN=Test Client" "DNS:client.test" clientAuth
openssl req -x509 -newkey rsa:2048 -nodes -keyout selfsigned-key.pem \
    -out selfsigned-cert.pem -days $days -subj "/CN=localhost" -addext subjectAltName=DNS:localhost
openssl pkcs8 -topk8 -in server-key.pem -out server-key-enc.pem -v2 aes-256-cbc -passout pass:secret
openssl x509 -in server-cert.pem -outform DER -out server-cert.der
openssl pkey -in server-key.pem -outform DER -out server-key.der
rm -f ca-cert.srl

# Expired on purpose: an intermediate (with a valid leaf below it) and a leaf.
ext() { printf "$2" > $1.ext; }
ext ca 'basicConstraints=critical,CA:TRUE\nkeyUsage=critical,keyCertSign\n'
ext leaf 'subjectAltName=DNS:localhost\nextendedKeyUsage=serverAuth\n'
key() { openssl req -new -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes \
    -keyout $1-key.pem -subj "$2" -out $1.csr; }
key inter "/CN=Expired CA"
openssl x509 -req -in inter.csr -CA ca-cert.pem -CAkey ca-key.pem -set_serial 100 \
    -not_before 20200101000000Z -not_after 20210101000000Z -extfile ca.ext -out inter-cert.pem
key below "/CN=localhost"
openssl x509 -req -in below.csr -CA inter-cert.pem -CAkey inter-key.pem -set_serial 101 \
    -days $days -extfile leaf.ext -out below-cert.pem
key expired "/CN=localhost"
openssl x509 -req -in expired.csr -CA ca-cert.pem -CAkey ca-key.pem -set_serial 102 \
    -not_before 20200101000000Z -not_after 20210101000000Z -extfile leaf.ext -out expired-cert.pem
rm -f *.csr *.ext
