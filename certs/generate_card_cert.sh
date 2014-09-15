#! /bin/sh

# generate another private key for client
openssl ecparam -out $1.priv.pem -name secp112r1 -genkey

# generate a certificate signing request
openssl req -new -nodes -key $1.priv.pem -outform pem -out $1.csr.pem

# generate certificate for the csr
openssl ca -in $1.csr.pem -out $1.cert.pem -config openssl.cnf
