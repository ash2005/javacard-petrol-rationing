#! /bin/sh

# a list of all supported curves can be obtained via the command
# openssl ecparam -list_curves
# the secp112r1 curve over a 112 bit prime field looks good since it is rather small

# vars
CA=root
CNF=configs

# clean up from last time
./clean.sh
mkdir $CA
mkdir $CA/newcerts
touch $CA/index.txt
echo "01" > $CA/serial

# generate an ecc private key on the aforementioned curve
openssl ecparam -out $CA/priv.pem -name secp112r1 -genkey

# generate CA cert for key
openssl req -x509 -new -key $CA/priv.pem -out $CA/cert.pem -outform pem -days 3650 -config $CNF/req_ca_cert.cnf
