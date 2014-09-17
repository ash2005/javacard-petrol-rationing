#! /bin/sh

# vars
CI=card_intermediate
PUMP=pump_terminal_certs
DIR=$PUMP/$1
CNF=configs

# create directory
mkdir -p $PUMP
mkdir $DIR

# generate private key for card cert
openssl ecparam -outform pem -out $DIR/priv.pem -name secp112r1 -genkey

# generate certificate signing request
openssl req -new -nodes -key $DIR/priv.pem -outform pem -out $DIR/csr.pem -config $CNF/req_low_certs.cnf

# generate certificates for the csrs
openssl ca -in $DIR/csr.pem -out $DIR/cert.pem -config $CNF/ca_pump_terminal_cert.cnf
