#! /bin/bash

# vars
CI=card_intermediate
CARD=card_certs
DIR=$CARD/$1
CNF=configs

# set CURVE variable
source set_curve.sh

# create directory
mkdir -p $CARD
mkdir $DIR

# generate private key for card cert
openssl ecparam -outform pem -out $DIR/priv.pem -name $CURVE -genkey

# generate certificate signing request
openssl req -new -nodes -key $DIR/priv.pem -outform pem -out $DIR/csr.pem -config $CNF/req_low_certs.cnf

# generate certificates for the csrs
openssl ca -in $DIR/csr.pem -out $DIR/cert.pem -config $CNF/ca_card_cert.cnf
