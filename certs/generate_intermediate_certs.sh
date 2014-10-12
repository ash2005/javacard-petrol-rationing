#! /bin/bash

# vars
CI=card_intermediate
PTI=pump_terminal_intermediate
CTI=charging_terminal_intermediate
CNF=configs

# set CURVE variable
source set_curve.sh

# clean up
rm -rf $CI $PTI $CTI
mkdir $CI $CI/newcerts
mkdir $PTI $PTI/newcerts
mkdir $CTI $CTI/newcerts

# make new index.txt databases
touch $CI/index.txt
touch $PTI/index.txt
touch $CTI/index.txt

# initialize serial files
echo "01" > $CI/serial
echo "01" > $PTI/serial
echo "01" > $CTI/serial

# generate private keys for client intermediate certs
openssl ecparam -outform pem -out $CI/priv.pem -name $CURVE -genkey
openssl ecparam -outform pem -out $PTI/priv.pem -name $CURVE -genkey
openssl ecparam -outform pem -out $CTI/priv.pem -name $CURVE -genkey

# generate certificate signing requests
openssl req -new -nodes -key $CI/priv.pem -outform pem -out $CI/csr.pem -config $CNF/req_$CI.cnf
openssl req -new -nodes -key $PTI/priv.pem -outform pem -out $PTI/csr.pem -config $CNF/req_$PTI.cnf
openssl req -new -nodes -key $CTI/priv.pem -outform pem -out $CTI/csr.pem -config $CNF/req_$CTI.cnf

# generate certificates for the csrs
openssl ca -in $CI/csr.pem -out $CI/cert.pem -config $CNF/ca_intermediates.cnf
openssl ca -in $PTI/csr.pem -out $PTI/cert.pem -config $CNF/ca_intermediates.cnf
openssl ca -in $CTI/csr.pem -out $CTI/cert.pem -config $CNF/ca_intermediates.cnf
