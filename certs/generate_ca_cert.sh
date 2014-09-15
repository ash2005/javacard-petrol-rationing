#! /bin/sh

# a list of all supported curves can be obtained via the command
# openssl ecparam -list_curves
# the secp112r1 curve over a 112 bit prime field looks good since it is rather small

# clean up from last time
rm -rf *.pem index.txt* serial* newcerts

# generate an ecc private key on the aforementioned curve
openssl ecparam -out ca.priv.pem -name secp112r1 -genkey

# generate CA cert for key
openssl req -x509 -new -key ca.priv.pem -out ca.cert.pem -outform pem -days 3650

# make new index.txt database
touch index.txt

# initialize serial file
echo "01" > serial

# create cert directories
mkdir newcerts
