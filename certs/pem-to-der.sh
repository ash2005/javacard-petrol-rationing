#! /bin/sh

#openssl x509 -in $1 -outform der | xxd -p
openssl ec -in $1 -outform der | xxd -p
