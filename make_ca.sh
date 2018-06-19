#!/bin/bash
export CERT_PATH=`pwd`"/certs"
export PEM_PATH="$CERT_PATH/pem"
export DOMAIN="testunical.it"
export SERVER_FQDN="pysaml2.sp.$DOMAIN"

apt install easy-rsa
rm -f easy-rsa
cp -Rp /usr/share/easy-rsa/ .
cd easy-rsa

# link easy-rsa ssl config defaults
# You can also edit it to change some informations about issuer and remove EASY-Rsa messages
ln -s openssl-1.0.0.cnf openssl.cnf # won't works with CommonName

# using original openssl file (needs more customizations)
# cp /etc/ssl/openssl.cnf openssl.cnf
# sed -i '1s/^/# For use with easy-rsa version 2.0 and OpenSSL 1.0.0*\n/' openssl.cnf

# customize informations in vars file (or override them later with env VAR)
# remember to configure "Common Name (your server's hostname)" in your certs 
# to let your client avoids "does not match common name in certificate"
#nano vars

# then source it
. ./vars

# override for speedup
export KEY_ALTNAMES=$DOMAIN
export KEY_OU=$DOMAIN
export KEY_NAME=$DOMAIN
export KEY_CN=$DOMAIN

export KEY_COUNTRY="IT"
export KEY_PROVINCE="CS"
export KEY_CITY="Cosenza"
export KEY_ORG="$DOMAIN"
export KEY_EMAIL="me@$DOMAIN"

./clean-all

./build-ca
./build-dh

export KEY_ALTNAMES=$SERVER_FQDN
export KEY_NAME=$SERVER_FQDN
export KEY_CN=$SERVER_FQDN
export KEY_NAME=$SERVER_FQDN
./build-key-server $SERVER_FQDN

mkdir -p $PEM_PATH

openssl x509 -inform PEM -in keys/ca.crt > $PEM_PATH/$DOMAIN-cacert.pem

openssl x509 -inform PEM -in keys/$SERVER_FQDN.crt > $PEM_PATH/$SERVER_FQDN-cert.pem
openssl rsa -in keys/$SERVER_FQDN.key -text > $PEM_PATH/$SERVER_FQDN-key.pem

mkdir -p $CERT_PATH

cp $PEM_PATH/$DOMAIN-cacert.pem $CERT_PATH/
cp $PEM_PATH/$SERVER_FQDN-cert.pem $CERT_PATH/
cp $PEM_PATH/$SERVER_FQDN-key.pem $CERT_PATH/
