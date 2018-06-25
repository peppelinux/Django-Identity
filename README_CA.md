### OpenSSL PKI and CA
- [OpenSSL private CA setup](https://jamielinux.com/docs/openssl-certificate-authority/index.html)
- [Private CA and Python requests certifi](https://liuhongjiang.github.io/hexotech/2016/12/23/setup-your-own-ca/)
- https://help.ubuntu.com/lts/serverguide/certificates-and-security.html.en

#### Installing your OWN CA certificates in a GNU/Linux workstation
Copy your certificate in PEM format (the format that has ----BEGIN CERTIFICATE---- in it) into /usr/local/share/ca-certificates and name it with a .crt file extension.

Then run sudo update-ca-certificates.

Caveats: This installation only affects products that use this certificate store. Some products may use other certificate stores; if you use those products, you'll need to add this CA certificate to those other certificate stores, too. (Firefox Instructions, Chrome Instructions, Java Instructions)

##### Reading and converting RSA,CSR and CRT (x509)
````
# check certificate x509
openssl x509 -text -noout -in /etc/ssl/certs/ca-certificates.crt 

# CSR
openssl req -text -noout -verify -in CSR.csr

# Key (RSA)
openssl rsa -in privateKey.key -check

# check pk12 format
openssl pkcs12 -info -in keyStore.p12

# to PEM format
openssl x509 -inform PEM -in keys/$SP_FQDN.crt > $SP_FQDN-cert.pem
openssl rsa -in keys/$SP_FQDN.key -text > $SP_FQDN-key.pem

````



##### Testing The CA
You can verify if this worked by looking for the certificate that you just added in /etc/ssl/certs/ca-certificates.crt (which is just a long list of all of your trusted CA's concatenated together).

You can also use OpenSSL's s_client by trying to connect to a server that you know is using a certificate signed by the CA that you just installed.

````
openssl s_client -connect foo.whatever.com:443 -CApath /etc/ssl/certs
````
