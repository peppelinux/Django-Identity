pySAML2
-------

````
git clone https://github.com/IdentityPython/pysaml2.git
cd pysaml2
python setup.py install

# unit tests
cd tests
pip install -r test_requirements.txt 

# run tests
py.test

````

### pySAML2 examples

- https://github.com/IdentityPython/pysaml2/blob/master/doc/examples/sp.rst
- [EntityCategory EduGain](https://github.com/IdentityPython/pysaml2/blob/master/example/sp-wsgi/sp_conf.py.example)


### Self Signed Certificates
````
openssl genrsa -out sp-key.pem 2048
openssl req -new -key sp-key.pem -out sp.csr
openssl x509 -req -days 3650 -in sp.csr -signkey sp-key.pem -out sp.crt

# convert them to pem
openssl x509 -inform PEM -in sp.crt > sp-cert.pem
````

### OpenSSL debug

````
always check idp certificate validity
echo -n | openssl s_client -connect idp.testunical.it:443 | grep Verify

# if local issuer (self signed/private CA)
sudo cp testunical.it_ca.crt /etc/ssl/certs/
sudo update-ca-certificates
echo -n | openssl s_client -connect idp.testunical.it:443 -CAfile /etc/ssl/certs/ca-certificates.crt | grep Verify

# or
echo -n | openssl s_client -connect idp.testunical.it:443 -CAfile /etc/ssl/certs/testunical_ca.crt | grep Verify

````


### Common Errors

##### Self signed certs with xmlsec
````
func=xmlSecOpenSSLX509StoreVerify:file=x509vfy.c:line=360:obj=x509-store:subj=X509_verify_cert:error=4:crypto library function failed:subj=/CN=idp.testunical.it;err=18;msg=self signed certificate
func=xmlSecOpenSSLX509StoreVerify:file=x509vfy.c:line=408:obj=x509-store:subj=unknown:error=71:certificate verification failed:err=18;msg=self signed certificate
func=xmlSecOpenSSLEvpSignatureVerify:file=signatures.c:line=493:obj=rsa-sha1:subj=EVP_VerifyFinal:error=18:data do not match:signature do not match
FAIL
SignedInfo References (ok/all): 1/1
Manifests References (ok/all): 0/0
Error: failed to verify file "/tmp/tmpntnzc1mb.xml"

------------------------------------------------------------
func=xmlSecOpenSSLX509StoreVerify:file=x509vfy.c:line=360:obj=x509-store:subj=X509_verify_cert:error=4:crypto library function failed:subj=/CN=idp.testunical.it;err=18;msg=self signed certificate
func=xmlSecOpenSSLX509StoreVerify:file=x509vfy.c:line=408:obj=x509-store:subj=unknown:error=71:certificate verification failed:err=18;msg=self signed certificate
func=xmlSecOpenSSLEvpSignatureVerify:file=signatures.c:line=493:obj=rsa-sha1:subj=EVP_VerifyFinal:error=18:data do not match:signature do not match
FAIL
SignedInfo References (ok/all): 1/1
Manifests References (ok/all): 0/0
Error: failed to verify file "/tmp/tmpntnzc1mb.xml"
============================================================
check_sig: func=xmlSecOpenSSLX509StoreVerify:file=x509vfy.c:line=360:obj=x509-store:subj=X509_verify_cert:error=4:crypto library function failed:subj=/CN=idp.testunical.it;err=18;msg=self signed certificate
func=xmlSecOpenSSLX509StoreVerify:file=x509vfy.c:line=408:obj=x509-store:subj=unknown:error=71:certificate verification failed:err=18;msg=self signed certificate
func=xmlSecOpenSSLEvpSignatureVerify:file=signatures.c:line=493:obj=rsa-sha1:subj=EVP_VerifyFinal:error=18:data do not match:signature do not match
FAIL
SignedInfo References (ok/all): 1/1
Manifests References (ok/all): 0/0
Error: failed to verify file "/tmp/tmpntnzc1mb.xml"

````
Problem: xmlsec1 (OpenSSL) needs to know where self-signed certificates are for security verification.

Test this:
 xmlsec1  --verify --trusted-pem testing/ROOT-CA-CERT.pem ../xmltmpl/appreq_signed.xml 

This warning is not a real problem, just the warning will be printed in stdout.
If ava dictionary doesn't contain any items means that idp attribute filters doesn't have a policy for this.


### Debug hints

````
# A SAML Request test

python3 tests/request_saml_auth.py
````

##### DjangoSAML2 Config manager
````
from django.conf import settings
from djangosaml2.conf import get_config
conf = get_config(config_loader_path=None, request)
pprint(conf.__dict__)
````

##### Play with a response objects (it cames from IDP)
Usefull tests:
 - https://github.com/IdentityPython/pysaml2/blob/master/tests/test_44_authnresp.py
 - https://github.com/IdentityPython/pysaml2/blob/master/tests/test_51_client.py

````
# get Response Objects from response XML
from saml2.samlp import response_from_string
response = samlp.response_from_string(authn_response.xmlstr)
xmlstr = '[put XML response from IDP here]'
rfs = response_from_string(xmlstr)
rfs.__dict__
{'assertion': [],
 'consent': None,
 'destination': 'http://sp.pysaml2.testunical.it/saml2/acs/',
 'encrypted_assertion': [<saml2.saml.EncryptedAssertion at 0x7f53fee5fd68>],
 'extension_attributes': {},
 'extension_elements': [],
 'extensions': None,
 'id': '_6df28307ece7b0b44767621f64062750',
 'in_response_to': 'id-i3XG8etpeS8JvwlBp',
 'issue_instant': '2018-06-28T07:31:16.449Z',
 'issuer': <saml2.saml.Issuer at 0x7f53fee5f6d8>,
 'signature': <saml2.xmldsig.Signature at 0x7f53fee5fba8>,
 'status': <saml2.samlp.Status at 0x7f53fee5f8d0>,
 'text': None,
 'version': '2.0'}
````

##### Play with Encrypted assertion

````
ea = rfs.encrypted_assertion[0]

# cipher_value
ea.encrypted_data.cipher_data.cipher_value.text
cipher_value = ea.encrypted_data.cipher_data.cipher_value.text

# encryption_method
encryption_method = ea.encrypted_data.encryption_method.algorithm

from pprint import pprint
def print_children(children):
    for i in children:
        pprint(i.__dict__)

# children navigations
for i in ea.encrypted_data.key_info.extension_elements:
    child = i.children
    for i in child:
        if not i.children:
            print_children(i.children)
        print()
        for ii in i.children:
            print_children(i.children)
            print_children(ii.children)
            print()


# decrypt data
from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_v1_5
from Crypto.Hash import SHA
from base64 import b64decode

rsa_key = RSA.importKey(open('private.txt', "rb").read())
verifier = PKCS1_v1_5.new(rsa_key)
raw_cipher_data = b64decode(cipher_value)
phn = rsa_key.decrypt(raw_cipher_data)

````

##### Very usefull unit tests:
 - https://github.com/IdentityPython/pysaml2/blob/master/tests/test_51_client.py
