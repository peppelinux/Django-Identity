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

### Hints

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

##### IDP Auth works but redirect on SP side fails
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
SSL_CTX_get_cert_store() was the right clue and X509_STORE_add_cert() did the trick.
This could be related

Resources:
 - https://www.aleksey.com/xmlsec/api/xmlsec-openssl-x509.html
 - https://www.aleksey.com/pipermail/xmlsec/2011/009076.html
 - http://openssl.6102.n7.nabble.com/Error-18-self-signed-certificate-td47361.html

UPDATES:
Problem: as we see Encyrption method should not be rsa-sha1 but Shibboleth default SHA256!
 - https://github.com/onelogin/python-saml/issues/33#issuecomment-64851119
 - https://www.aleksey.com/pipermail/xmlsec/2014/009862.html

Test this:
 xmlsec1  --verify --trusted-pem testing/ROOT-CA-CERT.pem ../xmltmpl/appreq_signed.xml 

NOTE pysaml2 internals:
- write here...

UPDATES:
- https://github.com/IdentityPython/pysaml2/pull/495



### Debug config loader

````
conf = get_config(config_loader_path, request)
pprint(conf.__dict__)


{'_homedir': '.',
 '_sp_attribute_converters': [<saml2.attribute_converter.AttributeConverter object at 0x7f2dbddfc320>,
                              <saml2.attribute_converter.AttributeConverter object at 0x7f2dbddfc748>,
                              <saml2.attribute_converter.AttributeConverter object at 0x7f2dbddfc8d0>,
                              <saml2.attribute_converter.AttributeConverter object at 0x7f2dbde14048>,
                              <saml2.attribute_converter.AttributeConverter object at 0x7f2dbde14550>],
 '_sp_authn_requests_signed': True,
 '_sp_endpoints': {'assertion_consumer_service': [('http://sp.pysaml2.testunical.it/saml2/acs/',
                                                   'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST')],
                   'single_logout_service': [('http://sp.pysaml2.testunical.it/saml2/ls/',
                                              'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect'),
                                             ('http://sp.pysaml2.testunical.it/saml2/ls/post',
                                              'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST')]},
 '_sp_force_authn': True,
 '_sp_idp': {'https://idp.testunical.it/idp/shibboleth': {'single_logout_service': {'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect': 'https://idp.testunical.it/idp/logout'},
                                                          'single_sign_on_service': {'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect': 'https://idp.testunical.it/idp/login/process/'}}},
 '_sp_logout_requests_signed': True,
 '_sp_name': 'http://sp.pysaml2.testunical.it/saml2/metadata/',
 '_sp_required_attributes': ['uid',
                             'mail',
                             'sn',
                             'cn',
                             'schacPersonalUniqueID'],
 '_sp_want_assertions_signed': True,
 'accepted_time_diff': None,
 'additional_cert_files': None,
 'allow_unknown_attributes': False,
 'attribute': [],
 'attribute_converters': [<saml2.attribute_converter.AttributeConverter object at 0x7f2dbddfc668>,
                          <saml2.attribute_converter.AttributeConverter object at 0x7f2dbde24080>,
                          <saml2.attribute_converter.AttributeConverter object at 0x7f2dbde24470>],
 'attribute_profile': [],
 'ca_certs': None,
 'cert_file': '/home/wert/DEV3/Django-Identity/djangosaml2_sp/djangosaml2_sp/certificates/shibidp/sp.pysaml2.testunical.it-cert.pem',
 'cert_handler_extra_class': None,
 'contact_person': [{'company': 'Universita della Calabria',
                     'contact_type': 'technical',
                     'email_address': 'giuseppe.demarco@unical.it',
                     'given_name': 'Giuseppe',
                     'sur_name': 'De Marco'},
                    {'company': 'Universita della Calabria',
                     'contact_type': 'technical',
                     'email_address': 'giuseppe.demarco@unical.it',
                     'given_name': 'Giuseppe',
                     'sur_name': 'De Marco'}],
 'context': 'sp',
 'crypto_backend': 'xmlsec1',
 'debug': False,
 'description': None,
 'disable_ssl_certificate_validation': None,
 'domain': '',
 'encryption_keypairs': [{'cert_file': '/home/wert/DEV3/Django-Identity/djangosaml2_sp/djangosaml2_sp/certificates/shibidp/sp.pysaml2.testunical.it-cert.pem',
                          'key_file': '/home/wert/DEV3/Django-Identity/djangosaml2_sp/djangosaml2_sp/certificates/shibidp/sp.pysaml2.testunical.it-key.pem'}],
 'entity_category': '',
 'entityid': 'http://sp.pysaml2.testunical.it/saml2/metadata/',
 'extension_schema': {},
 'extensions': {},
 'generate_cert_func': None,
 'generate_cert_info': None,
 'key_file': '/home/wert/DEV3/Django-Identity/djangosaml2_sp/djangosaml2_sp/certificates/shibidp/sp.pysaml2.testunical.it-key.pem',
 'logger': None,
 'logout_requests_signed': None,
 'metadata': <saml2.mdstore.MetadataStore object at 0x7f2dbddfc630>,
 'metadata_key_usage': 'both',
 'name': None,
 'name_form': None,
 'name_id_format': None,
 'name_id_format_allow_create': None,
 'name_qualifier': '',
 'only_use_keys_in_metadata': True,
 'organization': {'display_name': [('Unical', 'it'), ('Unical', 'en')],
                  'name': [('Unical', 'it'), ('Unical', 'en')],
                  'url': [('http://www.unical.it', 'it'),
                          ('http://www.unical.it', 'en')]},
 'policy': None,
 'preferred_binding': {'artifact_resolution_service': ['urn:oasis:names:tc:SAML:2.0:bindings:SOAP'],
                       'assertion_consumer_service': ['urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST',
                                                      'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect',
                                                      'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Artifact'],
                       'assertion_id_request_service': ['urn:oasis:names:tc:SAML:2.0:bindings:URI'],
                       'attribute_consuming_service': ['urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect',
                                                       'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST',
                                                       'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Artifact'],
                       'attribute_service': ['urn:oasis:names:tc:SAML:2.0:bindings:SOAP'],
                       'authn_query_service': ['urn:oasis:names:tc:SAML:2.0:bindings:SOAP'],
                       'authz_service': ['urn:oasis:names:tc:SAML:2.0:bindings:SOAP'],
                       'manage_name_id_service': ['urn:oasis:names:tc:SAML:2.0:bindings:SOAP',
                                                  'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect',
                                                  'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST',
                                                  'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Artifact'],
                       'name_id_mapping_service': ['urn:oasis:names:tc:SAML:2.0:bindings:SOAP'],
                       'single_logout_service': ['urn:oasis:names:tc:SAML:2.0:bindings:SOAP',
                                                 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect',
                                                 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST',
                                                 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Artifact'],
                       'single_sign_on_service': ['urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect',
                                                  'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST',
                                                  'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Artifact']},
 'requested_attribute_name_format': 'urn:oasis:names:tc:SAML:2.0:attrname-format:uri',
 'scope': '',
 'secret': None,
 'serves': ['sp'],
 'tmp_cert_file': None,
 'tmp_key_file': None,
 'valid_for': 8760,
 'validate_certificate': None,
 'verify_encrypt_cert_advice': None,
 'verify_encrypt_cert_assertion': None,
 'verify_ssl_cert': False,
 'virtual_organization': None,
 'vorg': {},
 'xmlsec_binary': '/usr/bin/xmlsec1',
 'xmlsec_path': []}
````
