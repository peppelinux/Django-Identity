

### xmlsec1 ssl error=18

Occours if IDP uses selfsigned certificates (pyopenssl).
Fails in:
client.py -> client_base.py -> entity.py -> response.py -> sigver.py -> self.verify_signature [#1535] -> self.verify_signature [#1458]

Exception's stdout here (obj=rsa-sha1:subj=EVP_VerifyFinal:error=18:data do not match:signature do not match):
````
============================================================

func=xmlSecOpenSSLX509StoreVerify:file=x509vfy.c:line=360:obj=x509-store:subj=X509_verify_cert:error=4:crypto library function failed:subj=/CN=idp.testunical.it;err=18;msg=self signed certificate
func=xmlSecOpenSSLX509StoreVerify:file=x509vfy.c:line=408:obj=x509-store:subj=unknown:error=71:certificate verification failed:err=18;msg=self signed certificate
func=xmlSecOpenSSLEvpSignatureVerify:file=signatures.c:line=493:obj=rsa-sha1:subj=EVP_VerifyFinal:error=18:data do not match:signature do not match
FAIL
SignedInfo References (ok/all): 1/1
Manifests References (ok/all): 0/0
Error: failed to verify file "/tmp/tmpdmllw0e6.xml"

------------------------------------------------------------
func=xmlSecOpenSSLX509StoreVerify:file=x509vfy.c:line=360:obj=x509-store:subj=X509_verify_cert:error=4:crypto library function failed:subj=/CN=idp.testunical.it;err=18;msg=self signed certificate
func=xmlSecOpenSSLX509StoreVerify:file=x509vfy.c:line=408:obj=x509-store:subj=unknown:error=71:certificate verification failed:err=18;msg=self signed certificate
func=xmlSecOpenSSLEvpSignatureVerify:file=signatures.c:line=493:obj=rsa-sha1:subj=EVP_VerifyFinal:error=18:data do not match:signature do not match
FAIL
SignedInfo References (ok/all): 1/1
Manifests References (ok/all): 0/0
Error: failed to verify file "/tmp/tmpdmllw0e6.xml"
============================================================
check_sig: func=xmlSecOpenSSLX509StoreVerify:file=x509vfy.c:line=360:obj=x509-store:subj=X509_verify_cert:error=4:crypto library function failed:subj=/CN=idp.testunical.it;err=18;msg=self signed certificate
func=xmlSecOpenSSLX509StoreVerify:file=x509vfy.c:line=408:obj=x509-store:subj=unknown:error=71:certificate verification failed:err=18;msg=self signed certificate
func=xmlSecOpenSSLEvpSignatureVerify:file=signatures.c:line=493:obj=rsa-sha1:subj=EVP_VerifyFinal:error=18:data do not match:signature do not match
FAIL
SignedInfo References (ok/all): 1/1
Manifests References (ok/all): 0/0
Error: failed to verify file "/tmp/tmpdmllw0e6.xml"
````
