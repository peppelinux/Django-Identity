https://www.spid.gov.it/come-diventare-fornitore-di-servizi-pubblici-e-privati-con-spid#procedura-amministrativa

### spid-testenv2

Setup
````
git clone https://github.com/italia/spid-testenv2.git
source $envfolder.env/bin/activate
pip install -r requirements.txt
openssl req -x509 -nodes -sha256 -subj '/C=IT' -newkey rsa:2048 -keyout conf/idp.key -out conf/idp.crt
````

Run
````
wget http://sp1.testunical.it:8000/spid/metadata -O conf/sp_metadata.xml
python spid-testenv.py
````

SP side
````
wget http://idpspid.testunical.it:8088/metadata -O saml2_sp/saml2_config/spid/idp_metadata.xml
````

CHECK:
- SP IDSResponse: ricezione delle risposte da parte del Discovery Service.

DONE:
Things to configure for a SPID SP:

- `ForceAuthn="true"` only for L2 and L3;
   The specification of ForceAuthn=true in the initial SAML request from the service provider specifies that the Identity Provider (IdP) should force re-authentication of the user, even if they possess a valid session

- `<ns0:NameIDPolicy AllowCreate="false" Format="urn:oasis:names:tc:SAML:2.0:nameid-format:persistent"/>` will be instead `<ns0:NameIDPolicy AllowCreate="true" Format="urn:oasis:names:tc:SAML:2.0:nameid-format:transient"/>`
  Questo suona ambiguo perchè AllowCreate dovrebbe essere impedito con NameID persistent, vedi [qui](http://docs.oasis-open.org/security/saml/v2.0/sstc-saml-approved-errata-2.0.html)

- `RequestedAuthnContext` need to be implemented, see: _urn:oasis:names:tc:SAML:2.0:ac:classes: SpidL1_
- digest SHA-256 for signing features: *to be implemented in pysaml2*, see [this](https://github.com/IdentityPython/pysaml2/pull/396) -> fixed [here](https://github.com/IdentityPython/pysaml2/pull/597)



Resources:
- https://docs.italia.it/italia/spid/spid-regole-tecniche/it/stabile/
- https://www.agid.gov.it/sites/default/files/repository_files/circolari/spid-regole_tecniche_v1.pdf
- https://www.spid.gov.it/assets/res/agid-spid-lg-interfacce-informazioni-idp-sp.pdf
- https://github.com/italia/spid-testenv2
- https://github.com/italia/spid
