https://www.spid.gov.it/come-diventare-fornitore-di-servizi-pubblici-e-privati-con-spid#procedura-amministrativa
https://www.eid.gov.it/abilita-eidas

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

### spid saml check
https://github.com/italia/spid-saml-check


CHECK:
- digest SHA-256 for signing features: *to be implemented in pysaml2*, see [this](https://github.com/IdentityPython/pysaml2/pull/396) -> fixed [here](https://github.com/IdentityPython/pysaml2/pull/597)

Mind THAT:
- https://github.com/italia/spid-testenv2/issues/218
- https://github.com/italia/spid-testenv2/issues/217
- https://github.com/italia/spid-regole-tecniche/issues/15


Resources:
- https://idp.spid.gov.it:8080/#/infoidp
- https://docs.italia.it/italia/spid/spid-regole-tecniche/it/stabile/
- https://www.spid.gov.it/come-diventare-fornitore-di-servizi-pubblici-e-privati-con-spid
- https://www.agid.gov.it/sites/default/files/repository_files/circolari/spid-regole_tecniche_v1.pdf
- https://www.spid.gov.it/assets/res/agid-spid-lg-interfacce-informazioni-idp-sp.pdf
- https://github.com/italia/spid-testenv2
- https://github.com/italia/spid
