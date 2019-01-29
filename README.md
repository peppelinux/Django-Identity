# Django-Identity
Development panel that aims to bring AAI technologies to Django context in a secure and standard way. 
Actually started from a SAML2 IDP and SP implementation built on pysaml2, this project will implement also OIDC/oAuth2 and other AAI features.

In this repository we can find quite tested Applications and also general purpose Code and python Resources related to AAI deployment.

## Bootstrap code examples
Each one for targeted projects, they will be migrated to project's Readme files.
These are workng examples of an IDP and a SP made with Django.
Components used:

- [pysaml2](https://github.com/IdentityPython/pysaml2)
- [djangosaml2](https://github.com/knaperek/djangosaml2)
- [djangosaml2idp](https://github.com/OTA-Insight/djangosaml2idp)

- [python3-saml - Not usable yet in these examples](https://github.com/onelogin/python3-saml)


### django-saml-idp (IDP server)
````
sudo apt install xmlsec1 mariadb-server libmariadbclient-dev python3-dev python3-pip libssl-dev
pip3 install virtualenv

mkdir django-saml2-idp
cd django-saml2-idp

virtualenv -ppython3 django-saml2-idp.env
source django-saml2-idp.env/bin/activate

# copy project folder from this git repo
#django-admin startproject django_saml2_idp

# create your MysqlDB
export USER='django-saml2-idp'
export PASS='django-saml2-idp78'
export HOST='%'
export DB='django-saml2-idp'

sudo mysql -u root -e "\
CREATE USER ${USER}@'${HOST}' IDENTIFIED BY '${PASS}';\
CREATE DATABASE ${DB} CHARACTER SET utf8 COLLATE utf8_general_ci;\
GRANT ALL PRIVILEGES ON ${DB}.* TO ${USER}@'${HOST}';"

# try the example app here
cd django_saml2_idp

pip3 install -r requirements
./manage.py migrate
./manage.py runserver 0.0.0.0:9000
````

### djangosaml2-sp (SP server)
````
sudo apt install xmlsec1 mariadb-server libmariadbclient-dev python3-dev python3-pip libssl-dev
pip3 install virtualenv

mkdir djangosaml2_sp
cd djangosaml2_sp

virtualenv -ppython3 djangosaml2_sp.env
source djangosaml2_sp.env/bin/activate

# copy project folder from this git repo
#django-admin startproject djangosaml2_sp

# create your MysqlDB
export USER='djangosaml2_sp'
export PASS='djangosaml2_sp78'
export HOST='%'
export DB='djangosaml2_sp'

sudo mysql -u root -e "\
CREATE USER ${USER}@'${HOST}' IDENTIFIED BY '${PASS}';\
CREATE DATABASE ${DB} CHARACTER SET utf8 COLLATE utf8_general_ci;\
GRANT ALL PRIVILEGES ON ${DB}.* TO ${USER}@'${HOST}';"

# try the example app here
cd djangosaml2_sp

pip3 install -r requirements
./manage.py migrate

# download idp metadata to sp, not needed if remote options is enabled
# wget http://localhost:9000/idp/metadata/

# download sp metadata to idp [remote not yet working here]
wget http://localhost:8000/saml2/metadata/

./manage.py runserver 0.0.0.0:8000
````

### djangosaml2-sp (SP Server) with Shibboleth-IDP

Also tested with a Shibboleth IDPv3.3.2 produced with the help of this playbook:
 - https://github.com/peppelinux/Ansible-Shibboleth-IDP-SP-Debian9

The example file is in [djangosaml2_sp/sp_pysaml2_shibidp.py](https://github.com/peppelinux/Django-Identity/blob/master/djangosaml2_sp/djangosaml2_sp/djangosaml2_sp/sp_pysaml2_shibidp.py).

### SAML2 security assertions
- Artifact resolution should be the best auth method in several bandwidth and security aspects. Read [this](https://stackoverflow.com/questions/13616169/what-is-the-purpose-of-a-saml-artifact)

## Todo 

#### django-saml-idp doesn't filter out attribute policy restrictions. 
Implement attribute policy restrinctions at line 111 of views.py following pysaml2 approach.
Actually the only way to filter out attributes for each SP is omitting fields in SAML_IDP_SPCONFIG[SPNAME]['attribute_mapping']. It works but policies with attribute restrictions allow us to introduce regexp filter per for every field.

This is the code that should be extended:
````
    # Create Identity dict (SP-specific)
    sp_mapping = sp_config.get('attribute_mapping', {'username': 'username'})
    identity = processor.create_identity(request.user, sp_mapping)
````

Also this code should be improved. Check what's going on here and do a security assessment of all the IDP Signing capabilities.
````
if "SigAlg" in request.session and "Signature" in request.session:
        _certs = IDP.metadata.certs(req_info.message.issuer.text, "any", "signing")
        verified_ok = False
        for cert in _certs:
            # TODO implement
            #if verify_redirect_signature(_info, IDP.sec.sec_backend, cert):
            #    verified_ok = True
            #    break
            pass
        if not verified_ok:
            return HttpResponseBadRequest("Message signature verification failure")
````

- Optional feature: Let the user decide how many minutes its data should stay stored on the SP, then clean up them leaving only username for internal objects relationships, page agreement and privacy infomations about their personal attributes stored on the IDP. __This is a common problem of all the SP, once they stored the userdata they won't change these even if they changes IDP side__!

- django production grade approach, improving security posture of pysaml2 implementation [more hacks here](https://github.com/IdentityPython/pysaml2/issues/333)
- courious analisys of [this pysaml2 idp example](https://github.com/IdentityPython/pysaml2/blob/master/example/idp2/idp_conf.py.example)
- SP can actually download on demand IDP metadatas, IDP not. Here should be implemented an approach similar to Shibboleth's FileBackedHTTPMetadataProvider.
- pySAML2 AttributeAuthority Server

### Interesting bugs
- [time_utils](https://github.com/IdentityPython/pysaml2/issues/445)
- [InResponseTo=""](https://github.com/IdentityPython/pysaml2/issues/458)
- [_parse_request Refactoring](https://github.com/IdentityPython/pysaml2/issues/456)
- [Cookies encrypted in AES CBC](https://github.com/IdentityPython/pysaml2/issues/453)
- [empty URI in ServiceName element](https://github.com/IdentityPython/pysaml2/issues/345)
- [handle_logout_request doesn't sign redirect binding responses as requested](https://github.com/IdentityPython/pysaml2/issues/334)
- [XXE attack](https://github.com/IdentityPython/pysaml2/issues/508)
- [SSRF](https://github.com/IdentityPython/pysaml2/issues/510)

### pySAML2 alternatives
With less features then pySAML2:

 - https://github.com/fangli/django-saml2-auth (now forkend in djangosaml2)
 - https://github.com/onelogin/python3-saml

### Auth proxies

- https://github.com/IdentityPython/SATOSA/blob/master/doc/one-to-many.md
- https://github.com/IdentityPython/satosa-developer

### large-metadata
- https://github.com/knaperek/djangosaml2/issues/113

### wayf and dicovery-service
IdP Discovery Service flow described in the specification (http://docs.oasis-open.org/security/saml/Post2.0/sstc-saml-idp-discovery.pdf?) is made of the following steps:

- SP is configured to use a remote IdP Discovery Service to determine the IdP to be used for the Federation SSO operation
- The SP redirects the user to the IdP Discovery Service via a 302 HTTP redirect and provides the following parameters in the query string
- entityID: the Issuer/ProviderID of OIF/SP
- returnIDParam: the name of the query string parameter that the service needs to use for the parameter containing the IdP - ProviderID value, when redirecting the user back to OIF/SP
- return: the URL to use to redirect the user to OIF/SP
- The service determines the IdP to use
- The service redirects the user to OIF/SP via a 302 HTTP redirect based on the query parameter "return" specified by the SP and provides the following parameters in the query string
- A query parameter containing the the IdP ProviderID value; the name of that query parameter is specified by the SP in the returnIDParam query parameter.

Hopefully a Discovery service will:
- Be aware of a list of known IdPs, referenced by the ProviderID/Issuer identifiers
- Let the user select the IdP to use from a drop down list
- Save the user's choice in a cookie called IDPDiscService
- At runtime, the service will check if the IDPDiscService is present:
- If present and contains a valid IdP, then the service will automatically redirect the user back to the SP with the IdP's - - ProviderID/Issuer: no user interaction will take place
- Otherwise, the service will display a page containing a dropdown list of the known IdPs

Additional resources:
- https://www.switch.ch/aai/support/tools/wayf/
- https://github.com/uktrade/staff-sso
- https://github.com/knaperek/djangosaml2/issues/73
- https://github.com/opennode/waldur-auth-saml2
- https://github.com/IdentityPython/SATOSA/issues/140

Interesting third-party discovery services:
- https://github.com/hu-berlin-cms/django-shibboleth-eds
 

### Other usefull resources
- [SAML2 Specifications](http://docs.oasis-open.org/security/saml/v2.0/saml-core-2.0-os.pdf)
- http://djangosaml2idp.readthedocs.io/en/latest/
- https://github.com/IdentityPython
- https://addons.mozilla.org/en-US/firefox/addon/saml-tracer/ (debug)
- https://github.com/SAMLRaider/SAMLRaider (pentest)
- https://wiki.oasis-open.org/security/FrontPage (stdlib source)
- https://www.aleksey.com/xmlsec/download.html (xmlsec1 sources)
