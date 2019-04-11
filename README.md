# Django-Identity
Development panel that aims to bring AAI technologies to Django context in a secure and standard way.
It started from a SAML2 IDP and a SP implementation built on pysaml2, this project will implement also OIDC/oAuth2 and other AAI features.

In this repository ther are quite tested Applications and also general purpose Code and python Resources related to AAI deployment.

## Bootstrap code examples
Each one for targeted projects, they will be migrated to related project Readme files in the future.
These are workng examples of an IDP and a SP made with Django.
Application used:

- [pysaml2](https://github.com/IdentityPython/pysaml2)
- [djangosaml2](https://github.com/knaperek/djangosaml2)
- [djangosaml2idp](https://github.com/OTA-Insight/djangosaml2idp)

### pySAML2 alternatives
All of them have less features then pySAML2:
 - https://github.com/fangli/django-saml2-auth (now forkend in djangosaml2)
 - https://github.com/onelogin/python3-saml

### django-saml-idp (IDP server)
````
sudo apt install xmlsec1 mariadb-server libmariadbclient-dev python3-dev python3-pip libssl-dev libmariadb-dev-compat
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
export DB='djangosaml2idp'

# tested on Debian 10
sudo mysql -u root -e "\
CREATE USER IF NOT EXISTS '${USER}'@'${HOST}' IDENTIFIED BY '${PASS}';\
CREATE DATABASE IF NOT EXISTS ${DB} CHARACTER SET = 'utf8' COLLATE = 'utf8_general_ci';\
GRANT ALL PRIVILEGES ON ${DB}.* TO '${USER}'@'${HOST}';"

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
CREATE USER IF NOT EXISTS '${USER}'@'${HOST}' IDENTIFIED BY '${PASS}';\
CREATE DATABASE IF NOT EXISTS ${DB} CHARACTER SET = 'utf8' COLLATE = 'utf8_general_ci';\
GRANT ALL PRIVILEGES ON ${DB}.* TO ${USER}@'${HOST}';"

# try the example app here
cd djangosaml2_sp

pip3 install -r requirements
./manage.py migrate

# cd djangosaml2_sp/saml2_sp/saml2_config
# download idp metadata to sp, not needed if remote options is enabled
wget http://idp1.testunical.it:9000/idp/metadata/ -O djangosaml2_sp/saml2_sp/saml2_config/idp_metadata.xml

# cd django_saml2_idp/idp/saml2_config
# download sp metadata to idp [remote not yet working here]
wget http://sp1.testunical.it:8000/saml2/metadata/ -O django_saml2_idp/idp/saml2_config/sp_metadata.xml

./manage.py runserver 0.0.0.0:8000
````

### Run SP and IDP in HTTPs
````
pip install gunicorn

# example for sp is
gunicorn -b0.0.0.0:11000 djangosaml2_sp.wsgi:application --keyfile=./certificates/private.key --certfile=./certificates/public.cert
````

### djangosaml2 SP with Shibboleth as IDP

Also tested with a Shibboleth IDPv3.3.2 produced with the help of this playbook:
 - https://github.com/peppelinux/Ansible-Shibboleth-IDP-SP-Debian9

The example file is in [djangosaml2_sp/sp_pysaml2_shibidp.py](https://github.com/peppelinux/Django-Identity/blob/master/djangosaml2_sp/djangosaml2_sp/djangosaml2_sp/sp_pysaml2_shibidp.py).

## djangosaml2idp topics
[pySAML2 IDP Attribute Policy](https://pysaml2.readthedocs.io/en/latest/howto/config.html#policy) on official doc.

Interesting code at views.py#111:
````
    # Create Identity dict (SP-specific)
    sp_mapping = sp_config.get('attribute_mapping', {'username': 'username'})
    identity = processor.create_identity(request.user, sp_mapping)
````

## pySAML2 things, improvements and bugs

- [time_utils](https://github.com/IdentityPython/pysaml2/issues/445)
- [InResponseTo=""](https://github.com/IdentityPython/pysaml2/issues/458)
- [_parse_request Refactoring](https://github.com/IdentityPython/pysaml2/issues/456)
- [Cookies encrypted in AES CBC](https://github.com/IdentityPython/pysaml2/issues/453)
- [empty URI in ServiceName element](https://github.com/IdentityPython/pysaml2/issues/345)
- [handle_logout_request doesn't sign redirect binding responses as requested](https://github.com/IdentityPython/pysaml2/issues/334)
- [XXE attack](https://github.com/IdentityPython/pysaml2/issues/508)
- [SSRF](https://github.com/IdentityPython/pysaml2/issues/510)

## Advanced Topics
Resources and examples about advanced SAML2 implementations and use cases.

### SAML2 security assertions
- Artifact resolution should be the best auth method in several bandwidth and security aspects. Read [this](https://stackoverflow.com/questions/13616169/what-is-the-purpose-of-a-saml-artifact)

### Auth proxies
- https://github.com/IdentityPython/SATOSA/blob/master/doc/one-to-many.md
- https://github.com/IdentityPython/SATOSA/wiki
- https://github.com/IdentityPython/satosa-developer

### large-metadata
- https://github.com/knaperek/djangosaml2/issues/113

### WAYF and Discovery-service
IdP Discovery Service flow described in [SAML2 specifications](http://docs.oasis-open.org/security/saml/Post2.0/sstc-saml-idp-discovery.pdf?) is made of the following steps:

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

http://docs.oasis-open.org/security/saml/Post2.0/sstc-saml-idp-discovery.pdf

Attribute Authorities
- https://www.cesnet.cz/wp-content/uploads/2013/12/saml-aa-shibboleth.pdf

Additional resources:
- https://discovery.refeds.org/guide/
- https://www.switch.ch/aai/support/tools/wayf/
- https://github.com/uktrade/staff-sso
- https://github.com/knaperek/djangosaml2/issues/73
- https://github.com/opennode/waldur-auth-saml2
- https://github.com/IdentityPython/SATOSA/issues/140

Interesting third-party discovery services:
- http://discojuice.org/getting-started/ - awesome to develop a django app (django-discojuice?). See [this php implementation](https://github.com/andreassolberg/DiscoJuice)
- https://www.accountchooser.com/learnmore.html (OpenID)
- https://github.com/hu-berlin-cms/django-shibboleth-eds


## Resources
- SAML2 Primer on [Wikipedia](https://en.m.wikipedia.org/wiki/SAML_2.0)
- SAML2 Primer for Research & Scholarship on [SAFIRE](https://safire.ac.za/safire/publications/saml-primer/)
- https://kantarainitiative.github.io/SAMLprofiles/fedinterop.html
- [SAML2 Specifications](http://docs.oasis-open.org/security/saml/v2.0/saml-core-2.0-os.pdf)
- http://djangosaml2idp.readthedocs.io/en/latest/
- https://github.com/IdentityPython
- https://addons.mozilla.org/en-US/firefox/addon/saml-tracer/ (debug)
- https://github.com/SAMLRaider/SAMLRaider (pentest)
- https://wiki.oasis-open.org/security/FrontPage (stdlib source)
- https://www.aleksey.com/xmlsec/download.html (xmlsec1 sources)
