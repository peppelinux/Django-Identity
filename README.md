# Django-Identity
Development panel that aims to bring AAI technologies to Django in a secure and standard way. 
Actually started from a SAML2 IDP and SP implementation built on pysaml2, this project will implement also OIDC/oAuth2 and other AAA features.

In this repository we can find quite tested Applications, Code and general Resources related to AAI deployment in a pure Django context.

## Bootstrap code examples
Each one for targeted projects, they will be migrated to project's Readme files.
These are workng examples of an IDP and a SP made with Django.
Components used:

- [pysaml2](https://github.com/IdentityPython/pysaml2)
- [djangosaml2](https://github.com/knaperek/djangosaml2)
- [djangosaml2idp](https://github.com/OTA-Insight/djangosaml2idp)

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
- [Is pysaml2 affected by CVE-2017-11427?](https://github.com/IdentityPython/pysaml2/issues/497)
- courious analisys of [this pysaml2 idp example](https://github.com/IdentityPython/pysaml2/blob/master/example/idp2/idp_conf.py.example)
- SP can actually download on demand IDP metadatas, IDP not. Here should be implemented an approach similar to Shibboleth's FileBackedHTTPMetadataProvider.
- pySAML2 AttributeAuthority Server

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

./manage.py runserver
````

### Other usefull resources

- http://djangosaml2idp.readthedocs.io/en/latest/
- https://github.com/IdentityPython
- https://github.com/fangli/django-saml2-auth
