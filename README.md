# Django-Identity
Development panel that aims to bring AAI technologies to Django context.
It started from a SAML2 IDP and a SP implementation built on pysaml2, this project show also OIDC/oAuth2 and related AAI examples.

In this repository ther are quite tested Applications and also general purpose Code and python Resources related to AAI deployment.

## Bootstrap code examples
Each one for targeted projects, they will be migrated to related project Readme files in the future.
These are workng examples of an IDP and a SP made with Django.

SAML2 Applications used:

- [pysaml2](https://github.com/IdentityPython/pysaml2)
- [djangosaml2](https://github.com/knaperek/djangosaml2)
- [uniAuth](https://github.com/UniversitaDellaCalabria/uniAuth)

OIDC Applications built on top of [jwtconnect.io](https://jwtconnect.io/) stack:

- [django-oidc-op](https://github.com/peppelinux/django-oidc-op), based on [oidc-op](https://github.com/rohe/oidc-op)


### Run SP and IDP in HTTPs
See Installation examples.

###### Configuration

Is you're a djangoer you should problably know that you have, first of all, set yuou environment and decide
which kind of RDBMS engine you want to use, then `./manage.py migrate`. This is an example project, use it as your best.

In `djangosaml2_sp/settings.py` configure which type of SAML2 SP you want to use.
````
# this is for a standard SAML2 federation
if 'saml2_sp' in INSTALLED_APPS:
    from . sp_pysaml2_satosa import *
    # from . import sp_pysaml2_shibidp as sp_pysaml2


# SPID SP
# if 'djangosaml2_spid' in INSTALLED_APPS:
    # from djangosaml2_spid.settings import *
````

If you want to use a SPID SP see `djangosaml2_sp.settings` for configuration.

###### run
````
bash run.sh

````

### djangosaml2 SP with Shibboleth as IDP

Also tested with a Shibboleth IDPv3.3.2 produced with the help of this playbook:
 - https://github.com/peppelinux/Ansible-Shibboleth-IDP-SP-Debian9

The example file is in [djangosaml2_sp/sp_pysaml2_shibidp.py](https://github.com/peppelinux/Django-Identity/blob/master/djangosaml2_sp/djangosaml2_sp/djangosaml2_sp/sp_pysaml2_shibidp.py).


### Docker compose

To use Docker compose environment, add to /etc/hosts this line:
````
127.0.0.1	hostnet
````

Duplicate the two files "*local.py.example" under the directory "./djangosaml2_sp/djangosaml2_sp/" and remove the ".example" extension, like so:
````
cp -a ./djangosaml2_sp/djangosaml2_sp/settingslocal.py.example ./djangosaml2_sp/djangosaml2_sp/settingslocal.py
cp -a ./djangosaml2_sp/djangosaml2_sp/spid_settingslocal.py.example ./djangosaml2_sp/djangosaml2_sp/spid_settingslocal.py
````

then use docker-compose up (the process takes some time) and when the services are up go to http://hostnet:8000/spid/login

### Known issues
  - using two IdP together (tested with spid_testenv2 e spid-saml-check) the server shows an IdP selection page;
  if you select the spid_testenv2 (default http://hostnet:8080/) you get an error about the AuthnRequest XML missing some elements
    ("Issuer - attribute: NameQualifier", "NameIDPolicy", "RequestedAuthnContext"). __workaround__: use in settings.py one IdP at a time.
