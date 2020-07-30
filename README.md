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

oAuth2:

- [django-oauth-toolkit](https://django-oauth-toolkit.readthedocs.io/en/latest/index.html), See [oAuth2 RFC](https://tools.ietf.org/html/rfc6749#section-4)


### Run SP and IDP in HTTPs
See Installation examples.

````
pip install gunicorn

# example for sp is
gunicorn -b0.0.0.0:11000 djangosaml2_sp.wsgi:application --keyfile=./certificates/private.key --certfile=./certificates/public.cert

# or using uwsgi
uwsgi --wsgi-file djangosaml2_sp.wsgi  --https 0.0.0.0:10000,./pki/frontend.cert,./pki/frontend.key --callable application --honour-stdin

````

### djangosaml2 SP with Shibboleth as IDP

Also tested with a Shibboleth IDPv3.3.2 produced with the help of this playbook:
 - https://github.com/peppelinux/Ansible-Shibboleth-IDP-SP-Debian9

The example file is in [djangosaml2_sp/sp_pysaml2_shibidp.py](https://github.com/peppelinux/Django-Identity/blob/master/djangosaml2_sp/djangosaml2_sp/djangosaml2_sp/sp_pysaml2_shibidp.py).
