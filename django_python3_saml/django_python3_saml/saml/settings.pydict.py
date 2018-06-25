IDP_URL = 'https://idp.testunical.it/idp'
IDP_METADATA_URL='{}{}'.format(IDP_URL, '/shibboleth')
SP_FQDN = 'http://sp.py3saml.testunical.it'

SP_CONF = {
            "strict": True,
            "debug": True,
            "sp": {
                #"entityId": "https://<sp_domain>/metadata/",
                "entityId": "{}/metadata/".format(SP_FQDN),
                "assertionConsumerService": {
                    "url": "{}/?acs".format(SP_FQDN),
                    "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
                },
                "singleLogoutService": {
                    "url": "{}/?sls".format(SP_FQDN),
                    "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
                },
                "NameIDFormat": "urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified",
                "x509cert": "sp.crt",
                "privateKey": "sp.key"
            },
            "idp": {
                "entityId": IDP_METADATA_URL,
                "singleSignOnService": {
                    "url": '{}/login/process/'.format(IDP_URL),
                    "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
                },
                "singleLogoutService": {
                    "url": '{}/ls/'.format(IDP_URL),
                    "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
                },
                "x509cert": "idp.testunical.it-cert.crt"
            }
}

import json
from pprint import pprint

pprint(SP_CONF)

with open('settings.json', 'w') as outfile:
    json.dump(SP_CONF, outfile)
