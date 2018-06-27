IDP_URL = 'https://idp.testunical.it/idp'
IDP_METADATA_URL='{}{}'.format(IDP_URL, '/shibboleth')
SP_FQDN = 'http://sp.py3saml.testunical.it'

SP_CONF = {
            # If strict is True, then the Python Toolkit will reject unsigned
            # or unencrypted messages if it expects them to be signed or encrypted.
            # Also it will reject the messages if the SAML standard is not strictly
            # followed. Destination, NameId, Conditions ... are validated too.
            "strict": True,
        
            # Enable debug mode (outputs errors).
            "debug": True,
            "sp": {
                #"entityId": "https://<sp_domain>/metadata/",
                "entityId": "{}/metadata/".format(SP_FQDN),
                "assertionConsumerService": {
                    "url": "{}/?acs".format(SP_FQDN),
                    # supports only HTTP-POST
                    "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
                },
                "singleLogoutService": {
                    "url": "{}/?sls".format(SP_FQDN),
                    "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
                },
                "NameIDFormat": "urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified",
                # must be a one-line string: Ensure that your x509cert value is a one-line string,
                # "x509cert": "sp.crt",
                # "privateKey": "sp.key"
                # "x509cert": "sp-cert.pem",
                # "privateKey": "sp-key.pem",
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
                # x509cert must be a one-line string: Ensure that your x509cert value is a one-line string, with no line breaks. Use the FORMAT A X509 CERTIFICATE tool to format your value, if necessary.
                # "x509cert": "---BEGIN ...."
            }
}

import json
from pprint import pprint

pprint(SP_CONF)

with open('settings.json', 'w') as outfile:
    json.dump(SP_CONF, outfile)
