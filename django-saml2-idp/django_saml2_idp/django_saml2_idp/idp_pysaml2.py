import os
import saml2
from saml2.saml import NAMEID_FORMAT_TRANSIENT, NAMEID_FORMAT_PERSISTENT
from saml2.saml import NAME_FORMAT_URI

from saml2.sigver import get_xmlsec_binary

# Build paths inside the project like this: os.path.join(BASE_DIR, ...)
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

LOGIN_URL = '/login/'

# idp protocol:fqdn:port
HOST = 'idp1.testunical.it'
PORT = 9000
HTTPS = False
if HTTPS: BASE = "https://%s:%s" % (HOST, PORT)
else: BASE = "http://%s:%s" % (HOST, PORT)
BASE_URL = '{}/idp'.format(BASE)
# end

SP_METADATA_URL = 'http://localhost:8000/saml2/metadata/'

SAML_IDP_CONFIG = {
    'debug' : True,
    'xmlsec_binary': get_xmlsec_binary(['/opt/local/bin', '/usr/bin/xmlsec1']),
    'entityid': '%s/metadata' % BASE_URL,
    'description': 'Example IdP setup',

    'service': {
        'idp': {
            'name': 'Django localhost IdP',
            'endpoints': {
                'single_sign_on_service': [
                    ('%s/sso/post' % BASE_URL, saml2.BINDING_HTTP_POST),
                    ('%s/sso/redirect' % BASE_URL, saml2.BINDING_HTTP_REDIRECT),
                ],
            },
            'name_id_format': [NAMEID_FORMAT_TRANSIENT,
                               NAMEID_FORMAT_PERSISTENT],

            'sign_response': True,
            'sign_assertion': True,

            # attribute policy
            # it seems that only SAML_IDP_SPCONFIG[SP]['attribute_mappings'] work as a filter!
            # policy with django-saml2-idp seems not!

            # "policy": {
                # "default": {
                    # "lifetime": {"minutes":15},
                    # "attribute_restrictions": {
                        # ## defaults Django User Account attributes (better do not show)
                        # "date_joined": None,
                        # "last_login": None,
                        # "password": None, # it's not readable but do not show by default
                        # "id": None,
                        # "user_permissions": None,

                        # ## only these will be showed
                        # 'username': None,
                        # 'first_name': None,
                        # 'last_name': None,
                        #
                        ## Here only mail addresses that end with ".umu.se" will be returned.
                        # 'email': None,
                        # #'email': [".*\.umu\.se$"],
                        # "mail": [".*\.umu\.se$"],
                    # },
                    # "name_form": "urn:oasis:names:tc:SAML:2.0:attrname-format:uri"
                # },

                # SP_METADATA_URL: {
                    # "lifetime": {"minutes": 5},
                    # "attribute_restrictions":{
                        # "givenName": None,
                        # "surName": None,
#
                        ## By default there is no restrictions as to which attributes should be return. Instead all the attributes and values that are gathered by the database backends will be returned if nothing else is stated. In the example above the SP with the entity identifier "urn:mace:umu.se:saml:roland:sp" has an attribute restriction: only the attributes 'givenName' and 'surName' are to be returned. There is no limitations as to what values on these attributes that can be returned.
                        # 'username': None,
                        # 'first_name': None,
                        # 'last_name': [".*\.umu\.se$"],
                        # 'email': [".*\.umu\.se$"],
#
                    # }
                # }
            # } # end attribute policy

        },
    },

    'metadata': {
        # periodically download this file with a scheduler like cron
        'local': [os.path.join(os.path.join(os.path.join(BASE_DIR, 'idp'), 'saml2_config'), 'sp_metadata.xml')],
        #"remote": [{
            #"url": SP_METADATA_URL,
            # "cert":"idp_https_cert.pem"}]
            #}]
    },
    # Signing
    'key_file': BASE_DIR + '/certificates/private_key.pem',
    'cert_file': BASE_DIR + '/certificates/public_key.pem',
    # Encryption
    'encryption_keypairs': [{
        'key_file': BASE_DIR + '/certificates/private_key.pem',
        'cert_file': BASE_DIR + '/certificates/public_key.pem',
    }],

    # How many hours this configuration is expected to be accurate.
    # This of course is only used by make_metadata.py. The server will not stop working when this amount of time has elapsed :-).
    'valid_for': 24,
}



SAML_IDP_SPCONFIG = {
    '{}'.format(SP_METADATA_URL): {
        'processor': 'djangosaml2idp.processors.BaseProcessor',
        'attribute_mapping': {
            # DJANGO: SAML
            # only these attributes from this SP
            'email': 'email',
            'first_name': 'first_name',
            'last_name': 'last_name',
            #'is_staff': 'is_staff',
            # 'is_superuser':  'is_superuser',
            # 'user_permissions': 'user_permissions',
            # 'groups': 'groups',
        },
    }
}
