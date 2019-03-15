import os
import saml2
from saml2 import (BINDING_HTTP_POST,
                   BINDING_SOAP,
                   BINDING_HTTP_ARTIFACT,
                   BINDING_HTTP_REDIRECT,
                   BINDING_PAOS)
from saml2.saml import (NAMEID_FORMAT_TRANSIENT,
                        NAMEID_FORMAT_PERSISTENT)
from saml2.saml import NAME_FORMAT_URI

from saml2.sigver import get_xmlsec_binary

# Build paths inside the project like this: os.path.join(BASE_DIR, ...)
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

LOGIN_URL = '/login/'

# idp protocol:fqdn:port
HOST = 'idp1.testunical.it'
PORT = 9000
HTTPS = False
if HTTPS:
    BASE = "https://%s:%s" % (HOST, PORT)
else:
    BASE = "http://%s:%s" % (HOST, PORT)
BASE_URL = '{}/idp'.format(BASE)
# end

SP_METADATA_URL = 'http://sp1.testunical.it:8000/saml2/metadata/'

SAML_IDP_CONFIG = {
    'debug' : True,
    'xmlsec_binary': get_xmlsec_binary(['/opt/local/bin', '/usr/bin/xmlsec1']),
    'entityid': '%s/metadata' % BASE_URL,
    'description': 'Example IdP setup',

    'service': {
        # "aa": {
            # "endpoints": {
                # "attribute_service": [
                    # ("%s/aap" % BASE, BINDING_HTTP_POST),
                    # ("%s/aas" % BASE, BINDING_SOAP)
                # ]
            # },
        # },
        'idp': {
            'name': 'Django localhost IdP',
            'endpoints': {
                'single_sign_on_service': [
                    ('%s/sso/post' % BASE_URL, BINDING_HTTP_POST),
                    ('%s/sso/redirect' % BASE_URL, BINDING_HTTP_REDIRECT),
                    ("%s/sso/art" % BASE, BINDING_HTTP_ARTIFACT),
                ],
                "assertion_consumer_service": [
                    ("%s/acs/post" % BASE, BINDING_HTTP_POST),
                    ("%s/acs/redirect" % BASE, BINDING_HTTP_REDIRECT),
                    ("%s/acs/artifact" % BASE, BINDING_HTTP_ARTIFACT),
                    #("%s/acs/soap" % BASE, BINDING_SOAP),
                    ("%s/ecp" % BASE, BINDING_PAOS)
                ],
                "artifact_resolution_service":[
                    ("%s/ars" % BASE, BINDING_SOAP)
                ],
                "single_logout_service": [
                    ("%s/slo/soap" % BASE, BINDING_SOAP),
                    ("%s/slo/post" % BASE, BINDING_HTTP_POST),
                    ("%s/slo/redirect" % BASE, BINDING_HTTP_REDIRECT)
                ],
            },
            'name_id_format': [NAMEID_FORMAT_TRANSIENT,
                               NAMEID_FORMAT_PERSISTENT],

            'sign_response': True,
            'sign_assertion': True,

            # attribute policy
            # it seems that only SAML_IDP_SPCONFIG[SP]['attribute_mappings'] work as a filter!
            # policy with django-saml2-idp seems not!

            "policy": {
                "default": {
                    "lifetime": {"minutes": 15},

                    # if the sp is not conform to entity_categories the attributes will not be released
                    #"entity_categories": ["swamid", "edugain"],

                    "name_form": NAME_FORMAT_URI,
                    # "name_form": "urn:oasis:names:tc:SAML:2.0:attrname-format:uri"
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
                },
                # "https://example.com/sp": {
                    # "lifetime": {"minutes": 5},
                    # "nameid_format": NAMEID_FORMAT_PERSISTENT,
                    # "name_form": NAME_FORMAT_BASIC
                # }
            },
            # } # end attribute policy

        },
    },

    'metadata': [{
        # periodically download this file with a scheduler like cron
        # 'local': [os.path.join(os.path.join(os.path.join(BASE_DIR, 'idp'),
                  # 'saml2_config'), 'sp_metadata.xml')],
        #"remote": [{
            #"url": SP_METADATA_URL,
            # "cert":"idp_https_cert.pem"}]
            #}]

        "class": "saml2.mdstore.MetaDataFile",
        "metadata": [(os.path.join(os.path.join(os.path.join(BASE_DIR, 'idp'),
                      'saml2_config'), 'sp_metadata.xml'), ),
                     # (full_path("metadata_sp_2.xml"), ),
                     # (full_path("vo_metadata.xml"), )
                     ],
    }],
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

    # own metadata settings
    'contact_person': [
      {'given_name': 'Giuseppe',
       'sur_name': 'De Marco',
       'company': 'Universita della Calabria',
       'email_address': 'giuseppe.demarco@unical.it',
       'contact_type': 'administrative'},
      {'given_name': 'Giuseppe',
       'sur_name': 'De Marco',
       'company': 'Universita della Calabria',
       'email_address': 'giuseppe.demarco@unical.it',
       'contact_type': 'technical'},
      ],
    # you can set multilanguage information here
    'organization': {
      'name': [('Unical', 'it'), ('Unical', 'en')],
      'display_name': [('Unical', 'it'), ('Unical', 'en')],
      'url': [('http://www.unical.it', 'it'),
              ('http://www.unical.it', 'en')],
      },

    # TODO: put idp logs in a separate file too
    # "logger": {
        # "rotating": {
            # "filename": "idp.log",
            # "maxBytes": 500000,
            # "backupCount": 5,
        # },
        # "loglevel": "debug",
    # }

}


SAML_IDP_SPCONFIG = {
    '{}'.format(SP_METADATA_URL): {
        'processor': 'djangosaml2idp.processors.BaseProcessor',
        'attribute_mapping': {
            # DJANGO: SAML
            # only these attributes from this IDP
            'email': 'email',
            'first_name': 'first_name',
            'last_name': 'last_name',
            'username': 'username',
            'is_staff': 'is_staff',
            'is_superuser':  'is_superuser',
            'user_permissions': 'user_permissions',
            'groups': 'groups',
        },
    }
}
