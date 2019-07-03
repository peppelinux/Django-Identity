import os
import saml2
from saml2.saml import (NAMEID_FORMAT_PERSISTENT,
                        NAMEID_FORMAT_TRANSIENT,
                        NAMEID_FORMAT_UNSPECIFIED)
from saml2.sigver import get_xmlsec_binary

# Build paths inside the project like this: os.path.join(BASE_DIR, ...)
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

BASE = 'https://sp1.testunical.it'
BASE_URL = '{}/saml2'.format(BASE)

LOGIN_URL = '/saml2/login/'
LOGOUT_URL = '/saml2/logout/'

# needed only if metadata are downloaded remotely
# IDP_URL = 'http://idp1.testunical.it:9000/idp'

SAML_CONFIG = {
    'debug' : True,
    'xmlsec_binary': get_xmlsec_binary(['/opt/local/bin',
                                        '/usr/bin/xmlsec1']),
    'entityid': '%s/metadata/' % BASE_URL,

    'attribute_map_dir': os.path.join(os.path.join(os.path.join(BASE_DIR,
                                                                'djangosaml2_spid'),
                                      'saml2_config'),
                                      'attribute-maps-satosa'),

    'service': {
        'sp': {
            'name': '%s/metadata/' % BASE_URL,

            # SPID needs NAMEID_FORMAT_TRANSIENT
            'name_id_format': [NAMEID_FORMAT_PERSISTENT,
                               NAMEID_FORMAT_TRANSIENT],

            'endpoints': {
                'assertion_consumer_service': [
                    ('%s/acs/' % BASE_URL, saml2.BINDING_HTTP_POST),
                    ],
                "single_logout_service": [
                    ("%s/ls/post/" % BASE_URL, saml2.BINDING_HTTP_POST),
                    ("%s/ls/" % BASE_URL, saml2.BINDING_HTTP_REDIRECT),
                ],
                }, # end endpoints

            # these only works using pySAML2 patched with this
            # https://github.com/IdentityPython/pysaml2/pull/597
            'signing_algorithm':  saml2.xmldsig.SIG_RSA_SHA256,
            'digest_algorithm':  saml2.xmldsig.DIGEST_SHA256,

            # Mandates that the identity provider MUST authenticate the
            # presenter directly rather than rely on a previous security context.
            "force_authn": True,
            'name_id_format_allow_create': False,

            # attributes that this project need to identify a user
            # 'required_attributes': ['email', 'username',
                                    # 'cn', 'sn', 'uid'],

            # attributes that may be useful to have but not required
            # 'optional_attributes': ['eduPersonAffiliation'],

            'want_response_signed': True,
            'authn_requests_signed': True,
            'logout_requests_signed': True,
            # Indicates that Authentication Responses to this SP must
            # be signed. If set to True, the SP will not consume
            # any SAML Responses that are not signed.
            'want_assertions_signed': True,

            'only_use_keys_in_metadata': True,

            # When set to true, the SP will consume unsolicited SAML
            # Responses, i.e. SAML Responses for which it has not sent
            # a respective SAML Authentication Request.
            'allow_unsolicited': False,

            # Permits to have attributes not configured in attribute-mappings
            # otherwise...without OID will be rejected
            'allow_unknown_attributes': True,

            # idp definition will be only in the metadata...

            # Since this is a very simple SP it only needs to know about
            # one IdP, therefore there is really no need for a metadata file
            # or a WAYF-function or anything like that. It needs the URL of the IdP and that’s all.:
            # "idp_url" : "{}/idp/SSOService.php".format(IDP_URL),

            # in this section the list of IdPs we talk to are defined
            # 'idp': {
              # we do not need a WAYF service since there is
              # only an IdP defined here. This IdP should be
              # present in our metadata

              # the keys of this dictionary are entity ids
              # '{}/metadata'.format(IDP_URL): {
                  # 'single_sign_on_service': {
                        # saml2.BINDING_HTTP_REDIRECT: '{}/sso/redirect'.format(IDP_URL),
                        # saml2.BINDING_HTTP_POST: '{}/sso/post'.format(IDP_URL),
                        # },
                  # 'single_logout_service': {
                        # saml2.BINDING_HTTP_REDIRECT: '{}/logout'.format(IDP_URL),
                        # },
                        # },
              # }, # end idp federation

            }, # end sp

    },

    # many metadata, many idp...
    'metadata': {
        'local': [

                  # os.path.join(os.path.join(os.path.join(BASE_DIR, 'saml2_sp'),
                  # 'saml2_config'), 'idp_metadata.xml'),

                  # os.path.join(os.path.join(os.path.join(BASE_DIR, 'saml2_sp'),
                  # 'saml2_config'), 'satosa_metadata.xml'),
                  ],
        #
        "remote": [{
            "url": "https://satosa.testunical.it/Saml2IDP/metadata",
            "cert": "/opt/satosa-saml2/pki/frontend.cert",
            "disable_ssl_certificate_validation": True,
            }],

        # "mdq": [{
            # "url": "https://ds.testunical.it",
            # "cert": "certficates/others/ds.testunical.it.cert",
            # "disable_ssl_certificate_validation": True,
            # }]

    },
    # avoids exception: HTTPSConnectionPool(host='satosa.testunical.it', port=443): Max retries exceeded with url: /idp/shibboleth (Caused by SSLError(SSLError("bad handshake: Error([('SSL routines', 'tls_process_server_certificate', 'certificate verify failed')],)",),))
    'ca_certs' : "/opt/satosa-saml2/pki/http_certificates/ca.crt",

    # Signing
    'key_file': BASE_DIR + '/certificates/private.key',
    'cert_file': BASE_DIR + '/certificates/public.cert',

    # Encryption
    'encryption_keypairs': [{
        'key_file': BASE_DIR + '/certificates/private.key',
        'cert_file': BASE_DIR + '/certificates/public.cert',
    }],

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
      'url': [('http://www.unical.it', 'it'), ('http://www.unical.it', 'en')],
      },

    'valid_for': 24 * 10,
}

# OR NAME_ID or MAIN_ATTRIBUTE (not together!)
SAML_USE_NAME_ID_AS_USERNAME = True
# SAML_DJANGO_USER_MAIN_ATTRIBUTE = 'email'
# SAML_DJANGO_USER_MAIN_ATTRIBUTE_LOOKUP = '__iexact'

SAML_CREATE_UNKNOWN_USER = True

# logout
SAML_LOGOUT_REQUEST_PREFERRED_BINDING = saml2.BINDING_HTTP_POST

SAML_ATTRIBUTE_MAPPING = {

    # django related
    # 'uid': ('username', ),

    # pure oid standard
    'email': ('email', ),
    'mail': ('email',),

    # oid pure
    'cn': ('first_name', ),
    'sn': ('last_name', ),
    'schacPersonalUniqueID': ('schacPersonalUniqueID',),
    'eduPersonPrincipalName': ('eduPersonPrincipalName',),
    'eduPersonEntitlement': ('eduPersonEntitlement',),
    'schacPersonalUniqueCode': ('schacPersonalUniqueCode',),

    # spid related
    'name': ('first_name', ),
    'familyName': ('last_name', ),
    'fiscalNumber': ('codice_fiscale',),
    'placeOfBirth': ('place_of_birth',),
    'dateOfBirth': ('birth_date',),

    # unical legacy fallback
    'codice_fiscale': ('codice_fiscale',),
}
