import os
import saml2
from saml2.saml import (NAMEID_FORMAT_PERSISTENT,
                        NAMEID_FORMAT_TRANSIENT,
                        NAMEID_FORMAT_UNSPECIFIED)
from saml2.sigver import get_xmlsec_binary

# Build paths inside the project like this: os.path.join(BASE_DIR, ...)
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

BASE = 'http://sp2.testunical.it:8000'
BASE_URL = '{}/saml2'.format(BASE)

LOGIN_URL = '/spid/login/'
LOGOUT_URL = '/saml2/logout/'

SPID_DEFAULT_BINDING = saml2.BINDING_HTTP_POST
SPID_DIG_ALG = saml2.xmldsig.DIGEST_SHA256
SPID_SIGN_ALG = saml2.xmldsig.SIG_RSA_SHA256
SPID_NAMEID_FORMAT = NAMEID_FORMAT_TRANSIENT
SPID_AUTH_CONTEXT = 'https://www.spid.gov.it/SpidL1'

SAML_CONFIG = {
    'debug' : True,
    'xmlsec_binary': get_xmlsec_binary(['/opt/local/bin',
                                        '/usr/bin/xmlsec1']),
    'entityid': '%s/metadata/' % BASE_URL,

    'attribute_map_dir': os.path.join(os.path.join(os.path.join(BASE_DIR,
                                                                'djangosaml2_spid'),
                                      'saml2_config/'),
                                      'attribute-maps'),

    'service': {
        'sp': {
            'name': '%s/metadata/' % BASE_URL,

            'name_qualifier': BASE,
            # SPID needs NAMEID_FORMAT_TRANSIENT
            'name_id_format': [SPID_NAMEID_FORMAT],

            'endpoints': {
                'assertion_consumer_service': [
                    ('%s/acs/' % BASE_URL, SPID_DEFAULT_BINDING),
                    ],
                "single_logout_service": [
                    ("%s/ls/post/" % BASE_URL, saml2.BINDING_HTTP_POST),
                    ("%s/ls/" % BASE_URL, saml2.BINDING_HTTP_REDIRECT),
                ],
                }, # end endpoints

            # Mandates that the identity provider MUST authenticate the
            # presenter directly rather than rely on a previous security context.
            "force_authn": False, # SPID
            'name_id_format_allow_create': False,

            # attributes that this project need to identify a user
            'required_attributes': ['spidCode',
                                    'name',
                                    'familyName',
                                    'fiscalNumber',
                                    'email'],

            # this are formaly correct but in pySAML4.7 it doesn't make sense because with SPID they doesn't work properly
            # as spid-testenv2 doesn't sent in AuthnRequest the attribute format and pySAML2 manage these as URI!
            #'requested_attribute_name_format': saml2.saml.NAME_FORMAT_BASIC,
            #'name_format': saml2.saml.NAME_FORMAT_BASIC,
            #

            # attributes that may be useful to have but not required
            # 'optional_attributes': ['gender',
                                    # 'companyName',
                                    # 'registeredOffice',
                                    # 'ivaCode',
                                    # 'idCard',
                                    # 'digitalAddress',
                                    # 'placeOfBirth',
                                    # 'countyOfBirth',
                                    # 'dateOfBirth',
                                    # 'address',
                                    # 'mobilePhone',
                                    # 'expirationDate'],

            'authn_requests_signed': True,
            'logout_requests_signed': True,
            # Indicates that Authentication Responses to this SP must
            # be signed. If set to True, the SP will not consume
            # any SAML Responses that are not signed.
            'want_assertions_signed': True,

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
        # 'local': [os.path.join(os.path.join(os.path.join(BASE_DIR, 'djangosaml2_spid'),
                  # 'saml2_config'), 'idp_metadata.xml'),
                  # os.path.join(os.path.join(os.path.join(BASE_DIR, 'saml2_sp'),
                  # 'saml2_config'), 'idp_metadata.xml'),
                  # other here...
                  # ],
        #
        "remote": [{
            "url": "http://localhost:8080/metadata.xml",
            # "cert":"idp_https_cert.pem"}]
            }]
    },

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
}

# OR NAME_ID or MAIN_ATTRIBUTE (not together!)
SAML_USE_NAME_ID_AS_USERNAME = True
# SAML_DJANGO_USER_MAIN_ATTRIBUTE = 'email'
SAML_DJANGO_USER_MAIN_ATTRIBUTE_LOOKUP = '__iexact'

SAML_CREATE_UNKNOWN_USER = True

# logout
SAML_LOGOUT_REQUEST_PREFERRED_BINDING = saml2.BINDING_HTTP_POST

SAML_ATTRIBUTE_MAPPING = {
    ## 'uid': ('username', ),
    'email': ('email', ),
    'name': ('first_name', ),
    'familyName': ('last_name', ),
    'fiscalNumber': ('codice_fiscale',),
    'placeOfBirth': ('place_of_birth',),
    'dateOfBirth': ('birth_date',),
}
