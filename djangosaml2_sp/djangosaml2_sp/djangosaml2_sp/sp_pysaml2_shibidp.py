import os
import saml2
from saml2.saml import NAMEID_FORMAT_EMAILADDRESS
from saml2.sigver import get_xmlsec_binary

# Build paths inside the project like this: os.path.join(BASE_DIR, ...)
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

BASE_URL = 'http://sp.pysaml2.testunical.it/saml2'
IDP_URL = 'https://idp.testunical.it/idp'

SAML_CONFIG = {
    'debug' : True,
    'xmlsec_binary': get_xmlsec_binary(['/opt/local/bin', '/usr/bin/xmlsec1']),
    'entityid': '%s/metadata/' % BASE_URL,

    'attribute_map_dir': os.path.join(os.path.join(os.path.join(BASE_DIR, 'saml2_sp'),
                                      'saml2_config'),
                                      'attribute-maps'),
    'service': {
        'sp': {
            'name': '%s/metadata/' % BASE_URL,
            'name_id_format': [NAMEID_FORMAT_EMAILADDRESS],
            'endpoints': {
                #'artifact_resolution_service': []
                'assertion_consumer_service': [
                    ('%s/acs/' % BASE_URL, saml2.BINDING_HTTP_POST),
                    ],
                'single_logout_service': [
                    ('%s/ls/' % BASE_URL, saml2.BINDING_HTTP_REDIRECT),
                    ('%s/ls/post' % BASE_URL, saml2.BINDING_HTTP_POST),
                    ],
                }, # end endpoints

            # attributes that this project need to identify a user
            'required_attributes': ['uid',
                                    #'mail',
                                    'surname',
                                    'givenName',],
            
            # Mandates that the identity provider MUST authenticate the
            # presenter directly rather than rely on a previous security context.
            "force_authn": True,
            
            # attributes that may be useful to have but not required
            #'optional_attributes': ['eduPersonAffiliation'],

            'authn_requests_signed': True,
            'logout_requests_signed': True,
            
            # Indicates that Authentication Responses to this SP must be signed.
            # If set to True, the SP will not consume any SAML Responses that are not signed.
            'want_assertions_signed': True,
            
            # When set to true, the SP will consume unsolicited SAML Responses,
            # i.e. SAML Responses for which it has not sent a respective SAML Authentication Request.
            #'allow_unsolicited': True,

            # This kind of functionality is required for the eIDAS SAML profile.
            # eIDAS-Connectors SHOULD NOT provide AssertionConsumerServiceURL.
            # "hide_assertion_consumer_service": True,
            
            # Since this is a very simple SP it only needs to know about
            # one IdP, therefore there is really no need for a metadata
            # file or a WAYF-function or anything like that.
            # It needs the URL of the IdP and that’s all.:
            #"idp_url" : "{}/idp/SSOService.php".format(IDP_URL),
            
            # in this section the list of IdPs we talk to are defined
            'idp': {
              # we do not need a WAYF service since there is
              # only an IdP defined here. This IdP should be
              # present in our metadata
            
              # the keys of this dictionary are entity ids
              '{}/shibboleth'.format(IDP_URL): {
                  'single_sign_on_service': {
                        saml2.BINDING_HTTP_REDIRECT: '{}/login/process/'.format(IDP_URL),
                        },
                  'single_logout_service': {
                        saml2.BINDING_HTTP_REDIRECT: '{}/logout'.format(IDP_URL),
                        },
                        },
                    }, # end idp federation
            
            }, # end sp

    },

    # where the remote metadata is stored
    'metadata': {
        # To verify the authenticity of the file downloaded from the net, the local copy of the public key should be used.
        # This public key must be acquired by some out-of-band method.

        # Uses metadata files, both local and remote, and will talk to whatever IdP that appears in any of the metadata files.

        # wget -O idp_metadata.xml https://idp.testunical.it/idp/shibboleth
        'local': [os.path.join(os.path.join(os.path.join(BASE_DIR, 'saml2_sp'), 'saml2_config'), 'idp_metadata.xml')],
        #
        # ondemand
        # "remote": [{
            # "url": "{}/shibboleth".format(IDP_URL),
            # if self-signed
            # "cert": "/certificates/shibidp/idp-cert.pem"
            # }]
            
    },
    
    # Signing
    'key_file': BASE_DIR + '/certificates/shibidp/sp-key.pem',
    'cert_file': BASE_DIR + '/certificates/shibidp/sp-cert.pem',
    
    # Encryption
    'encryption_keypairs': [{
        'key_file': BASE_DIR + '/certificates/shibidp/sp-key.pem',
        'cert_file': BASE_DIR + '/certificates/shibidp/sp-cert.pem',
    }],

    # own metadata settings
    'contact_person': [
      {'given_name': 'Giuseppe',
       'sur_name': 'De Marco',
       'company': 'Universita della Calabria',
       'email_address': 'giuseppe.demarco@unical.it',
       'contact_type': 'technical'},
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

    'valid_for': 365 * 24, 
}

# OR NAME_ID or MAIN_ATTRIBUTE (not together!)
SAML_USE_NAME_ID_AS_USERNAME = True
# SAML_DJANGO_USER_MAIN_ATTRIBUTE = 'email'
# SAML_DJANGO_USER_MAIN_ATTRIBUTE_LOOKUP = '__iexact'

SAML_CREATE_UNKNOWN_USER = True

SAML_ATTRIBUTE_MAPPING = {
    # SAML: DJANGO
    # Must also be present in attribute-maps!
    # 'username': ( 'username', ),
    'email': ('mail', ),
    'first_name': ('givenName', ),
    'last_name': ('surname', ),
    'matricola': ('uid',),
    'codice_fiscale': ('eduPersonUniqueId',),
    #'is_staff': ('is_staff', ),
    #'is_superuser':  ('is_superuser', ),
}
