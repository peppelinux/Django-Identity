import os
import saml2
from saml2.saml import (NAMEID_FORMAT_EMAILADDRESS,
                        NAMEID_FORMAT_TRANSIENT,
                        NAMEID_FORMAT_PERSISTENT
                        )
from saml2.sigver import get_xmlsec_binary

# Build paths inside the project like this: os.path.join(BASE_DIR, ...)
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

BASE_URL = 'http://sp.pysaml2.testunical.it:8000/saml2'
IDP_URL = 'https://idp.testunical.it/idp'

SAML_CONFIG = {
    'debug' : False,
    'xmlsec_binary': get_xmlsec_binary(['/opt/local/bin', '/usr/bin/xmlsec1']),
    'entityid': '%s/metadata/' % BASE_URL,

    'attribute_map_dir': os.path.join(os.path.join(os.path.join(BASE_DIR, 'saml2_sp'),
                                      'saml2_config'),
                                      'attribute-maps'),

    # affects saml2.mdstore ->
    # class MetadataStore(MetaData):
    # def __init__(self, attrc, config, ca_certs=None, check_validity=True, disable_ssl_certificate_validation=False, filter=None):
    # only to be used if metadata are downloaded and idp CA is private.
    # avoids exception: HTTPSConnectionPool(host='idp.testunical.it', port=443): Max retries exceeded with url: /idp/shibboleth (Caused by SSLError(SSLError("bad handshake: Error([('SSL routines', 'tls_process_server_certificate', 'certificate verify failed')],)",),))
    # 'disable_ssl_certificate_validation': True,
    'ca_certs' : os.path.join(BASE_DIR, 'certificates/shibidp', "testunical.it-cacert.pem"),

    # If True produces Exception: 'CertHandler' object has no attribute '_cert_handler_extra_class'
    # "validate_certificate" : True,

    # to be documented as previous one
    # "verify_encrypt_cert_advice" : False,
    # "verify_encrypt_cert_assertion" : False,
    # "verify_ssl_cert" : False,

    # study/check: saml2.sigver.security_context(conf, debug=None)
    # 'only_use_keys_in_metadata' : False,
    
    'service': {
        'sp': {
            'name': '%s/metadata/' % BASE_URL,

            # Disable cause of SAML1's
            # Profile Action AddNameIDToSubjects: Request specified use of an unsupportable identifier format: urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress
            # InvalidNameIDPolicy
            # 'name_id_format': [NAMEID_FORMAT_EMAILADDRESS],

            'name_id_format': [NAMEID_FORMAT_PERSISTENT, NAMEID_FORMAT_PERSISTENT],
                              # [NAMEID_FORMAT_TRANSIENT,
                               # NAMEID_FORMAT_PERSISTENT],
            
            'name_id_format_allow_create': True,
            
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
                                    'mail',
                                    'sn',
                                    'cn',
                                    'schacPersonalUniqueID'],
            
            # 'allow_unknown_attributes' : True,
            
            # PR https://github.com/IdentityPython/pysaml2/pull/495
            # requires saml2/config.py patch line 
            # 'authn_requests_signed_alg': 'sha512',

            # Mandates that the identity provider MUST authenticate the
            # presenter directly rather than rely on a previous security context.
            "force_authn": True,
            
            # attributes that may be useful to have but not required
            'optional_attributes': ['eduPersonAffiliation'],

            # Indicates if the Authentication Requests sent by this SP should be signed by default.
            # default value is True (POST METHOD will be used, if false GET method will be used)
            # Shibboleth SP send this not signed trough GET method by default
            'authn_requests_signed': False,

            # doesn't seems to be really loaded:
            "logout_requests_signed": True,
            
            # Indicates that Authentication Responses to this SP must be signed.
            # If set to True, the SP will not consume any SAML Responses that are not signed.
            # if both set to False pysaml2 will say: The SAML service provider accepts unsigned SAML Responses and Assertions. This configuration is insecure.
            # want_assertions_signed to False will let us work with idp self signed certs, it avoids xmlsec1 exception: func=xmlSecOpenSSLX509StoreVerify:file=x509vfy.c:line=408:obj=x509-store:subj=unknown:error=71:certificate verification failed:err=18;msg=self signed certificate
            'want_response_signed': True,
            'want_assertions_signed': True, # reference: https://github.com/IdentityPython/pysaml2/pull/485
            
            
            # When set to true, the SP will consume unsolicited SAML Responses,
            # i.e. SAML Responses for which it has not sent a respective SAML Authentication Request.
            # example, a page refresh after a POST from IDP, as unsolicitated will work
            'allow_unsolicited': False,

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
        # 'local': [os.path.join(os.path.join(os.path.join(BASE_DIR, 'saml2_sp'), 'saml2_config'), 'idp_metadata.xml')],
        #
        # ondemand
        "remote": [{
            "url": "{}/shibboleth".format(IDP_URL),
            # if self-signed must be globally defined also 'disable_ssl_certificate_validation': True, 
            "cert": BASE_DIR + "/certificates/shibidp/idp.testunical.it-cert.pem",
             }]
            
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
      {'given_name': 'YourName',
       'sur_name': 'YourSurname',
       'company': 'YourComapnyName',
       'email_address': 'user@email.com',
       'contact_type': 'technical'},
      {'given_name': 'otheruser',
       'sur_name': 'YourSurname',
       'company': 'YourComapnyName',
       'email_address': 'user@email.com',
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

# NAME_ID or MAIN_ATTRIBUTE (not together!)
SAML_USE_NAME_ID_AS_USERNAME = False
SAML_DJANGO_USER_MAIN_ATTRIBUTE = 'username'
SAML_DJANGO_USER_MAIN_ATTRIBUTE_LOOKUP = '__iexact'

SAML_CREATE_UNKNOWN_USER = True

SAML_ATTRIBUTE_MAPPING = {
    # SAML: DJANGO
    # Must also be present in attribute-maps!
    'uid': ('username',),
    'mail': ('email',),
    'givenName': ('first_name',),
    'sn': ('last_name',),
    'schacPersonalUniqueID': ('codice_fiscale',),
    'eduPersonPrincipalName' : ('matricola',),
    #'is_staff': ('is_staff', ),
    #'is_superuser':  ('is_superuser', ),
}
