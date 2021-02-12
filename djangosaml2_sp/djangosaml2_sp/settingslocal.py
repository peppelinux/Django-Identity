from djangosaml2_spid.settings import *
from djangosaml2_spid.settings import SAML_CONFIG, SPID_DEFAULT_BINDING, saml2


BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BASE = 'http://hostnet:8000'
BASE_URL = '{}/saml2'.format(BASE)

SPID_CONTACTS = [
    {
        'contact_type': 'billing',
        'telephone_number': '+39 84756344785',
        'email_address': 'info@example.org',
        'company': 'example s.p.a.',
        # 'CodiceFiscale': 'NGLMRA80A01D086T',
        'IdCodice': '983745349857',
        'IdPaese': 'IT',
        'Denominazione': 'Destinatario Fatturazione',
        'Indirizzo': 'via tante cose',
        'NumeroCivico': '12',
        'CAP': '87100',
        'Comune': 'Cosenza',
        'Provincia': 'CS',
        'Nazione': 'IT',
    },
]

SAML_CONFIG.update({
    'entityid': f'{BASE_URL}/metadata/',
    'metadata': {
        "remote": [
            {
                'name': 'spid-testenv2',
                'url': 'http://hostnet:8088/metadata'
            },
            # {
            #     'name': 'spid-saml-check',
            #     'url': 'http://hostnet:8080/metadata.xml'
            # },
        ]
    },

    # Signing
    'key_file': f'{BASE_DIR}/certificates/private.key',
    'cert_file': f'{BASE_DIR}/certificates/public.cert',

    # Encryption
    'encryption_keypairs': [{
        'key_file': f'{BASE_DIR}/certificates/private.key',
        'cert_file': f'{BASE_DIR}/certificates/public.cert',
    }],

    # you can set multilanguage information here
    'organization': {
        'name': [('Example', 'it'), ('Example', 'en')],
        'display_name': [('Example', 'it'), ('Example', 'en')],
        'url': [('http://www.example.it', 'it'), ('http://www.example.it', 'en')],
    },
})

SAML_CONFIG['service']['sp'].update({
    'name': f'{BASE_URL}/metadata/',
    'name_qualifier': BASE,
    'endpoints': {
        'assertion_consumer_service': [
            (f'{BASE_URL}/acs/', SPID_DEFAULT_BINDING),
        ],
        'single_logout_service': [
            (f'{BASE_URL}/ls/post/', saml2.BINDING_HTTP_POST),
            (f'{BASE_URL}/ls/', saml2.BINDING_HTTP_REDIRECT),
        ],
    },
})
