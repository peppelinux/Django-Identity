import base64
import requests
import saml2

from saml2 import saml, BINDING_HTTP_POST

from django.test.client import RequestFactory
from djangosaml2.conf import get_config
from djangosaml2.overrides import Saml2Client
from djangosaml2.utils import available_idps


# SP init
#########
conf = get_config(None)
client = Saml2Client(conf)
# just needed to initialize the MetadataStore - it automatically fetches remote idp's metadata
configured_idps = available_idps(conf)


# Arguments needed to create an Attribute query
###############################################
message_id = 'MSG_ID1'
entityid = "http://idp1.testunical.it:9000/idp/aa/metadata"
destination = "http://idp1.testunical.it:9000/aap"
subject_id = "E8042FB4-4D5B-48C3-8E14-8EDD852790DD"
attributes = {
    ('urn:oasis:names:tc:SAML:attribute:pairwise-id',
     "urn:oasis:names:tc:SAML:2.0:attrname-format:uri"): "spidCode-3242342342@idp.spid.it",
    ("fiscalCode",
     "urn:oasis:names:tc:SAML:2.0:attrname-format:basic"): "TIN-SDF7SD89F7SD98F",
    ("email",
     "urn:oasis:names:tc:SAML:2.0:attrname-format:basic",
     "email"): None,
}


# Create an Authoritative, signed, Attribute Query -> xml
req_id, saml_req = client.create_attribute_query(
            destination,
            subject_id,
            
            # if I use attribute as argument using the official pysaml2 release
            # a saml2.response.IncorrectlySigned Exception will raise 
            # use pplnx's pysaml2-aa fork instead, it will correctly validate signature idp-aa-side
            attribute=attributes,
            
            consent=True,
            format=saml.NAMEID_FORMAT_TRANSIENT,
            message_id=message_id,
            # sign=True,
            # sign_alg=saml2.xmldsig.SIG_RSA_SHA256,
            # digest_alg=saml2.xmldsig.DIGEST_SHA256
)

data = {'SAMLRequest' : base64.b64encode(saml_req.encode())}
headers = {'User-Agent': 'Mozilla/5.0'}
req = requests.post('http://idp1.testunical.it:9000/aap/', data=data, headers=headers)



# create request with html form in HTTP-POST
request = client.do_attribute_query(
        entityid,
        subject_id,
        attribute=attributes,
        # sp_name_qualifier=None,
        # name_qualifier=None,
        nameid_format=saml.NAMEID_FORMAT_TRANSIENT,
        # real_id=None,
        # consent=None,
        # extensions=None,
        sign=True,
        binding=BINDING_HTTP_POST,
        # nsprefix=None,
        # sign_alg=None,
        # digest_alg=None,
)
