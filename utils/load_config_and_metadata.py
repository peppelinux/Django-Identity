import copy
import os

from django.conf import settings
from djangosaml2idp.utils import repr_saml
from saml2.attribute_converter import ac_factory
from saml2.config import IdPConfig
from saml2.mdstore import MetadataStore
from saml2.metadata import entity_descriptor

try:
    BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
except:
    BASE_DIR = os.getcwd()
    print('BASE_DIR is', BASE_DIR)
conf = IdPConfig()

# conf.load_file("idp_conf_mdb")
conf.load(copy.deepcopy(settings.SAML_IDP_CONFIG))

for i in conf.__dict__.items(): print(i)

# generate metadata
idp_metadata = entity_descriptor(conf)
# print metadata
print(repr_saml(idp_metadata.__str__()))


# load sp metadata from FILE
attr_conv = '' # void

mds = MetadataStore('', conf, disable_ssl_certificate_validation=True)
# Import metadata from local file.
sp1_fpath = (os.path.join(os.path.join(os.path.join(BASE_DIR, 'idp'),
                          'saml2_config'), 'sp_metadata.xml'), )

mds.imp([{"class": "saml2.mdstore.MetaDataFile",
          "metadata": [sp1_fpath,
                     # (full_path("metadata_sp_2.xml"), ),]
                      ]
          }])

# navigate mds
sp_md = mds.metadata[sp1_fpath[0]]
# metadata as dict
sp_md.entity
# sp entity_id as string
sp_entity_id = sp_md.entity_descr.entity_id


# metadata checks
# def check_valid_until(xmlstring):

# see. https://github.com/IdentityPython/pysaml2/blob/master/tests/test_30_mdstore.py

# def test_metadata_file():
    # sec_config.xmlsec_binary = sigver.get_xmlsec_binary(["/opt/local/bin"])
    # mds = MetadataStore(ATTRCONV, sec_config,
                        # disable_ssl_certificate_validation=True)

    # mds.imp(METADATACONF["8"])
    # print(len(mds.keys()))
    # assert len(mds.keys()) == 560

    
# use MDQ
import copy
import os

from django.conf import settings
from djangosaml2idp.utils import repr_saml
from saml2.attribute_converter import ac_factory
from saml2.config import IdPConfig
from saml2.mdstore import MetadataStore, MetaDataMDX
from saml2.metadata import entity_descriptor

try:
    BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
except:
    BASE_DIR = os.getcwd()
    print('BASE_DIR is', BASE_DIR)
conf = IdPConfig()

# conf.load_file("idp_conf_mdb")
conf.load(copy.deepcopy(settings.SAML_IDP_CONFIG))

mdx = MetaDataMDX("https://ds.testunical.it") 
sso_loc = mdx.service("https://sp1.testunical.it/saml2/metadata", "spsso_descriptor", 'assertion_consumer_service')
mdx.certs("https://sp1.testunical.it/saml2/metadata", "spsso", use="signing")

mdx.service("https://idp1.testunical.it/idp/metadata", 'idpsso', 'sso_service')
mdx.certs("https://idp1.testunical.it/idp/metadata", "idpsso", use="encryption")  
