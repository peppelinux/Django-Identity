# stupid
import re
import requests

form_action_regex = '[\s\n.]*action="(?P<action>.*)" '
form_samlreq_regex = ('[\s\n.]*name="SAMLRequest" '
                      'value="(?P<value>.*)"[\s\n.]*')

target = 'https://peo.unical.it'
r = requests.Session()
sp_saml_request = r.get(target, verify=False)
html_content =  sp_saml_request.content.decode() \
                        if isinstance(sp_saml_request.content, bytes) \
                        else sp_saml_request.content

action = re.search(form_action_regex, html_content)
saml_request_dict = {}
saml_request_dict.update(action.groupdict())
saml_request = re.search(form_samlreq_regex, html_content)
saml_request_dict.update(saml_request.groupdict())

d = {'SAMLRequest': saml_request_dict['value'], 'RelayState': '/'}
idp_auth_form = r.post(saml_request_dict['action'], data=d)
assert idp_auth_form.status_code == 200
