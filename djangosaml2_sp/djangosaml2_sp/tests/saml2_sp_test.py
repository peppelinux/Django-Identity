import re
import requests


form_action_regex = '[\s\n.]*action="(?P<action>.*)" '
# TODO: make single regexp
form_samlreq_regex = ('[\s\n.]*name="SAMLRequest" '
                      'value="(?P<value>.*)"[\s\n.]*')
# TODO: add RelayState
#  <input type="hidden" name="RelayState" value="/"/>


class Saml2SPAuth(object):
    """https://wiki.geant.org/display/eduGAIN/eduGAIN+Connectivity+Check
    """
    def __init__(self, wayf=False, verify=False, debug=False):
        # create an user agent here ;)
        self.session = requests.Session()
        self.wayf = wayf
        self.debug = debug
        self.verify = verify
        # to be filled
        self.saml_request_dict = {}

    def _check_response(self, request):
        assert request.status_code == 200
        print(request.reason)

    def saml_request(self, target,
                     form_action_regex=form_action_regex,
                     form_samlreq_regex=form_samlreq_regex):
        # do a GET, do not verify ssl cert validity
        sp_saml_req_form = self.session.get(target, verify=self.verify)
        if not sp_saml_req_form.ok:
            raise ('SP SAML Request Failed')

        html_content =  sp_saml_req_form._content.decode() \
                        if isinstance(sp_saml_req_form._content, bytes) \
                        else sp_saml_req_form._content

        if self.wayf:
            self._check_response(sp_saml_req_form)
            return

        action = re.search(form_action_regex, html_content)
        if not action:
            raise Exception(('Error: Cannot find any saml request '
                             'form in {}').format(target))
        self.saml_request_dict.update(action.groupdict())

        saml_request = re.search(form_samlreq_regex, html_content)
        if not saml_request:
            raise Exception(('Error: Cannot find any saml request '
                             'value in {}').format(target))
        self.saml_request_dict.update(saml_request.groupdict())

    def saml_request_post(self):
        if self.wayf: return
        d = {'SAMLRequest': self.saml_request_dict['value'],
             'RelayState': '/'}
        idp_auth_form = self.session.post(self.saml_request_dict['action'],
                                          data=d)
        self._check_response(idp_auth_form)


if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser()

    # parameters
    parser.add_argument('-target', required=True,
                        help=("service provider protected resource. "
                              "Used to be redirected to the IdP login page"))
    parser.add_argument('-u', required=False,
                        help="username")
    parser.add_argument('-p', required=False,
                    help="password")
    parser.add_argument('--wayf', action='store_true',
                        help="TODO", required=False,
                        default=False)
    parser.add_argument('--check-cert', action='store_true',
                        help="validate https TLS certificates", required=False,
                        default=False)
    parser.add_argument('-debug', action='store_true',
                        help="print debug informations", required=False)
    args = parser.parse_args()

    # let's go
    ua = Saml2SPAuth(wayf=args.wayf, verify=args.check_cert)
    ua.saml_request(target=args.target)
    ua.saml_request_post()


# stupid
# import re
# import requests

# form_action_regex = '[\s\n.]*action="(?P<action>.*)" '
# form_samlreq_regex = ('[\s\n.]*name="SAMLRequest" '
                      # 'value="(?P<value>.*)"[\s\n.]*')

# target = 'https://peo.unical.it'
# r = requests.Session()
# sp_saml_request = r.get(target, verify=False)
# html_content =  sp_saml_request.content.decode() \
                        # if isinstance(sp_saml_request.content, bytes) \
                        # else sp_saml_request.content

# action = re.search(form_action_regex, html_content)
# saml_request_dict = {}
# saml_request_dict.update(action.groupdict())
# saml_request = re.search(form_samlreq_regex, html_content)
# saml_request_dict.update(saml_request.groupdict())

# d = {'SAMLRequest': saml_request_dict['value'], 'RelayState': '/'}
# idp_auth_form = r.post(saml_request_dict['action'], data=d)
# assert idp_auth_form.status_code == 200
