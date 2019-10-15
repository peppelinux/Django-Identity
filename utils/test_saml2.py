import re
import requests


form_action_regex = '[\s\n.]*action="(?P<action>[a-zA-Z0-9\:\.\_\-\?\&\/]*)"'
# TODO: make single regexp
form_samlreq_regex = '[\s\n.]*name="SAMLRequest"'
form_samlreq_value_regex = 'value="(?P<value>[a-zA-Z0-9+]*)"[\s\n.]*'

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
        print(request.reason)
        assert request.status_code == 200

    def _handle_error(self, info):
        raise Exception(('Error: Cannot find any saml request '
                         'value in {}').format(info))

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
        if not action: self._handle_error(target)
        self.saml_request_dict.update(action.groupdict())

        saml_request = re.search(form_samlreq_regex, html_content)
        if not saml_request: self._handle_error(target)
        self.saml_request_dict.update(saml_request.groupdict())

        saml_request_value = re.search(form_samlreq_value_regex, html_content)
        self.saml_request_dict.update(saml_request_value.groupdict())

        if self.debug:
            print(self.saml_request_dict)

    def saml_request_post(self):
        d = {'SAMLRequest': self.saml_request_dict['value'],
             'RelayState': '/'}
        idp_auth_form = self.session.post(self.saml_request_dict['action'],
                                          data=d)
        self._check_response(idp_auth_form)


if __name__ == '__main__':
    import argparse
    _description = 'test_saml2.py -target "https://peo.unical.it" --check-cert'
    parser = argparse.ArgumentParser(description=_description,
                                     epilog='Usage example: ')

    # parameters
    parser.add_argument('-target', required=True,
                        help=("service provider protected resource. "
                              "Used to be redirected to the IdP login page"))
    parser.add_argument('-u', required=False,
                        help="username")
    parser.add_argument('-p', required=False,
                    help="password")
    parser.add_argument('--wayf', action='store_true',
                        help=("if the url contains the wayf selection, es: "
                              "https://elearning.unical.it/Shibboleth.sso/Login?"
                              "providerId=https://idp.unical.it/idp/shibboleth"
                              "&target=https://elearning.unical.it/auth/shibboleth/index.php"),
                        required=False,
                        default=False)
    parser.add_argument('--check-cert', action='store_true',
                        help="validate https TLS certificates", required=False,
                        default=False)
    parser.add_argument('-debug', action='store_true',
                        help="print debug informations", required=False)
    args = parser.parse_args()

    # let's go
    ua = Saml2SPAuth(wayf=args.wayf, verify=args.check_cert, debug=args.debug)
    ua.saml_request(target=args.target)
    if not ua.wayf:
        ua.saml_request_post()
