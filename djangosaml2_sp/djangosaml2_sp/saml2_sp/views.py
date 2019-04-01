import base64
import logging

from django.conf import settings
from django.contrib.auth.models import User
from django.dispatch import receiver
from django.http import HttpResponse
from django.shortcuts import render
from django.template import TemplateDoesNotExist
from django.utils.six import text_type, binary_type
from djangosaml2.conf import get_config
from djangosaml2.cache import IdentityCache, OutstandingQueriesCache
from djangosaml2.cache import StateCache
from djangosaml2.conf import get_config
from djangosaml2.overrides import Saml2Client
from djangosaml2.signals import post_authenticated, pre_user_save
from djangosaml2.utils import (
    available_idps, fail_acs_response, get_custom_setting,
    get_idp_sso_supported_bindings, get_location, is_safe_url_compat,
)
from saml2 import BINDING_HTTP_REDIRECT, BINDING_HTTP_POST
from saml2.metadata import entity_descriptor
from saml2.xmldsig import SIG_RSA_SHA1, SIG_RSA_SHA256

from .utils import repr_saml


logger = logging.getLogger('djangosaml2')


def index(request):
    """ Barebone 'diagnostics' view, print user attributes if logged in + login/logout links.
    """
    if request.user.is_authenticated:
        out = "LOGGED IN: <a href={0}>LOGOUT</a><br>".format(settings.LOGOUT_URL)
        out += "".join(['%s: %s</br>' % (field.name, getattr(request.user, field.name))
                    for field in request.user._meta.get_fields()
                    if field.concrete])
        return HttpResponse(out)
    else:
        return HttpResponse("LOGGED OUT: <a href={0}>LOGIN</a>".format(settings.LOGIN_URL))


# TODO fix this in IdP side?
@receiver(pre_user_save, sender=User)
def custom_update_user(sender, instance, attributes, user_modified, **kargs):
    """ Default behaviour does not play nice with booleans encoded in SAML as u'true'/u'false'.
        This will convert those attributes to real booleans when saving.
    """
    for k, v in attributes.items():
        u = set.intersection(set(v), set([u'true', u'false']))
        if u:
            setattr(instance, k, u.pop() == u'true')
    return True  # I modified the user object


def spid_login(request,
          config_loader_path=None,
          wayf_template='djangosaml2/wayf.html',
          authorization_error_template='djangosaml2/auth_error.html',
          post_binding_form_template='djangosaml2/post_binding_form.html'):
    """SAML Authorization Request initiator

    This view initiates the SAML2 Authorization handshake
    using the pysaml2 library to create the AuthnRequest.
    It uses the SAML 2.0 Http Redirect protocol binding.

    * post_binding_form_template - path to a template containing HTML form with
    hidden input elements, used to send the SAML message data when HTTP POST
    binding is being used. You can customize this template to include custom
    branding and/or text explaining the automatic redirection process. Please
    see the example template in
    templates/djangosaml2/example_post_binding_form.html
    If set to None or nonexistent template, default form from the saml2 library
    will be rendered.
    """
    logger.debug('Login process started')

    came_from = request.GET.get('next', settings.LOGIN_REDIRECT_URL)
    if not came_from:
        logger.warning('The next parameter exists but is empty')
        came_from = settings.LOGIN_REDIRECT_URL

    # Ensure the user-originating redirection url is safe.
    if not is_safe_url_compat(url=came_from, allowed_hosts={request.get_host()}):
        came_from = settings.LOGIN_REDIRECT_URL

    # if the user is already authenticated that maybe because of two reasons:
    # A) He has this URL in two browser windows and in the other one he
    #    has already initiated the authenticated session.
    # B) He comes from a view that (incorrectly) send him here because
    #    he does not have enough permissions. That view should have shown
    #    an authorization error in the first place.
    # We can only make one thing here and that is configurable with the
    # SAML_IGNORE_AUTHENTICATED_USERS_ON_LOGIN setting. If that setting
    # is True (default value) we will redirect him to the came_from view.
    # Otherwise, we will show an (configurable) authorization error.
    if callable(request.user.is_authenticated):
        redirect_authenticated_user = getattr(settings, 'SAML_IGNORE_AUTHENTICATED_USERS_ON_LOGIN', True)
        if redirect_authenticated_user:
            return HttpResponseRedirect(came_from)
        else:
            logger.debug('User is already logged in')
            return render(request, authorization_error_template, {
                    'came_from': came_from,
                    })

    selected_idp = request.GET.get('idp', None)
    conf = get_config(config_loader_path, request)

    # is a embedded wayf needed?
    idps = available_idps(conf)
    if selected_idp is None and len(idps) > 1:
        logger.debug('A discovery process is needed')
        return render(request, wayf_template, {
                'available_idps': idps.items(),
                'came_from': came_from,
                })

    # choose a binding to try first
    sign_requests = getattr(conf, '_sp_authn_requests_signed', False)
    binding = BINDING_HTTP_POST if sign_requests else BINDING_HTTP_REDIRECT
    logger.debug('Trying binding %s for IDP %s', binding, selected_idp)

    # ensure our selected binding is supported by the IDP
    supported_bindings = get_idp_sso_supported_bindings(selected_idp, config=conf)
    if binding != BINDING_HTTP_POST:
            raise UnsupportedBinding('IDP %s does not support %s or %s',
                                     selected_idp, BINDING_HTTP_POST, BINDING_HTTP_REDIRECT)

    client = Saml2Client(conf)

    logger.debug('Redirecting user to the IdP via %s binding.', binding)
    # use the html provided by pysaml2 if no template was specified or it didn't exist
    try:
        location_fixed = 'http://idpspid.testunical.it:8088'
        location = client.sso_location(selected_idp, binding)
        session_id, request_xml = client.create_authn_request(
                                                        location_fixed,
                                                        binding=binding)

        print(repr_saml(request_xml))
        _req_str = request_xml
        http_info = client.apply_binding(binding, _req_str, location,
                                         sign=True, sigalg=SIG_RSA_SHA256)

    except TypeError as e:
        logger.error('Unable to know which IdP to use')
        return HttpResponse(text_type(e))
    else:
        http_response = HttpResponse(http_info['data'])

    # success, so save the session ID and return our response
    logger.debug('Saving the session_id in the OutstandingQueries cache')
    oq_cache = OutstandingQueriesCache(request.session)
    oq_cache.set(session_id, came_from)
    return http_response


def metadata_spid(request, config_loader_path=None, valid_for=None):
    """Returns an XML with the SAML 2.0 metadata for this
    SP as configured in the settings.py file.
    """
    conf = get_config(config_loader_path, request)
    metadata = entity_descriptor(conf)

    # this will renumber acs starting from 0 and set index=0 as is_default
    cnt = 0
    for attribute_consuming_service in metadata.spsso_descriptor.attribute_consuming_service:
        attribute_consuming_service.index = str(cnt)
        cnt += 1

    cnt = 0
    for assertion_consumer_service in metadata.spsso_descriptor.assertion_consumer_service:
        assertion_consumer_service.is_default = 'true' if not cnt else ''
        assertion_consumer_service.index = str(cnt)
        cnt += 1

    # nameformat patch
    for reqattr in metadata.spsso_descriptor.attribute_consuming_service[0].requested_attribute:
        reqattr.name_format = "urn:oasis:names:tc:SAML:2.0:attrname-format:basic"

    # remove unecessary encryption and digest algs
    supported_algs = ['http://www.w3.org/2009/xmldsig11#dsa-sha256',
                      'http://www.w3.org/2001/04/xmldsig-more#rsa-sha256']
    new_list = []
    for alg in metadata.extensions.extension_elements:
        # if alg.namespace != 'urn:oasis:names:tc:SAML:metadata:algsupport': continue
        if alg.attributes.get('Algorithm') in supported_algs:
            new_list.append(alg)
    metadata.extensions.extension_elements = new_list
    # non devo specificare gli algoritmi di firma/criptazione...
    metadata.extensions = None

    # attribute consuming service service name patch
    service_name = metadata.spsso_descriptor.attribute_consuming_service[0].service_name[0]
    service_name.lang = 'it'
    service_name.text = "Nome del servizio"

    return HttpResponse(content=text_type(metadata).encode('utf-8'),
                        content_type="text/xml; charset=utf8")
