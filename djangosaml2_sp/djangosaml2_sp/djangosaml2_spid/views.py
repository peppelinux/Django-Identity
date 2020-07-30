import base64
import logging
import saml2

from django.conf import settings
from django.contrib.auth.models import User
from django.contrib.auth.decorators import login_required
from django.dispatch import receiver
from django.http import HttpResponse
from django.shortcuts import render
from django.template import TemplateDoesNotExist
from djangosaml2.conf import get_config
from djangosaml2.cache import IdentityCache, OutstandingQueriesCache
from djangosaml2.cache import StateCache
from djangosaml2.conf import get_config
from djangosaml2.overrides import Saml2Client
from djangosaml2.signals import post_authenticated, pre_user_save
from djangosaml2.utils import (
    available_idps, fail_acs_response, get_custom_setting,
    get_idp_sso_supported_bindings, get_location
)
from djangosaml2.views import finish_logout, _get_subject_id
from saml2 import BINDING_HTTP_REDIRECT, BINDING_HTTP_POST
from saml2.authn_context import requested_authn_context
from saml2.metadata import entity_descriptor

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
          authorization_error_template='djangosaml2/auth_error.html'):
    """SAML Authorization Request initiator

    This view initiates the SAML2 Authorization handshake
    using the pysaml2 library to create the AuthnRequest.
    It uses the SAML 2.0 Http POST protocol binding.
    """
    logger.debug('SPID Login process started')

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
        redirect_authenticated_user = getattr(settings,
                                              'SAML_IGNORE_AUTHENTICATED_USERS_ON_LOGIN',
                                              True)
        if redirect_authenticated_user:
            return HttpResponseRedirect(came_from)
        else:
            logger.debug('User is already logged in')
            return render(request, authorization_error_template, {
                    'came_from': came_from})

    # this works only if request came from wayf
    selected_idp = request.GET.get('idp', None)

    conf = get_config(config_loader_path, request)

    # is a embedded wayf needed?
    idps = available_idps(conf)
    if selected_idp is None and len(idps) > 1:
        logger.debug('A discovery process is needed')
        return render(request, wayf_template, {
                'available_idps': idps.items(),
                'came_from': came_from})
    else:
        # otherwise is the first one
        try:
            selected_idp = list(idps.keys())[0]
        except TypeError as e:
            logger.error('Unable to know which IdP to use')
            return HttpResponse(text_type(e))

    # choose a binding to try first
    # sign_requests = getattr(conf, '_sp_authn_requests_signed', False)

    binding = BINDING_HTTP_POST
    logger.debug('Trying binding %s for IDP %s', binding, selected_idp)

    # ensure our selected binding is supported by the IDP
    supported_bindings = get_idp_sso_supported_bindings(selected_idp, config=conf)
    if binding != BINDING_HTTP_POST:
            raise UnsupportedBinding('IDP %s does not support %s or %s',
                                     selected_idp, BINDING_HTTP_POST, BINDING_HTTP_REDIRECT)

    client = Saml2Client(conf)

    logger.debug('Redirecting user to the IdP via %s binding.', binding)
    # use the html provided by pysaml2 if no template was specified or it didn't exist
    # SPID want the fqdn of the IDP, not the SSO endpoint
    location_fixed = selected_idp
    location = client.sso_location(selected_idp, binding)
    # ...hope to see the SSO endpoint soon in spid-testenv2

    authn_req = saml2.samlp.AuthnRequest()
    authn_req.destination = location_fixed
    # spid-testenv2 preleva l'attribute consumer service dalla authnRequest (anche se questo sta già nei metadati...)
    authn_req.attribute_consuming_service_index = "0"

    # import pdb; pdb.set_trace()
    issuer = saml2.saml.Issuer()
    issuer.name_qualifier = client.config.entityid
    issuer.text = client.config.entityid
    issuer.format = "urn:oasis:names:tc:SAML:2.0:nameid-format:entity"
    authn_req.issuer = issuer

    # message id
    authn_req.id = saml2.s_utils.sid()
    authn_req.version = saml2.VERSION # "2.0"
    authn_req.issue_instant = saml2.time_util.instant()

    name_id_policy = saml2.samlp.NameIDPolicy()
    # del(name_id_policy.allow_create)
    name_id_policy.format = settings.SPID_NAMEID_FORMAT
    authn_req.name_id_policy  = name_id_policy

    authn_context = requested_authn_context(class_ref=settings.SPID_AUTH_CONTEXT)
    authn_req.requested_authn_context = authn_context

    authn_req.protocol_binding = settings.SPID_DEFAULT_BINDING

    assertion_consumer_service_url = client.config._sp_endpoints['assertion_consumer_service'][0][0]
    authn_req.assertion_consumer_service_url = assertion_consumer_service_url #'http://sp1.testunical.it:8000/saml2/acs/'

    authn_req_signed = client.sign(authn_req, sign_prepare=False,
                                   sign_alg=settings.SPID_ENC_ALG,
                                   digest_alg=settings.SPID_DIG_ALG)
    session_id = authn_req.id

    _req_str = authn_req_signed
    logger.debug('AuthRequest to {}: {}'.format(selected_idp, (_req_str)))
    http_info = client.apply_binding(binding,
                                     _req_str, location,
                                     sign=True,
                                     sigalg=settings.SPID_ENC_ALG)

    # success, so save the session ID and return our response
    logger.debug('Saving the session_id in the OutstandingQueries cache')
    oq_cache = OutstandingQueriesCache(request.session)
    oq_cache.set(session_id, came_from)
    return HttpResponse(http_info['data'])


@login_required
def spid_logout(request, config_loader_path=None, **kwargs):
    """SAML Logout Request initiator

    This view initiates the SAML2 Logout request
    using the pysaml2 library to create the LogoutRequest.
    """
    state = StateCache(request.session)
    conf = get_config(config_loader_path, request)

    client = Saml2Client(conf, state_cache=state,
                         identity_cache=IdentityCache(request.session))
    subject_id = _get_subject_id(request.session)
    if subject_id is None:
        logger.warning(
            'The session does not contain the subject id for user %s',
            request.user)
        logger.error("Looks like the user %s is not logged in any IdP/AA", subject_id)
        return HttpResponseBadRequest("You are not logged in any IdP/AA")

    slo_req = saml2.samlp.LogoutRequest()

    binding = settings.SPID_DEFAULT_BINDING
    location_fixed = subject_id.name_qualifier
    location = location_fixed
    slo_req.destination = location_fixed
    # spid-testenv2 preleva l'attribute consumer service dalla authnRequest (anche se questo sta già nei metadati...)
    slo_req.attribute_consuming_service_index = "0"

    # import pdb; pdb.set_trace()
    issuer = saml2.saml.Issuer()
    issuer.name_qualifier = client.config.entityid
    issuer.text = client.config.entityid
    issuer.format = "urn:oasis:names:tc:SAML:2.0:nameid-format:entity"
    slo_req.issuer = issuer

    # message id
    slo_req.id = saml2.s_utils.sid()
    slo_req.version = saml2.VERSION # "2.0"
    slo_req.issue_instant = saml2.time_util.instant()

    # oggetto
    slo_req.name_id = subject_id


    session_info = client.users.get_info_from(slo_req.name_id,
                                              subject_id.name_qualifier,
                                              False)
    session_indexes = [session_info['session_index']]

    # aggiungere session index
    if session_indexes:
        sis = []
        for si in session_indexes:
            if isinstance(si, saml2.samlp.SessionIndex):
                sis.append(si)
            else:
                sis.append(saml2.samlp.SessionIndex(text=si))
        slo_req.session_index = sis

    slo_req.protocol_binding = binding

    assertion_consumer_service_url = client.config._sp_endpoints['assertion_consumer_service'][0][0]
    slo_req.assertion_consumer_service_url = assertion_consumer_service_url

    slo_req_signed = client.sign(slo_req, sign_prepare=False,
                                 sign_alg=settings.SPID_ENC_ALG,
                                 digest_alg=settings.SPID_DIG_ALG)
    session_id = slo_req.id


    _req_str = slo_req_signed
    logger.debug('LogoutRequest to {}: {}'.format(subject_id.name_qualifier,
                                                  repr_saml(_req_str)))

    # get slo from metadata
    slo_location = None
    # for k,v in client.metadata.metadata.items():
        # idp_nq = v.entity.get(subject_id.name_qualifier)
        # if idp_nq:
            # slo_location = idp_nq['idpsso_descriptor'][0]['single_logout_service'][0]['location']

    slo_location = client.metadata.single_logout_service(subject_id.name_qualifier,
                                                         binding,
                                                         "idpsso")[0]['location']
    if not slo_location:
        logger.error('Unable to know SLO endpoint in {}'.format(subject_id.name_qualifier))
        return HttpResponse(text_type(e))

    http_info = client.apply_binding(binding,
                                     _req_str,
                                     slo_location,
                                     sign=True,
                                     sigalg=settings.SPID_ENC_ALG)

    state.sync()
    return HttpResponse(http_info['data'])


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

    # nameformat patch... tutto questo non rispecchia gli standard OASIS
    for reqattr in metadata.spsso_descriptor.attribute_consuming_service[0].requested_attribute:
        reqattr.name_format = None #"urn:oasis:names:tc:SAML:2.0:attrname-format:basic"
        # reqattr.is_required = None
        reqattr.friendly_name = None

    # remove unecessary encryption and digest algs
    supported_algs = ['http://www.w3.org/2009/xmldsig11#dsa-sha256',
                      'http://www.w3.org/2001/04/xmldsig-more#rsa-sha256']
    new_list = []
    for alg in metadata.extensions.extension_elements:
        # if alg.namespace != 'urn:oasis:names:tc:SAML:metadata:algsupport': continue
        if alg.attributes.get('Algorithm') in supported_algs:
            new_list.append(alg)
    metadata.extensions.extension_elements = new_list
    # ... Piuttosto non devo specificare gli algoritmi di firma/criptazione...
    metadata.extensions = None

    # attribute consuming service service name patch
    service_name = metadata.spsso_descriptor.attribute_consuming_service[0].service_name[0]
    service_name.lang = 'it'
    service_name.text = conf._sp_name

    return HttpResponse(content=text_type(metadata).encode('utf-8'),
                        content_type="text/xml; charset=utf8")
