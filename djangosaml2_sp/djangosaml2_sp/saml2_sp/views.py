from django.conf import settings
from django.contrib.auth.models import User
from django.dispatch import receiver
from django.http import HttpResponse
from django.utils.six import text_type
from djangosaml2.conf import get_config
from djangosaml2.signals import pre_user_save
from saml2.metadata import entity_descriptor


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

    return HttpResponse(content=text_type(metadata).encode('utf-8'),
                        content_type="text/xml; charset=utf8")
