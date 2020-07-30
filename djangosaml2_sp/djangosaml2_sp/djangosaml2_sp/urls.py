"""djangosaml2_sp URL Configuration

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/2.0/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  path('', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  path('', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.urls import include, path
    2. Add a URL to urlpatterns:  path('blog/', include('blog.urls'))
"""
from djangosaml2 import views

from django.conf import settings
from django.contrib import admin
from django.contrib.auth.views import LogoutView
from django.urls import include, path

urlpatterns = [
    path('admin/', admin.site.urls),
]

if 'saml2_sp' in settings.INSTALLED_APPS:
    import saml2_sp.urls
    saml2_url_prefix = 'saml2'

    urlpatterns += path('', include((saml2_sp.urls, 'sp',))),
    urlpatterns += path('{}/login/'.format(saml2_url_prefix),
                        views.login, name='saml2_login'),
    urlpatterns += path('{}/acs/'.format(saml2_url_prefix),
                        views.AssertionConsumerServiceView.as_view(), name='saml2_acs'),
    urlpatterns += path('{}/logout/'.format(saml2_url_prefix),
                        views.logout, name='saml2_logout'),
    urlpatterns += path('{}/ls/'.format(saml2_url_prefix),
                        views.logout_service, name='saml2_ls'),
    urlpatterns += path('{}/ls/post/'.format(saml2_url_prefix),
                        views.logout_service_post, name='saml2_ls_post'),
    urlpatterns += path('{}/metadata/'.format(saml2_url_prefix),
                        views.metadata, name='saml2_metadata'),
    urlpatterns += path('{}/echo_attributes'.format(saml2_url_prefix),
                        views.echo_attributes, name='saml2_echo_attributes'),

    # system local
    urlpatterns += path('logout/', LogoutView.as_view(),
                        {'next_page': settings.LOGOUT_REDIRECT_URL},
                        name='logout'),


if 'djangosaml2' in settings.INSTALLED_APPS:
    import djangosaml2.urls
    urlpatterns += path('', include((djangosaml2.urls, 'djangosaml2',))),

if 'djangosaml2_spid' in settings.INSTALLED_APPS:
    import djangosaml2_spid.urls
    urlpatterns += path('', include((djangosaml2_spid.urls, 'djangosaml2_spid',))),
