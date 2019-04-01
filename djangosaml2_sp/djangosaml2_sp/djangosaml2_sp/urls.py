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
from django.conf import settings
from django.contrib import admin
from django.urls import include, path

from saml2_sp.views import metadata_spid

urlpatterns = [
    path('admin/', admin.site.urls),
]

if 'saml2_sp' in settings.INSTALLED_APPS:
    import saml2_sp.urls
    urlpatterns += path('', include((saml2_sp.urls, 'sp',))),
    # patched metadata for spid
    urlpatterns += path('spid/metadata', metadata_spid, name='spid_metadata'),
