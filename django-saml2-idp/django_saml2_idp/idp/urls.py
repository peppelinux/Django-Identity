from django.urls import include, path
from django.contrib import admin
from django.contrib.auth.views import LoginView

import djangosaml2idp

urlpatterns = [
    path('idp/', include('djangosaml2idp.urls')),
]
