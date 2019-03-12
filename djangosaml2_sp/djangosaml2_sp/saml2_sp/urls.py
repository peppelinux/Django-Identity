from django.urls import include, path
from django.conf import settings
from django.contrib import admin
from django.contrib.auth.views import LogoutView
from . import views

urlpatterns = [
    path('', views.index),
    path('logout/', LogoutView.as_view(),
         {'next_page': settings.LOGOUT_REDIRECT_URL},
         name='logout'),
    path('saml2/', include('djangosaml2.urls')),
]
