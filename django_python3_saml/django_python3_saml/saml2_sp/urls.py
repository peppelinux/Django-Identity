from django.urls import include, path
from .views import attrs, index, metadata

urlpatterns = [
    path('', index, name='index'),
    path('attrs/', attrs, name='attrs'),
    path('metadata/', metadata, name='metadata'),
]
