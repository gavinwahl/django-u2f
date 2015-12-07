from django.conf.urls import patterns, include, url
from django.contrib import admin

admin.autodiscover()

urlpatterns = [
    url(r'^u2f/', include('django_u2f.urls', 'u2f')),
    url(r'^admin/', include(admin.site.urls)),
]
