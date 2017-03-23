from django.conf.urls import include, url
from django.contrib import admin

import django_u2f.urls

admin.autodiscover()

urlpatterns = [
    url(r'^u2f/', include(django_u2f.urls, namespace='u2f')),
    url(r'^admin/', include(admin.site.urls)),
]
