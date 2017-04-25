from django.conf.urls import include, url
from django.contrib import admin
from django.conf import settings

import django_u2f.urls

admin.autodiscover()

urlpatterns = [
    url(r'^u2f/', include(django_u2f.urls, namespace='u2f')),
    url(r'^admin/', include(admin.site.urls)),
]

if settings.DEBUG:
    import debug_toolbar
    urlpatterns = [
        url(r'^__debug__/', include(debug_toolbar.urls)),
    ] + urlpatterns
