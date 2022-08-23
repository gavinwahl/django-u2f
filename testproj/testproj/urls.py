from django.urls import include, re_path
from django.contrib import admin
from django.conf import settings

import django_u2f.urls

admin.autodiscover()

urlpatterns = [
    re_path(r'^u2f/', include(django_u2f.urls, namespace='u2f')),
    re_path(r'^admin/', admin.site.urls),
]

if settings.DEBUG:
    import debug_toolbar
    urlpatterns = [
        re_path(r'^__debug__/', include(debug_toolbar.urls)),
    ] + urlpatterns
