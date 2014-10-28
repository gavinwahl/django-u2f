from django.conf.urls import patterns, include, url

urlpatterns = patterns('',
    url(r'^u2f/', include('django_u2f.urls')),
)
