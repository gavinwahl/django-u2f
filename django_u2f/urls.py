from django.conf.urls import patterns, url

urlpatterns = patterns('django_u2f.views',
    url(r'^add-key/', 'add_key'),
    url(r'^verify-key/', 'verify_key'),
    url(r'^login/', 'login', name='login'),
    url(r'^keys/', 'keys'),
)
