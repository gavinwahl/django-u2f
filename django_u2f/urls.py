from django.conf.urls import url

from . import views

app_name = 'u2f'

urlpatterns = [
    url(r'^add-key/', views.add_key, name='add-u2f-key'),
    url(r'^verify-second-factor/', views.verify_second_factor, name='verify-second-factor'),
    url(r'^login/', views.login, name='login'),
    url(r'^keys/', views.keys, name='u2f-keys'),
    url(r'^two-factor-settings/', views.two_factor_settings, name='two-factor-settings'),
    url(r'^backup-codes/', views.backup_codes, name='backup-codes'),
    url(r'^add-totp-device/', views.add_totp, name='add-totp'),
    url(r'^totp-devices/', views.totp_devices, name='totp-devices'),
]
