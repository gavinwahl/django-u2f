from django.urls import re_path

from . import views

app_name = 'u2f'

urlpatterns = [
    re_path(r'^add-key/', views.add_key, name='add-u2f-key'),
    re_path(r'^verify-second-factor/', views.verify_second_factor, name='verify-second-factor'),
    re_path(r'^login/', views.login, name='login'),
    re_path(r'^keys/', views.keys, name='u2f-keys'),
    re_path(r'^two-factor-settings/', views.two_factor_settings, name='two-factor-settings'),
    re_path(r'^backup-codes/', views.backup_codes, name='backup-codes'),
    re_path(r'^add-totp-device/', views.add_totp, name='add-totp'),
    re_path(r'^totp-devices/', views.totp_devices, name='totp-devices'),
]
