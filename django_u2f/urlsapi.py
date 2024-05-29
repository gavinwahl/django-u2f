from django.urls import re_path

from . import views

app_name = 'u2f-api'

urlpatterns = [
    re_path(r'^add-key/', views.add_key_json, name='add-u2f-key'),
    re_path(r'^add-totp/', views.add_totp_json, name='add-totp'),
    re_path(r'^totp-devices/', views.totp_devices_json, name='totp-devices'),
    re_path(r'^keys/', views.keys_json, name='u2f-keys'),
    re_path(r'^verify/', views.verify_second_factor_json, name='verify'),
    re_path(r'^backup-codes/', views.backup_codes_json, name='backup-codes'),
]
