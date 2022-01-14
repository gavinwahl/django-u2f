import os
import re
import json
import string
import datetime
from base64 import b32decode
from six import StringIO
import unittest

from django.test import TestCase, Client
from django.urls import reverse
from django.contrib.auth import get_user_model, SESSION_KEY
from django.utils.crypto import get_random_string
from django.utils import timezone
from django.core.management import call_command

from django_u2f.forms import BackupCodeForm, TOTPForm
from django_u2f import oath
from django_u2f.models import TOTPDevice

User = get_user_model()


class TwoFactorTest(TestCase):
    def setUp(self):
        self.client = Client()
        self.user = User.objects.create_superuser(
            username='test',
            email='test@example.com',
            password='asdfasdf',
        )
        self.login_url = reverse('u2f:login')

    def login(self):
        return self.client.post(self.login_url, {
            'username': 'test',
            'password': 'asdfasdf',
            'next': '/next/'
        })

    def enable_backupcode(self):
        code = get_random_string(length=6, allowed_chars=string.digits)
        self.user.backup_codes.create(code=code)
        return code


class U2FTest(TwoFactorTest):
    def enable_u2f(self):
        self.user.u2f_keys.create(
            key_handle='0A8u1AifaDA-D6tjOppWWSEUaBScNnDeashgT869algXVHf6-7ZGfVy8asVWgbjiYm5cd7i9WlrWffgMQXTOQg',
            public_key='pQECAyYgASFYIHlYYfK3OwMqc-wvfVShLshA17BpbFvqSzVafTYshcF7IlggAkUNp9r5xt8Mp9tLpYNxp1Slt7HmKWJBSQouMaqpAbY',
            app_id='https://localhost:8000',
        )

    def set_challenge(self):
        session = self.client.session
        session['u2f_sign_request'] = {
            "publicKey": {
                "challenge": "mn4GAUL58lCqEXuXUy7MztfgKo2osRqBnIjTf9LHoxd00CXQVGtIxjMtP-79n7EiMlYJoHiRlWfkeSWTYluAxg",
                "allowCredentials": [
                    {
                        "id": "0A8u1AifaDA-D6tjOppWWSEUaBScNnDeashgT869algXVHf6-7ZGfVy8asVWgbjiYm5cd7i9WlrWffgMQXTOQg",
                        "type": "public-key"
                    }
                ],
                "userVerification": "preferred",
                "timeout": 60000,
                "rpId": "localhost",
                "extensions": {
                    "appid": "https://localhost:8000"
                }
            }
        }
        session['expected_origin'] = 'https://localhost:8000'
        session.save()
        resp = {
            'clientExtensionResults': {'appid': False},
            'id': '0A8u1AifaDA-D6tjOppWWSEUaBScNnDeashgT869algXVHf6-7ZGfVy8asVWgbjiYm5cd7i9WlrWffgMQXTOQg',
            'rawId': '0A8u1AifaDA-D6tjOppWWSEUaBScNnDeashgT869algXVHf6-7ZGfVy8asVWgbjiYm5cd7i9WlrWffgMQXTOQg',
            'response': {
                'authenticatorData': 'SZYN5YgOjGh0NBcPZHZgW4_krrmihjLHmVzzuoMdl2MBAAAADA',
                'clientDataJSON': 'eyJjaGFsbGVuZ2UiOiJtbjRHQVVMNThsQ3FFWHVYVXk3TXp0ZmdLbzJvc1JxQm5JalRmOUxIb3hkMDBDWFFWR3RJeGpNdFAtNzluN0VpTWxZSm9IaVJsV2ZrZVNXVFlsdUF4ZyIsImNsaWVudEV4dGVuc2lvbnMiOnsiYXBwaWQiOiJodHRwczovL2xvY2FsaG9zdDo4MDAwIn0sImhhc2hBbGdvcml0aG0iOiJTSEEtMjU2Iiwib3JpZ2luIjoiaHR0cHM6Ly9sb2NhbGhvc3Q6ODAwMCIsInR5cGUiOiJ3ZWJhdXRobi5nZXQifQ',
                'signature': 'MEYCIQC-_chxCsvIIPcovxfxA4S3wflNnh940I8aUjpE7qV3rQIhALUKBcbAh0A4NdArSJBZpE0lHKR9q2hBLfc7lx7Ce6-J',
                'userHandle': None
            },
           'type': 'public-key'
        }
        return resp


    def set_add_key(self):
        session = self.client.session
        session['expected_origin'] = 'https://localhost:8000'
        session['u2f_registration_request'] = {
            "rp": {
                "name": "localhost",
                "id": "localhost"
            },
            "user": {
                "id": "MQ",
                "name": "1",
                "displayName": "1"
            },
            "challenge": "Bvb8XGi7IXqqVY8ijWjQfW9c59qtIUICzbcwtdpGGwuLVDHEsB39XCu8oDEu200XGQfg0kdap6aE6ka6Hm-_6g",
            "pubKeyCredParams": [
                {
                    "type": "public-key",
                    "alg": -7
                },
                {
                    "type": "public-key",
                    "alg": -8
                },
                {
                    "type": "public-key",
                    "alg": -36
                },
                {
                    "type": "public-key",
                    "alg": -37
                },
                {
                    "type": "public-key",
                    "alg": -38
                },
                {
                    "type": "public-key",
                    "alg": -39
                },
                {
                    "type": "public-key",
                    "alg": -257
                },
                {
                    "type": "public-key",
                    "alg": -258
                },
                {
                    "type": "public-key",
                    "alg": -259
                }
            ],
            "attestation": "none",
            "timeout": 60000,
            "excludeCredentials": []
        }

        session.save()
        return {'clientExtensionResults': {},
               'id': '0A8u1AifaDA-D6tjOppWWSEUaBScNnDeashgT869algXVHf6-7ZGfVy8asVWgbjiYm5cd7i9WlrWffgMQXTOQg',
               'rawId': '0A8u1AifaDA-D6tjOppWWSEUaBScNnDeashgT869algXVHf6-7ZGfVy8asVWgbjiYm5cd7i9WlrWffgMQXTOQg',
               'response': {'attestationObject': 'o2NmbXRkbm9uZWdhdHRTdG10oGhhdXRoRGF0YVjESZYN5YgOjGh0NBcPZHZgW4_krrmihjLHmVzzuoMdl2NBAAAAAAAAAAAAAAAAAAAAAAAAAAAAQNAPLtQIn2gwPg-rYzqaVlkhFGgUnDZw3mrIYE_OvWpYF1R3-vu2Rn1cvGrFVoG44mJuXHe4vVpa1n34DEF0zkKlAQIDJiABIVggeVhh8rc7Aypz7C99VKEuyEDXsGlsW-pLNVp9NiyFwXsiWCACRQ2n2vnG3wyn20ulg3GnVKW3seYpYkFJCi4xqqkBtg',
                            'clientDataJSON': 'eyJjaGFsbGVuZ2UiOiJCdmI4WEdpN0lYcXFWWThpaldqUWZXOWM1OXF0SVVJQ3piY3d0ZHBHR3d1TFZESEVzQjM5WEN1OG9ERXUyMDBYR1FmZzBrZGFwNmFFNmthNkhtLV82ZyIsImNsaWVudEV4dGVuc2lvbnMiOnt9LCJoYXNoQWxnb3JpdGhtIjoiU0hBLTI1NiIsIm9yaWdpbiI6Imh0dHBzOi8vbG9jYWxob3N0OjgwMDAiLCJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIn0'},
               'type': 'public-key'}


class TestU2F(U2FTest):
    def test_normal_login(self):
        r = self.login()
        self.assertTrue(r['location'].endswith('/next/'))
        self.assertEqual(str(self.client.session[SESSION_KEY]), str(self.user.id))

    def test_u2f_login(self):
        self.enable_u2f()
        r = self.login()
        self.assertNotIn(SESSION_KEY, self.client.session)
        self.assertIn(reverse('u2f:verify-second-factor'), r['location'])

        device_response = self.set_challenge()
        resp = self.client.post(r['location'], {
            'response': json.dumps(device_response),
            'type': 'u2f',
        })
        self.assertEquals(resp.status_code, 302)
        self.assertTrue(resp['location'].endswith('/next/'))
        self.assertEqual(str(self.client.session[SESSION_KEY]), str(self.user.id))

    def test_failed_u2f_login(self):
        self.enable_u2f()
        r = self.login()
        device_response = self.set_challenge()
        resp = device_response['response']
        resp['signature'] = 'a' + resp['signature'][1:]
        response = self.client.post(r['location'], {
            'response': json.dumps(device_response),
            'type': 'u2f',
        })
        self.assertNotIn(SESSION_KEY, self.client.session)
        self.assertContains(response, 'Validation failed')

    def test_verify_when_not_logged_in(self):
        r = self.client.get(reverse('u2f:verify-second-factor'))
        self.assertTrue(r['location'].endswith(self.login_url))

    def test_add_key(self):
        self.login()

        url = reverse('u2f:add-u2f-key')
        r = self.client.get(url)
        self.assertContains(r, '"challenge"')

        device_response = self.set_add_key()
        r = self.client.post(url, {
            'response': json.dumps(device_response),
        })
        added_key_obj = self.user.u2f_keys.get()
        self.assertEqual(added_key_obj.public_key, "pQECAyYgASFYIHlYYfK3OwMqc-wvfVShLshA17BpbFvqSzVafTYshcF7IlggAkUNp9r5xt8Mp9tLpYNxp1Slt7HmKWJBSQouMaqpAbY")
        self.assertEqual(added_key_obj.key_handle, "0A8u1AifaDA-D6tjOppWWSEUaBScNnDeashgT869algXVHf6-7ZGfVy8asVWgbjiYm5cd7i9WlrWffgMQXTOQg")
        self.assertEqual(added_key_obj.app_id, 'https://localhost:8000')

    def test_key_delete(self):
        other_user = User.objects.create_superuser(
            username='abc',
            email='abc@example.com',
            password='asdfasdf',
        )
        other_user.u2f_keys.create()
        self.enable_u2f()
        self.client.login(username='test', password='asdfasdf')

        r = self.client.post(reverse('u2f:u2f-keys'), {
            'key_id': self.user.u2f_keys.get().pk,
            'delete': '1',
        })
        self.assertFalse(self.user.u2f_keys.exists())

        # cant delete someone else's keys
        r = self.client.post(reverse('u2f:u2f-keys'), {
            'key_id': other_user.u2f_keys.get().pk,
            'delete': '1',
        })
        self.assertTrue(other_user.u2f_keys.exists())
        self.assertEqual(r.status_code, 404)


class TestAdminLogin(TwoFactorTest):
    def setUp(self):
        super(TestAdminLogin, self).setUp()
        self.admin_url = reverse('admin:index')
        # discover admin login url, different on django 1.6 and django 1.7
        r = self.client.get(self.admin_url)
        if r.status_code == 302:
            # django 1.7
            self.login_url = r['location']
        else:
            # django 1.6
            self.login_url = self.admin_url

    def test_admin_template_rendered(self):
        r = self.client.get(self.login_url)
        self.assertEqual(r.templates[0].name, 'admin/login.html')

    def test_login_with_u2f(self):
        code = self.enable_backupcode()
        r = self.client.post(self.login_url, {
            'username': 'test',
            'password': 'asdfasdf',
        })
        self.assertNotIn(SESSION_KEY, self.client.session)
        self.assertIn(reverse('u2f:verify-second-factor'), r['location'])

        verify_key_response = self.client.get(r['location'])
        self.assertContains(verify_key_response, 'Django administration')

        r = self.client.post(r['location'], {
            'code': code,
            'type': 'backup',
        })

        self.assertEqual(str(self.client.session[SESSION_KEY]), str(self.user.id))
        self.assertTrue(r['location'].endswith(self.admin_url))

    def test_login_without_u2f(self):
        r = self.client.post(self.login_url, {
            'username': 'test',
            'password': 'asdfasdf',
            'this_is_the_login_form': 1,
            'next': self.admin_url,
        })
        self.assertTrue(r['location'].endswith(self.admin_url))
        self.assertEqual(str(self.client.session[SESSION_KEY]), str(self.user.id))


class TestBackupCode(TwoFactorTest):
    def test_validation_error(self):
        self.enable_backupcode()
        r = self.login()
        self.assertNotIn(SESSION_KEY, self.client.session)
        self.assertIn(reverse('u2f:verify-second-factor'), r['location'])

        r = self.client.post(r['location'], {
            'type': 'backup',
        })
        self.assertContains(r, 'This field is required.')

    def test_code_required_and_login(self):
        code = self.enable_backupcode()
        r = self.login()
        self.assertNotIn(SESSION_KEY, self.client.session)
        self.assertIn(reverse('u2f:verify-second-factor'), r['location'])

        r = self.client.post(r['location'], {
            'code': code,
            'type': 'backup',
        })
        self.assertEqual(str(self.client.session[SESSION_KEY]), str(self.user.id))
        self.assertTrue(r['location'].endswith('/next/'))
        self.assertFalse(self.user.backup_codes.filter(code=code).exists())

    def test_incorrect_code(self):
        self.enable_backupcode()
        r = self.login()
        r = self.client.post(r['location'], {
            'code': 'abc',
            'type': 'backup',
        })
        self.assertNotIn(SESSION_KEY, self.client.session)
        self.assertContains(r, BackupCodeForm.INVALID_ERROR_MESSAGE)

    def test_add_backup_codes(self):
        self.login()
        r = self.client.post(reverse('u2f:backup-codes'))
        self.assertEqual(r.status_code, 302)
        self.assertEqual(self.user.backup_codes.count(), 10)

    def test_list_backup_codes(self):
        self.login()
        self.user.backup_codes.create(code='foobar')
        otheruser = User.objects.create_superuser(
            username='test2',
            email='test2@example.com',
            password='asdfasdf',
        )
        otheruser.backup_codes.create(code='test2code')

        r = self.client.get(reverse('u2f:backup-codes'))
        self.assertContains(r, 'foobar')
        self.assertNotContains(r, 'test2code')

    def test_addbackupcode(self):
        out = StringIO()
        call_command('addbackupcode', self.user.get_username(), stdout=out)
        code = out.getvalue().strip()
        self.assertTrue(self.user.backup_codes.filter(code=code).exists())

        call_command('addbackupcode', self.user.get_username(), code='foo', stdout=out)
        self.assertTrue(self.user.backup_codes.filter(code='foo').exists())

    def test_login_while_already_logged_in(self):
        User.objects.create_superuser(
            username='test2',
            email='test2@example.com',
            password='asdfasdf',
        )
        r = self.client.post(self.login_url, {
            'username': 'test2',
            'password': 'asdfasdf',
            'next': '/next/'
        })
        assert r.status_code == 302

        code = self.enable_backupcode()
        r = self.login()
        self.assertIn(reverse('u2f:verify-second-factor'), r['location'])

        r = self.client.post(r['location'], {
            'code': code,
            'type': 'backup',
        })
        self.assertEqual(str(self.client.session[SESSION_KEY]), str(self.user.id))
        self.assertTrue(r['location'].endswith('/next/'))
        self.assertFalse(self.user.backup_codes.filter(code=code).exists())


class TestTOTP(U2FTest):
    def enable_totp(self):
        key = os.urandom(20)
        self.user.totp_devices.create(
            key=key,
        )
        return key

    def test_login(self):
        key = self.enable_totp()
        r = self.login()
        self.assertNotIn(SESSION_KEY, self.client.session)
        self.assertIn(reverse('u2f:verify-second-factor'), r['location'])

        r = self.client.post(r['location'], {
            'token': oath.totp(key, timezone.now()),
            'type': 'totp',
        })
        self.assertEqual(str(self.client.session[SESSION_KEY]), str(self.user.id))
        self.assertTrue(r['location'].endswith('/next/'))

    def test_token_cant_be_used_twice(self):
        key = self.enable_totp()
        r = self.login()
        token = oath.totp(key, timezone.now()),
        r = self.client.post(r['location'], {
            'token': token,
            'type': 'totp',
        })
        self.assertEqual(str(self.client.session[SESSION_KEY]), str(self.user.id))
        self.client.logout()
        r = self.login()
        r = self.client.post(r['location'], {
            'token': token,
            'type': 'totp',
        })
        self.assertContains(r, TOTPForm.INVALID_ERROR_MESSAGE)

    def test_incorrect_code(self):
        key = self.enable_totp()
        r = self.login()
        r = self.client.post(r['location'], {
            'token': oath.totp(key, timezone.now() + datetime.timedelta(seconds=120)),
            'type': 'totp',
        })
        self.assertNotIn(SESSION_KEY, self.client.session)
        self.assertContains(r, TOTPForm.INVALID_ERROR_MESSAGE)

    def _extract_key(self, response):
        return re.search('<tt>([A-Z0-9]+)</tt>', response.content.decode('utf-8')).group(1)

    def test_add_device(self):
        self.login()
        url = reverse('u2f:add-totp')
        r = self.client.get(url)
        self.assertContains(r, 'svg')
        base32_key = self._extract_key(r)
        key = b32decode(base32_key)

        r = self.client.post(url, {
            'base32_key': base32_key,
            'token': oath.totp(key, timezone.now()),
        })
        self.assertEqual(r.status_code, 302)
        self.assertTrue(self.user.totp_devices.filter(key=key).exists())

    def test_add_device_incorrect_token(self):
        self.login()
        url = reverse('u2f:add-totp')
        r = self.client.get(url)
        base32_key = self._extract_key(r)
        key = b32decode(base32_key)

        r = self.client.post(url, {
            'base32_key': base32_key,
            'token': oath.totp(key, timezone.now() + datetime.timedelta(seconds=120)),
        })
        self.assertEqual(r.status_code, 200)
        self.assertContains(r, TOTPForm.INVALID_ERROR_MESSAGE)

    def test_delete_device(self):
        self.login()
        self.enable_totp()
        r = self.client.post(reverse('u2f:totp-devices'), {
            'device_id': self.user.totp_devices.get().pk,
            'delete': '1',
        })
        self.assertEqual(r.status_code, 302)
        self.assertFalse(self.user.totp_devices.exists())

    def test_slop(self):
        key = os.urandom(20)
        device = TOTPDevice(key=key)
        now = timezone.now()

        self.assertTrue(device.validate_token(oath.totp(key, now - datetime.timedelta(seconds=30))))
        self.assertTrue(device.validate_token(oath.totp(key, now)))
        self.assertTrue(device.validate_token(oath.totp(key, now + datetime.timedelta(seconds=30))))
