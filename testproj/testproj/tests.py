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
            key_handle='bbavVvfXPz2w8S3IwIS0LkE1SkC3MQuXSYjAYHVPFqUJIRQTIEyM3D34Lv2G4a_PuAZkZIQ6XV3ocwp47cPYjg',
            public_key='BFp3EHDcpm5HxA4XYuCKlnNPZ3tphVzRvXsX2_J33REPU0bgFgWsUoyZHz6RGxdA84VgxDNI4lvUudr7JGmFdDk',
            app_id='http://localhost:8000',
        )

    def set_challenge(self):
        session = self.client.session
        session['u2f_sign_request'] = {
            'appId': 'https://localhost:8000',
            'challenge': '9O7gQlN4O68Rs0ILsEjewRoNX3vHIC6V8m2XbFN4rVI',
            'registeredKeys': [
                {
                    'appId': 'https://localhost:8000',
                    'keyHandle': 'bbavVvfXPz2w8S3IwIS0LkE1SkC3MQuXSYjAYHVPFqUJIRQTIEyM3D34Lv2G4a_PuAZkZIQ6XV3ocwp47cPYjg',
                    'publicKey': 'BFp3EHDcpm5HxA4XYuCKlnNPZ3tphVzRvXsX2_J33REPU0bgFgWsUoyZHz6RGxdA84VgxDNI4lvUudr7JGmFdDk',
                    'version': 'U2F_V2',
                },
            ],
        }
        session.save()
        return {
            "keyHandle": "bbavVvfXPz2w8S3IwIS0LkE1SkC3MQuXSYjAYHVPFqUJIRQTIEyM3D34Lv2G4a_PuAZkZIQ6XV3ocwp47cPYjg",
            "clientData": "eyJ0eXAiOiJuYXZpZ2F0b3IuaWQuZ2V0QXNzZXJ0aW9uIiwiY2hhbGxlbmdlIjoiOU83Z1FsTjRPNjhSczBJTHNFamV3Um9OWDN2SElDNlY4bTJYYkZONHJWSSIsIm9yaWdpbiI6Imh0dHBzOi8vbG9jYWxob3N0OjgwMDAiLCJjaWRfcHVia2V5IjoidW51c2VkIn0",
            "signatureData": "AQAAAQ8wRQIgXvlM1xGuDy5WAIb0irJsu_BLrQCrBUBD4xMw1sR-d9cCIQCywv1E7A-iGDL-Xac9loelFqBewfHP80xCZ7wNDiWYcw"
        }

    def set_add_key(self):
        session = self.client.session
        session['u2f_registration_request'] = {
            "appId": "https://localhost:8000",
            "registerRequests": [
                {
                    "challenge": "sodVF6tVg6dgfEbHPdLlITFDqR4-J31aTy3ZO1DexiE",
                    "version": "U2F_V2"
                }
            ],
            "registeredKeys": []
        }
        session.save()
        return {
            "registrationData": "BQRadxBw3KZuR8QOF2LgipZzT2d7aYVc0b17F9vyd90RD1NG4BYFrFKMmR8-kRsXQPOFYMQzSOJb1Lna-yRphXQ5QG22r1b31z89sPEtyMCEtC5BNUpAtzELl0mIwGB1TxalCSEUEyBMjNw9-C79huGvz7gGZGSEOl1d6HMKeO3D2I4wggIcMIIBBqADAgECAgQk26tAMAsGCSqGSIb3DQEBCzAuMSwwKgYDVQQDEyNZdWJpY28gVTJGIFJvb3QgQ0EgU2VyaWFsIDQ1NzIwMDYzMTAgFw0xNDA4MDEwMDAwMDBaGA8yMDUwMDkwNDAwMDAwMFowKzEpMCcGA1UEAwwgWXViaWNvIFUyRiBFRSBTZXJpYWwgMTM1MDMyNzc4ODgwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAQCsJS-NH1HeUHEd46-xcpN7SpHn6oeb-w5r-veDCBwy1vUvWnJanjjv4dR_rV5G436ysKUAXUcsVe5fAnkORo2oxIwEDAOBgorBgEEAYLECgEBBAAwCwYJKoZIhvcNAQELA4IBAQCjY64OmDrzC7rxLIst81pZvxy7ShsPy2jEhFWEkPaHNFhluNsCacNG5VOITCxWB68OonuQrIzx70MfcqwYnbIcgkkUvxeIpVEaM9B7TI40ZHzp9h4VFqmps26QCkAgYfaapG4SxTK5k_lCPvqqTPmjtlS03d7ykkpUj9WZlVEN1Pf02aTVIZOHPHHJuH6GhT6eLadejwxtKDBTdNTv3V4UlvjDOQYQe9aL1jUNqtLDeBHso8pDvJMLc0CX3vadaI2UVQxM-xip4kuGouXYj0mYmaCbzluBDFNsrzkNyL3elg3zMMrKvAUhoYMjlX_-vKWcqQsgsQ0JtSMcWMJ-umeDMEYCIQCcFT1apcHBu3hHT8PVrsg-iijUzE81mtcK7Nf4rkiDyQIhAN_IgQvxxN4HT00d04UWQjEpCywALZBlVG5NiAwq7Ive",
            "challenge": "sodVF6tVg6dgfEbHPdLlITFDqR4-J31aTy3ZO1DexiE",
            "version": "U2F_V2",
            "clientData": "eyJ0eXAiOiJuYXZpZ2F0b3IuaWQuZmluaXNoRW5yb2xsbWVudCIsImNoYWxsZW5nZSI6InNvZFZGNnRWZzZkZ2ZFYkhQZExsSVRGRHFSNC1KMzFhVHkzWk8xRGV4aUUiLCJvcmlnaW4iOiJodHRwczovL2xvY2FsaG9zdDo4MDAwIiwiY2lkX3B1YmtleSI6InVudXNlZCJ9",
        }


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
        r = self.client.post(r['location'], {
            'response': json.dumps(device_response),
            'type': 'u2f',
        })
        self.assertEquals(r.status_code, 302)
        self.assertTrue(r['location'].endswith('/next/'))
        self.assertEqual(str(self.client.session[SESSION_KEY]), str(self.user.id))

    def test_failed_u2f_login(self):
        self.enable_u2f()
        r = self.login()
        device_response = self.set_challenge()
        device_response['signatureData'] = 'a' + device_response['signatureData'][1:]
        r = self.client.post(r['location'], {
            'response': json.dumps(device_response),
            'type': 'u2f',
        })
        self.assertNotIn(SESSION_KEY, self.client.session)
        self.assertContains(r, 'U2F validation failed')

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
        self.assertEqual(added_key_obj.public_key, "BFp3EHDcpm5HxA4XYuCKlnNPZ3tphVzRvXsX2_J33REPU0bgFgWsUoyZHz6RGxdA84VgxDNI4lvUudr7JGmFdDk")
        self.assertEqual(added_key_obj.key_handle, "bbavVvfXPz2w8S3IwIS0LkE1SkC3MQuXSYjAYHVPFqUJIRQTIEyM3D34Lv2G4a_PuAZkZIQ6XV3ocwp47cPYjg")
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
