import json

from django.test import TestCase, Client
from django.core.urlresolvers import reverse
from django.contrib.auth import get_user_model, SESSION_KEY

User = get_user_model()


class U2FTest(TestCase):
    def setUp(self):
        self.client = Client()
        self.user = User.objects.create_superuser(
            username='test',
            email='test@example.com',
            password='asdfasdf',
        )
        self.login_url = reverse('django_u2f.views.login')

    def enable_u2f(self):
        self.user.u2f_keys.create(
            public_key='BCux01toHSq_5YHfsw3EAqfGGKirLoHnDqAuW5RedtP8dGbJTJ55-QEJ_alPDM06kHw7UOUOCawdHinHVrNbnKw',
            key_handle='OJiPPVZ6oU-PszwbAAJhbanYvhawFrQi6n3AkcT1k7SeZDo3Ch6BU8i21kp2tcsyQ2BE7nc34RdljU4iS997vA',
            app_id='http://localhost.com:8000',
        )

    def set_challenge(self):
        session = self.client.session
        session['u2f_authentication_challenges'] = [
            {
                "challenge": "jUvsJfqf2FMXkUTTFQ57gqNhVn0K2eJ7ElxnF3EK_M8",
                "version": "U2F_V2",
                "keyHandle": "OJiPPVZ6oU-PszwbAAJhbanYvhawFrQi6n3AkcT1k7SeZDo3Ch6BU8i21kp2tcsyQ2BE7nc34RdljU4iS997vA",
                "appId": "http://localhost.com:8000",
            }
        ]
        session.save()
        return {
            "keyHandle": "OJiPPVZ6oU-PszwbAAJhbanYvhawFrQi6n3AkcT1k7SeZDo3Ch6BU8i21kp2tcsyQ2BE7nc34RdljU4iS997vA",
            "clientData": "eyJ0eXAiOiJuYXZpZ2F0b3IuaWQuZ2V0QXNzZXJ0aW9uIiwiY2hhbGxlbmdlIjoialV2c0pmcWYyRk1Ya1VUVEZRNTdncU5oVm4wSzJlSjdFbHhuRjNFS19NOCIsIm9yaWdpbiI6Imh0dHA6Ly9sb2NhbGhvc3QuY29tOjgwMDAiLCJjaWRfcHVia2V5IjoiIn0",
            "signatureData": "AQAAADcwRQIhALnYwD3DMN3CAhKzhH7hwoJfSSiNMrOHhZq2nQA0WunTAiB2hKEpPn4u0znti-mjC4Xq6Ekv1tfopsapTsJ8EOxmYg",
        }

    def set_add_key(self):
        session = self.client.session
        session['u2f_registration_challenge'] = {
            'challenge': "1C57ZaTxUkXyMJqcfdNc_7Lp34aPgYDNt_nL2wwsLPQ",
            'version': "U2F_V2",
            'appId': "http://localhost.com:8000",
        }

        session.save()
        return {
            "registrationData": "BQR-zQiLHRPYDlXEDG_yZ_Y53mLP20BXMUpm-zqH1ntWHr3S1EZtJbFKNkWRwo2BQA-SBRZH4SvA2mZyCK2wP4AZQMF2iVGLM8guW_L2o7tfu9THxhMtOFRC6WICT_Kn2Vn3kxkMLjt4fBYO0ZeatzA5qaBk_O6PIypq0R9oYmHiQYEwggIcMIIBBqADAgECAgQk26tAMAsGCSqGSIb3DQEBCzAuMSwwKgYDVQQDEyNZdWJpY28gVTJGIFJvb3QgQ0EgU2VyaWFsIDQ1NzIwMDYzMTAgFw0xNDA4MDEwMDAwMDBaGA8yMDUwMDkwNDAwMDAwMFowKzEpMCcGA1UEAwwgWXViaWNvIFUyRiBFRSBTZXJpYWwgMTM1MDMyNzc4ODgwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAQCsJS-NH1HeUHEd46-xcpN7SpHn6oeb-w5r-veDCBwy1vUvWnJanjjv4dR_rV5G436ysKUAXUcsVe5fAnkORo2oxIwEDAOBgorBgEEAYLECgEBBAAwCwYJKoZIhvcNAQELA4IBAQCjY64OmDrzC7rxLIst81pZvxy7ShsPy2jEhFWEkPaHNFhluNsCacNG5VOITCxWB68OonuQrIzx70MfcqwYnbIcgkkUvxeIpVEaM9B7TI40ZHzp9h4VFqmps26QCkAgYfaapG4SxTK5k_lCPvqqTPmjtlS03d7ykkpUj9WZlVEN1Pf02aTVIZOHPHHJuH6GhT6eLadejwxtKDBTdNTv3V4UlvjDOQYQe9aL1jUNqtLDeBHso8pDvJMLc0CX3vadaI2UVQxM-xip4kuGouXYj0mYmaCbzluBDFNsrzkNyL3elg3zMMrKvAUhoYMjlX_-vKWcqQsgsQ0JtSMcWMJ-umeDMEUCIDmr7y3CyKDwDThdf8MUyp3R_meuSz6pYPavyjt5vDlHAiEApjqut4HuWZzTz9WmjDTAa8_Dn8DmrXfMCbFFsYXU_nU",
            "challenge": "1C57ZaTxUkXyMJqcfdNc_7Lp34aPgYDNt_nL2wwsLPQ",
            "version": "U2F_V2",
            "appId": "http://localhost.com:8000",
            "clientData": "eyJ0eXAiOiJuYXZpZ2F0b3IuaWQuZmluaXNoRW5yb2xsbWVudCIsImNoYWxsZW5nZSI6IjFDNTdaYVR4VWtYeU1KcWNmZE5jXzdMcDM0YVBnWUROdF9uTDJ3d3NMUFEiLCJvcmlnaW4iOiJodHRwOi8vbG9jYWxob3N0LmNvbTo4MDAwIiwiY2lkX3B1YmtleSI6IiJ9",
        }


class TestU2F(U2FTest):
    def login(self):
        return self.client.post(self.login_url, {
            'username': 'test',
            'password': 'asdfasdf',
            'next': '/next/'
        })

    def test_normal_login(self):
        r = self.login()
        self.assertTrue(r['location'].endswith('/next/'))
        self.assertEqual(self.client.session[SESSION_KEY], self.user.id)

    def test_u2f_login(self):
        self.enable_u2f()
        r = self.login()
        self.assertNotIn(SESSION_KEY, self.client.session)
        self.assertIn(reverse('django_u2f.views.verify_key'), r['location'])

        device_response = self.set_challenge()
        r = self.client.post(r['location'], {
            'response': json.dumps(device_response),
        })
        self.assertEqual(self.client.session[SESSION_KEY], self.user.id)
        key_obj = self.user.u2f_keys.get()
        # Last counter value should have gotten set
        self.assertNotEqual(0, key_obj.last_counter_value)

    def test_failed_u2f_login(self):
        self.enable_u2f()
        r = self.login()
        device_response = self.set_challenge()
        device_response['signatureData'] = 'a' + device_response['signatureData'][1:]
        r = self.client.post(r['location'], {
            'response': json.dumps(device_response),
        })
        self.assertNotIn(SESSION_KEY, self.client.session)
        self.assertIn('Challenge signature verification failed!', r.content)

    def test_verify_when_not_logged_in(self):
        r = self.client.get(reverse('django_u2f.views.verify_key'))
        self.assertTrue(r['location'].endswith(self.login_url))

    def test_add_key(self):
        self.login()

        url = reverse('django_u2f.views.add_key')
        r = self.client.get(url)
        self.assertIn('"challenge"', r.content)

        device_response = self.set_add_key()
        r = self.client.post(url, {
            'response': json.dumps(device_response),
        })
        added_key_obj = self.user.u2f_keys.get()
        self.assertEqual(added_key_obj.public_key, 'BH7NCIsdE9gOVcQMb_Jn9jneYs_bQFcxSmb7OofWe1YevdLURm0lsUo2RZHCjYFAD5IFFkfhK8DaZnIIrbA_gBk')
        self.assertEqual(added_key_obj.key_handle, 'wXaJUYszyC5b8vaju1-71MfGEy04VELpYgJP8qfZWfeTGQwuO3h8Fg7Rl5q3MDmpoGT87o8jKmrRH2hiYeJBgQ')
        self.assertEqual(added_key_obj.app_id, 'http://localhost.com:8000')

    def test_key_delete(self):
        other_user = User.objects.create_superuser(
            username='abc',
            email='abc@example.com',
            password='asdfasdf',
        )
        other_user.u2f_keys.create()
        self.enable_u2f()
        self.client.login(username='test', password='asdfasdf')

        r = self.client.post(reverse('django_u2f.views.keys'), {
            'key_id': self.user.u2f_keys.get().pk,
            'delete': '1',
        })
        self.assertFalse(self.user.u2f_keys.exists())

        # cant delete someone else's keys
        r = self.client.post(reverse('django_u2f.views.keys'), {
            'key_id': other_user.u2f_keys.get().pk,
            'delete': '1',
        })
        self.assertTrue(other_user.u2f_keys.exists())
        self.assertEqual(r.status_code, 404)

    def test_nonincreasing_counter(self):
        self.enable_u2f()

        # Authenticate using U2F once
        r = self.login()
        device_response = self.set_challenge()
        self.client.post(r['location'], {
            'response': json.dumps(device_response),
        })

        # Now logout and authenticate with U2F again; the counter value
        # returned will be the same, so this should trigger the check for a
        # nonincreasing counter.
        self.client.logout()
        r = self.login()
        device_response = self.set_challenge()
        r = self.client.post(r['location'], {
            'response': json.dumps(device_response),
        })

        # Check that the login didn't work and the warning message gets shown.
        self.assertNotIn(SESSION_KEY, self.client.session)
        self.assertIn('spoofed', r.content)


class TestAdminLogin(U2FTest):
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
        self.enable_u2f()
        r = self.client.post(self.login_url, {
            'username': 'test',
            'password': 'asdfasdf',
        })
        self.assertNotIn(SESSION_KEY, self.client.session)
        self.assertIn(reverse('django_u2f.views.verify_key'), r['location'])

        verify_key_response = self.client.get(r['location'])
        self.assertIn('Django administration', verify_key_response.content)

        device_response = self.set_challenge()
        r = self.client.post(r['location'], {
            'response': json.dumps(device_response),
        })

        self.assertEqual(self.client.session[SESSION_KEY], self.user.id)
        self.assertTrue(r['location'].endswith(self.admin_url))

    def test_login_without_u2f(self):
        r = self.client.get(self.admin_url)
        if r.status_code == 200:
            # django 1.6
            self.assertEqual(r.context['next'], self.admin_url)
        # else:
            # django 1.7

        r = self.client.post(self.login_url, {
            'username': 'test',
            'password': 'asdfasdf',
            'this_is_the_login_form': 1,
            'next': self.admin_url,
        })
        self.assertTrue(r['location'].endswith(self.admin_url))
        self.assertEqual(self.client.session[SESSION_KEY], self.user.id)
