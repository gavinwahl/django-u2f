import json

from django.test import TestCase, Client
from django.core.urlresolvers import reverse
from django.contrib.auth import get_user_model, SESSION_KEY

User = get_user_model()


class TestAdminLogin(TestCase):
    def setUp(self):
        self.client = Client()
        self.user = User.objects.create_superuser(
            username='test',
            email='test@example.com',
            password='asdfasdf',
        )
        self.admin_url = reverse('admin:index')
        # discover admin login url, different on django 1.6 and django 1.7
        r = self.client.get(self.admin_url)
        if r.status_code == 302:
            # django 1.7
            self.login_url = r['location']
        else:
            # django 1.6
            self.login_url = self.admin_url

    def enable_u2f(self):
        self.user.u2f_keys.create(
            public_key='BCux01toHSq_5YHfsw3EAqfGGKirLoHnDqAuW5RedtP8dGbJTJ55-QEJ_alPDM06kHw7UOUOCawdHinHVrNbnKw',
            key_handle='OJiPPVZ6oU-PszwbAAJhbanYvhawFrQi6n3AkcT1k7SeZDo3Ch6BU8i21kp2tcsyQ2BE7nc34RdljU4iS997vA',
            app_id='http://localhost.com:8000',
        )

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

        r = self.client.post(r['location'], {
            'response': json.dumps({
                "keyHandle": "OJiPPVZ6oU-PszwbAAJhbanYvhawFrQi6n3AkcT1k7SeZDo3Ch6BU8i21kp2tcsyQ2BE7nc34RdljU4iS997vA",
                "clientData": "eyJ0eXAiOiJuYXZpZ2F0b3IuaWQuZ2V0QXNzZXJ0aW9uIiwiY2hhbGxlbmdlIjoialV2c0pmcWYyRk1Ya1VUVEZRNTdncU5oVm4wSzJlSjdFbHhuRjNFS19NOCIsIm9yaWdpbiI6Imh0dHA6Ly9sb2NhbGhvc3QuY29tOjgwMDAiLCJjaWRfcHVia2V5IjoiIn0",
                "signatureData": "AQAAADcwRQIhALnYwD3DMN3CAhKzhH7hwoJfSSiNMrOHhZq2nQA0WunTAiB2hKEpPn4u0znti-mjC4Xq6Ekv1tfopsapTsJ8EOxmYg",
            }),
        })

        self.assertEqual(self.client.session[SESSION_KEY], self.user.id)
        self.assertTrue(r['location'].endswith(self.admin_url))

    def test_login_without_u2f(self):
        r = self.client.get(self.admin_url)
        self.assertEqual(r.context['next'], self.admin_url)

        r = self.client.post(self.login_url, {
            'username': 'test',
            'password': 'asdfasdf',
            'this_is_the_login_form': 1,
            'next': self.admin_url,
        })
        self.assertTrue(r['location'].endswith(self.admin_url))
        self.assertEqual(self.client.session[SESSION_KEY], self.user.id)
