from django.apps import AppConfig


class U2FConfig(AppConfig):
    name = 'django_u2f'

    def monkeypatch_login_view(self):
        from .admin import monkeypatch_admin
        monkeypatch_admin()

    def ready(self):
        self.monkeypatch_login_view()
