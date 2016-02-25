from django.apps import AppConfig


class U2FConfig(AppConfig):
    name = 'django_u2f'

    def monkeypatch_login_view(self):
        # Monkey patch django.contrib.auth.views.login, because the admin login
        # view delegates to it. This allows us to share the same code path
        # without using a custom admin site.
        from django.contrib.auth import views as auth_views
        from django_u2f import views as u2f_views
        u2f_views.original_auth_login_view = auth_views.login
        auth_views.login = u2f_views.U2FLoginView.as_view()

    def ready(self):
        self.monkeypatch_login_view()
