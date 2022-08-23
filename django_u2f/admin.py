from django.contrib.auth import REDIRECT_FIELD_NAME
from django.urls import reverse
from django.http import HttpResponseRedirect
from django.utils.translation import gettext as _


def make_login_view(view_class):
    def login(self, request, extra_context=None):
        """
        Displays the login form for the given HttpRequest.
        """
        if request.method == 'GET' and self.has_permission(request):
            # Already logged-in, redirect to admin index
            index_path = reverse('admin:index', current_app=self.name)
            return HttpResponseRedirect(index_path)

        # Since this module gets imported in the application's root package,
        # it cannot import models from other applications at the module level,
        # and django.contrib.admin.forms eventually imports User.
        from django.contrib.admin.forms import AdminAuthenticationForm
        context = dict(
            self.each_context(request),
            title=_('Log in'),
            app_path=request.get_full_path(),
            username=request.user.get_username(),
        )
        if (REDIRECT_FIELD_NAME not in request.GET and
                REDIRECT_FIELD_NAME not in request.POST):
            context[REDIRECT_FIELD_NAME] = reverse('admin:index', current_app=self.name)
        context.update(extra_context or {})

        defaults = {
            'extra_context': context,
            'authentication_form': self.login_form or AdminAuthenticationForm,
            'template_name': self.login_template or 'admin/login.html',
        }
        request.current_app = self.name
        return view_class.as_view(**defaults)(request)
    return login


def monkeypatch_admin(view_class=None):
    if view_class is None:
        from django_u2f.views import U2FLoginView
        view_class = U2FLoginView

    from django.contrib.admin.sites import AdminSite
    AdminSite.login = make_login_view(view_class)
