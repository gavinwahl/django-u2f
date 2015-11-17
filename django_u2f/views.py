import string

from django.views.generic import FormView, ListView, TemplateView
from django.contrib.auth.forms import AuthenticationForm
from django.contrib.auth import load_backend
from django.contrib.auth import views as auth_views
from django.contrib.auth.decorators import login_required
from django.contrib import auth, messages
from django.conf import settings
from django.http import HttpResponseRedirect
from django.core.urlresolvers import reverse
from django.utils.http import is_safe_url, urlencode
from django.shortcuts import resolve_url, get_object_or_404
from django.utils.crypto import get_random_string
from django.db import transaction, IntegrityError

from u2flib_server import u2f_v2 as u2f

from django_u2f.forms import KeyResponseForm, BackupCodeForm


class U2FLoginView(FormView):
    form_class = AuthenticationForm
    template_name = 'u2f/login.html'

    @property
    def is_admin(self):
        try:
            return self.kwargs['current_app'] == 'admin'
        except KeyError:
            return False

    def requires_two_factor(self, user):
        return user.u2f_keys.exists() or user.backup_codes.exists()

    def get_template_names(self):
        if self.is_admin:
            return 'admin/login.html'
        else:
            return self.template_name

    def form_valid(self, form):
        user = form.get_user()
        if not self.requires_two_factor(user):
            # no keys registered, use single-factor auth
            return original_auth_login_view(self.request, **self.kwargs)
        else:
            self.request.session['u2f_pre_verify_user_pk'] = user.pk
            self.request.session['u2f_pre_verify_user_backend'] = user.backend

            verify_key_url = reverse(verify_key)
            redirect_to = self.request.POST.get(auth.REDIRECT_FIELD_NAME, '')
            try:
                # acting as admin login view, handle weird django <= 1.6
                # behavior where login view is used without redirecting
                if self.is_admin:
                    redirect_to = self.kwargs['extra_context'][auth.REDIRECT_FIELD_NAME]
            except KeyError:
                pass

            params = {}
            if is_safe_url(url=redirect_to, host=self.request.get_host()):
                params[auth.REDIRECT_FIELD_NAME] = redirect_to
            if self.is_admin:
                params['admin'] = 1
            if params:
                verify_key_url += '?' + urlencode(params)

            return HttpResponseRedirect(verify_key_url)

    def get_context_data(self, **kwargs):
        kwargs = super(U2FLoginView, self).get_context_data(**kwargs)
        kwargs[auth.REDIRECT_FIELD_NAME] = self.request.POST.get(auth.REDIRECT_FIELD_NAME, '')
        kwargs.update(self.kwargs.get('extra_context', {}))
        return kwargs


class AdminU2FLoginView(U2FLoginView):
    template_name = 'admin/login.html'


class AddKeyView(FormView):
    template_name = 'u2f/add_key.html'
    form_class = KeyResponseForm

    def get_origin(self):
        return '{scheme}://{host}'.format(
            # BBB: Django >= 1.7 has request.scheme
            scheme='https' if self.request.is_secure() else 'http',
            host=self.request.get_host(),
        )

    def get_form_kwargs(self):
        kwargs = super(AddKeyView, self).get_form_kwargs()
        kwargs.update(
            user=self.request.user,
            request=self.request,
        )
        return kwargs

    def get_context_data(self, **kwargs):
        kwargs = super(AddKeyView, self).get_context_data(**kwargs)
        challenge = u2f.start_register(self.get_origin())
        self.request.session['u2f_registration_challenge'] = challenge
        kwargs['challenge'] = challenge

        # Create a SignRequest for each key that has already been added to the
        # account.
        # This can be passed to u2f.register as the second parameter to prevent
        # re-registering the same key for the same user.
        sign_requests = [
            u2f.start_authenticate(d.to_json()) for d in self.request.user.u2f_keys.all()
        ]
        kwargs['sign_requests'] = sign_requests

        return kwargs

    def form_valid(self, form):
        response = form.cleaned_data['response']
        challenge = self.request.session['u2f_registration_challenge']
        del self.request.session['u2f_registration_challenge']
        device, attestation_cert = u2f.complete_register(challenge, response)
        self.request.user.u2f_keys.create(
            public_key=device['publicKey'],
            key_handle=device['keyHandle'],
            app_id=device['appId'],
        )
        messages.success(self.request, 'Key added.')
        return HttpResponseRedirect(reverse(keys))


class VerifyKeyView(TemplateView):
    template_name = 'u2f/verify_key.html'
    form_classes = {
        'u2f': KeyResponseForm,
        'backup': BackupCodeForm,
    }

    def get_user(self):
        try:
            user_id = self.request.session['u2f_pre_verify_user_pk']
            backend_path = self.request.session['u2f_pre_verify_user_backend']
            assert backend_path in settings.AUTHENTICATION_BACKENDS
            backend = load_backend(backend_path)
            user = backend.get_user(user_id)
            if user is not None:
                user.backend = backend_path
            return user
        except (KeyError, AssertionError):
            return None

    def dispatch(self, request, *args, **kwargs):
        self.user = self.get_user()
        if self.user is None:
            return HttpResponseRedirect(reverse(login))
        return super(VerifyKeyView, self).dispatch(request, *args, **kwargs)

    def post(self, request, *args, **kwargs):
        forms = self.get_forms()
        form = forms[request.POST['type']]
        if form.is_valid():
            return self.form_valid(form, forms)
        else:
            return self.form_invalid(forms)

    def form_invalid(self, forms):
        return self.render_to_response(self.get_context_data(forms=forms))

    def get_form_kwargs(self):
        return {
            'user': self.user,
            'request': self.request,
        }

    def get_forms(self):
        kwargs = self.get_form_kwargs()
        if self.request.method == 'GET':
            forms = {key: form(**kwargs) for key, form in self.form_classes.items()}
        else:
            method = self.request.POST['type']
            forms = {key: form(**kwargs) for key, form in self.form_classes.items()}
            forms[method] = self.form_classes[method](self.request.POST, **kwargs)
        return forms

    def get_context_data(self, **kwargs):
        if 'forms' not in kwargs:
            kwargs['forms'] = self.get_forms()
        kwargs = super(VerifyKeyView, self).get_context_data(**kwargs)
        if self.request.GET.get('admin'):
            kwargs['base_template'] = 'admin/base_site.html'
        else:
            kwargs['base_template'] = 'base.html'
        return kwargs

    def form_valid(self, form, forms):
        if not form.validate_second_factor():
            return self.form_invalid(forms)

        auth.login(self.request, self.user)

        del self.request.session['u2f_pre_verify_user_pk']
        del self.request.session['u2f_pre_verify_user_backend']

        redirect_to = self.request.POST.get(auth.REDIRECT_FIELD_NAME, '')
        if not is_safe_url(url=redirect_to, host=self.request.get_host()):
            redirect_to = resolve_url(settings.LOGIN_REDIRECT_URL)
        return HttpResponseRedirect(redirect_to)


class TwoFactorSettingsView(TemplateView):
    template_name = 'u2f/two_factor_settings.html'


class KeyManagementView(ListView):
    template_name = 'u2f/key_list.html'

    def get_queryset(self):
        return self.request.user.u2f_keys.all()

    def post(self, request):
        assert 'delete' in self.request.POST
        key = get_object_or_404(self.get_queryset(), pk=self.request.POST['key_id'])
        key.delete()
        if self.get_queryset().exists():
            messages.success(request, 'Key removed.')
        else:
            messages.success(request, 'Key removed. Two-factor auth disabled.')
        return HttpResponseRedirect(reverse(keys))


class BackupCodesView(ListView):
    template_name = 'u2f/backup_codes.html'

    def get_queryset(self):
        return self.request.user.backup_codes.all()

    def create_backup_code(self):
        while True:
            with transaction.atomic():
                try:
                    code = get_random_string(length=6, allowed_chars=string.digits)
                    return self.request.user.backup_codes.create(code=code)
                except IntegrityError:
                    pass

    def post(self, request):
        for i in range(10):
            self.create_backup_code()
        return HttpResponseRedirect(self.request.build_absolute_uri())


add_key = login_required(AddKeyView.as_view())
verify_key = VerifyKeyView.as_view()
login = U2FLoginView.as_view()
keys = login_required(KeyManagementView.as_view())
two_factor_settings = login_required(TwoFactorSettingsView.as_view())
backup_codes = login_required(BackupCodesView.as_view())

original_auth_login_view = auth_views.login
auth_views.login = U2FLoginView.as_view()
