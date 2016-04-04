import os
from base64 import b32encode, b32decode
from collections import OrderedDict
from six import BytesIO
from six.moves.urllib.parse import quote

from django.views.generic import FormView, ListView, TemplateView
from django.contrib.auth.forms import AuthenticationForm
from django.contrib.auth import load_backend
from django.contrib.auth import views as auth_views
from django.contrib.auth.decorators import login_required
from django.contrib import auth, messages
from django.conf import settings
from django.http import HttpResponseRedirect
from django.core.urlresolvers import reverse, reverse_lazy
from django.utils.http import is_safe_url, urlencode
from django.shortcuts import resolve_url, get_object_or_404
from django.contrib.sites.shortcuts import get_current_site
from django.utils.functional import cached_property
from django.utils.translation import ugettext as _

import qrcode
from qrcode.image.svg import SvgPathImage

from .u2f_impl import u2f, U2F_ENABLED
from .forms import KeyResponseForm, BackupCodeForm, TOTPForm
from .models import TOTPDevice


class U2FLoginView(FormView):
    form_class = AuthenticationForm
    template_name = 'u2f/login.html'

    @property
    def is_admin(self):
        return self.get_template_names() == 'admin/login.html'

    def requires_two_factor(self, user):
        return (user.u2f_keys.exists() or
                user.backup_codes.exists() or
                user.totp_devices.exists())

    def get_template_names(self):
        return self.kwargs.get('template_name', self.template_name)

    def form_valid(self, form):
        user = form.get_user()
        if not self.requires_two_factor(user):
            # no keys registered, use single-factor auth
            return original_auth_login_view(self.request, **self.kwargs)
        else:
            self.request.session['u2f_pre_verify_user_pk'] = user.pk
            self.request.session['u2f_pre_verify_user_backend'] = user.backend

            verify_url = reverse('u2f:verify-second-factor')
            redirect_to = self.request.POST.get(auth.REDIRECT_FIELD_NAME,
                                                self.request.GET.get(auth.REDIRECT_FIELD_NAME, ''))
            params = {}
            if is_safe_url(url=redirect_to, host=self.request.get_host()):
                params[auth.REDIRECT_FIELD_NAME] = redirect_to
            if self.is_admin:
                params['admin'] = 1
            if params:
                verify_url += '?' + urlencode(params)

            return HttpResponseRedirect(verify_url)

    def get_context_data(self, **kwargs):
        kwargs = super(U2FLoginView, self).get_context_data(**kwargs)
        kwargs[auth.REDIRECT_FIELD_NAME] = self.request.GET.get(auth.REDIRECT_FIELD_NAME, '')
        kwargs.update(self.kwargs.get('extra_context', {}))
        return kwargs


class AdminU2FLoginView(U2FLoginView):
    template_name = 'admin/login.html'


class AddKeyView(FormView):
    template_name = 'u2f/add_key.html'
    form_class = KeyResponseForm
    success_url = reverse_lazy('u2f:u2f-keys')

    def dispatch(self, request, *args, **kwargs):
        if U2F_ENABLED:
            return super(AddKeyView, self).dispatch(request, *args, **kwargs)
        else:
            return self.render_to_response({'U2F_ENABLED': False})

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
        kwargs['U2F_ENABLED'] = 'U2F_ENABLED'
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
        messages.success(self.request, _("Key added."))
        return super(AddKeyView, self).form_valid(form)

    def get_success_url(self):
        if 'next' in self.request.GET and is_safe_url(self.request.GET['next']):
            return self.request.GET['next']
        else:
            return super().get_success_url()


class VerifySecondFactorView(TemplateView):
    template_name = 'u2f/verify_second_factor.html'
    form_classes = {
        'u2f': KeyResponseForm,
        'backup': BackupCodeForm,
        'totp': TOTPForm,
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
            return HttpResponseRedirect(reverse('u2f:login'))
        return super(VerifySecondFactorView, self).dispatch(request, *args, **kwargs)

    def post(self, request, *args, **kwargs):
        forms = self.get_forms()
        form = forms[request.POST['type']]
        if form.is_valid():
            return self.form_valid(form, forms)
        else:
            return self.form_invalid(forms)

    def form_invalid(self, forms):
        return self.render_to_response(self.get_context_data(
            forms=forms,
        ))

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
            forms = {
                key: form(**kwargs)
                for key, form in self.form_classes.items()
                if key != method
            }
            forms[method] = self.form_classes[method](self.request.POST, **kwargs)
        return forms

    def get_context_data(self, **kwargs):
        if 'forms' not in kwargs:
            kwargs['forms'] = self.get_forms()
        kwargs = super(VerifySecondFactorView, self).get_context_data(**kwargs)
        if self.request.GET.get('admin'):
            kwargs['base_template'] = 'admin/base_site.html'
        else:
            kwargs['base_template'] = 'base.html'
        kwargs['user'] = self.user
        return kwargs

    def form_valid(self, form, forms):
        if not form.validate_second_factor():
            return self.form_invalid(forms)

        del self.request.session['u2f_pre_verify_user_pk']
        del self.request.session['u2f_pre_verify_user_backend']

        auth.login(self.request, self.user)

        redirect_to = self.request.POST.get(auth.REDIRECT_FIELD_NAME,
                                            self.request.GET.get(auth.REDIRECT_FIELD_NAME, ''))
        if not is_safe_url(url=redirect_to, host=self.request.get_host()):
            redirect_to = resolve_url(settings.LOGIN_REDIRECT_URL)
        return HttpResponseRedirect(redirect_to)


class TwoFactorSettingsView(TemplateView):
    template_name = 'u2f/two_factor_settings.html'

    def get_context_data(self, **kwargs):
        kwargs = super(TwoFactorSettingsView, self).get_context_data(**kwargs)
        kwargs['U2F_ENABLED'] = U2F_ENABLED
        return kwargs


class KeyManagementView(ListView):
    template_name = 'u2f/key_list.html'

    def get_queryset(self):
        return self.request.user.u2f_keys.all()

    def post(self, request):
        assert 'delete' in self.request.POST
        key = get_object_or_404(self.get_queryset(), pk=self.request.POST['key_id'])
        key.delete()
        if self.get_queryset().exists():
            messages.success(request, _("Key removed."))
        else:
            messages.success(request, _("Key removed. Two-factor auth disabled."))
        return HttpResponseRedirect(reverse('u2f:u2f-keys'))


class BackupCodesView(ListView):
    template_name = 'u2f/backup_codes.html'

    def get_queryset(self):
        return self.request.user.backup_codes.all()

    def post(self, request):
        for i in range(10):
            self.request.user.backup_codes.create_backup_code()
        return HttpResponseRedirect(self.request.build_absolute_uri())


class AddTOTPDeviceView(FormView):
    form_class = TOTPForm
    template_name = 'u2f/totp_device.html'
    success_url = reverse_lazy('u2f:two-factor-settings')

    def gen_key(self):
        return os.urandom(20)

    def get_otpauth_url(self, key):
        secret = b32encode(key)
        issuer = get_current_site(self.request).name

        params = OrderedDict([
            ('secret', secret),
            ('digits', 6),
            ('issuer', issuer),
        ])

        return 'otpauth://totp/{issuer}:{username}?{params}'.format(
            issuer=quote(issuer),
            username=quote(self.request.user.get_username()),
            params=urlencode(params),
        )

    def get_qrcode(self, data):
        img = qrcode.make(data, image_factory=SvgPathImage)
        buf = BytesIO()
        img.save(buf)
        return buf.getvalue()

    @cached_property
    def key(self):
        try:
            return b32decode(self.request.POST['base32_key'])
        except KeyError:
            return self.gen_key()

    def get_context_data(self, **kwargs):
        kwargs = super(AddTOTPDeviceView, self).get_context_data(**kwargs)
        kwargs['base32_key'] = b32encode(self.key)
        kwargs['qr_svg'] = self.get_qrcode(self.get_otpauth_url(self.key))
        return kwargs

    def get_form_kwargs(self):
        kwargs = super(AddTOTPDeviceView, self).get_form_kwargs()
        kwargs.update(
            user=self.request.user,
            request=self.request,
        )
        return kwargs

    def form_valid(self, form):
        device = TOTPDevice(
            user=self.request.user,
            key=self.key,
        )
        if device.validate_token(form.cleaned_data['token']):
            device.save()
            messages.success(self.request, _("Device added."))
            return super(AddTOTPDeviceView, self).form_valid(form)
        else:
            assert not device.pk
            form.add_error('token', TOTPForm.INVALID_ERROR_MESSAGE)
            return self.form_invalid(form)

    def form_invalid(self, form):
        # Should this go in Django's FormView?!
        # <https://code.djangoproject.com/ticket/25548>
        return self.render_to_response(self.get_context_data(form=form))

    def get_success_url(self):
        if 'next' in self.request.GET and is_safe_url(self.request.GET['next']):
            return self.request.GET['next']
        else:
            return super().get_success_url()


class TOTPDeviceManagementView(ListView):
    template_name = 'u2f/totpdevice_list.html'

    def get_queryset(self):
        return self.request.user.totp_devices.all()

    def post(self, request):
        assert 'delete' in self.request.POST
        device = get_object_or_404(self.get_queryset(), pk=self.request.POST['device_id'])
        device.delete()
        messages.success(request, _("Device removed."))
        return HttpResponseRedirect(reverse('u2f:totp-devices'))


add_key = login_required(AddKeyView.as_view())
verify_second_factor = VerifySecondFactorView.as_view()
login = U2FLoginView.as_view()
keys = login_required(KeyManagementView.as_view())
two_factor_settings = login_required(TwoFactorSettingsView.as_view())
backup_codes = login_required(BackupCodesView.as_view())
add_totp = login_required(AddTOTPDeviceView.as_view())
totp_devices = login_required(TOTPDeviceManagementView.as_view())
