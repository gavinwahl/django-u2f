import os
import json
from base64 import b32encode, b32decode
from collections import OrderedDict
from six import BytesIO
from six.moves.urllib.parse import quote

from django.views.generic import FormView, ListView, TemplateView, View
from django.contrib.auth.forms import AuthenticationForm
from django.contrib.auth import load_backend
from django.contrib.auth.views import LoginView
from django.contrib.auth.decorators import login_required
from django.contrib import auth, messages
from django.conf import settings
from django.http import HttpResponseRedirect, JsonResponse
from django.urls import reverse, reverse_lazy
from django.utils.http import urlencode
from django.shortcuts import resolve_url, get_object_or_404
from django.contrib.sites.shortcuts import get_current_site
from django.utils.functional import cached_property
from django.utils.translation import gettext as _
try:
    from django.utils.http import url_has_allowed_host_and_scheme
except ImportError:
    # BBB: Django <= 2.2
    from django.utils.http import is_safe_url as url_has_allowed_host_and_scheme

from webauthn import generate_registration_options, verify_registration_response
from webauthn.helpers.structs import PublicKeyCredentialDescriptor, RegistrationCredential
from webauthn.helpers import base64url_to_bytes, options_to_json, bytes_to_base64url

import qrcode
from qrcode.image.svg import SvgPathImage

from .forms import KeyResponseForm, BackupCodeForm, TOTPForm, KeyRegistrationForm, get_origin
from .forms import get_rp_id
from .models import TOTPDevice


class U2FLoginView(LoginView):
    form_class = AuthenticationForm
    template_name = 'u2f/login.html'

    @property
    def is_admin(self):
        return self.template_name == 'admin/login.html'

    def requires_two_factor(self, user):
        return (user.u2f_keys.exists() or
                user.backup_codes.exists() or
                user.totp_devices.exists())

    def form_valid(self, form):
        user = form.get_user()
        if not self.requires_two_factor(user):
            # no keys registered, use single-factor auth
            return super(U2FLoginView, self).form_valid(form)
        else:
            self.request.session['u2f_pre_verify_user_pk'] = user.pk
            self.request.session['u2f_pre_verify_user_backend'] = user.backend

            verify_url = reverse('u2f:verify-second-factor')
            redirect_to = self.request.POST.get(auth.REDIRECT_FIELD_NAME,
                                                self.request.GET.get(auth.REDIRECT_FIELD_NAME, ''))
            params = {}
            if url_has_allowed_host_and_scheme(url=redirect_to, allowed_hosts=self.request.get_host()):
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


class AddKeyMixin:
    def get_data(self):
        data = {}
        request = generate_registration_options(
            rp_id=get_rp_id(self.request),
            rp_name=get_rp_id(self.request),
            user_id=str(self.request.user.id),
            user_name=str(self.request.user.id),
            exclude_credentials=[
                PublicKeyCredentialDescriptor(id=base64url_to_bytes(x.key_handle))
                for x in self.request.user.u2f_keys.all()
            ],
        )
        request = json.loads(options_to_json(request))
        self.request.session['u2f_registration_request'] = request
        self.request.session['expected_origin'] = get_origin(self.request)
        data['registration_request'] = request
        return data

    def create_key(self, response):
        u2f_request = self.request.session.pop('u2f_registration_request')
        expected_origin = self.request.session.pop('expected_origin')
        verification = verify_registration_response(
            credential=RegistrationCredential.parse_raw(response),
            expected_challenge=base64url_to_bytes(u2f_request['challenge']),
            expected_origin=expected_origin,
            expected_rp_id=u2f_request['rp']['id'],
            require_user_verification=False,
        )
        return self.request.user.u2f_keys.create(
            public_key=bytes_to_base64url(verification.credential_public_key),
            key_handle=bytes_to_base64url(verification.credential_id),
            app_id=expected_origin,
        )


class AddKeyJsonView(AddKeyMixin, View):
    def get(self, *args, **kwargs):
        data = self.get_data()
        return JsonResponse(data)

    def post(self, request, *args, **kwargs):
        response = request.POST['response']
        self.create_key(response)
        return JsonResponse({})


class AddKeyView(AddKeyMixin, FormView):
    template_name = 'u2f/add_key.html'
    form_class = KeyRegistrationForm
    success_url = reverse_lazy('u2f:u2f-keys')

    def dispatch(self, request, *args, **kwargs):
        return super(AddKeyView, self).dispatch(request, *args, **kwargs)

    def get_form_kwargs(self):
        kwargs = super(AddKeyView, self).get_form_kwargs()
        kwargs.update(
            user=self.request.user,
            request=self.request,
            appId=get_origin(self.request),
        )
        return kwargs

    def get_context_data(self, **kwargs):
        kwargs = super(AddKeyView, self).get_context_data(**kwargs)
        kwargs.update(self.get_data())
        return kwargs

    def form_valid(self, form):
        response = form.cleaned_data['response']
        self.create_key(response)
        messages.success(self.request, _("Key added."))
        return super(AddKeyView, self).form_valid(form)

    def get_success_url(self):
        if 'next' in self.request.GET and url_has_allowed_host_and_scheme(self.request.GET['next'], allowed_hosts=self.request.get_host()):
            return self.request.GET['next']
        else:
            return super(AddKeyView, self).get_success_url()


class VerifySecondFactorMixin:
    @property
    def form_classes(self):
        ret = {}
        if self.user.u2f_keys.exists():
            ret['u2f'] = KeyResponseForm
        if self.user.backup_codes.exists():
            ret['backup'] = BackupCodeForm
        if self.user.totp_devices.exists():
            ret['totp'] = TOTPForm
        return ret

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

    def get_form_kwargs(self):
        return {
            'user': self.user,
            'request': self.request,
            'appId': get_origin(self.request),
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

    def form_valid(self, form, forms):
        if not form.validate_second_factor():
            return self.form_invalid(forms)

        del self.request.session['u2f_pre_verify_user_pk']
        del self.request.session['u2f_pre_verify_user_backend']

        auth.login(self.request, self.user)

        return JsonResponse({})


class VerifySecondFactorJsonView(VerifySecondFactorMixin, View):
    def get(self, request, *args, **kwargs):
        forms = self.get_forms()
        data = {}
        if 'u2f' in forms:
            data['django_u2f_request'] = forms['u2f'].sign_request
        return JsonResponse(data)

    def dispatch(self, request, *args, **kwargs):
        self.user = self.get_user()
        if self.user is None:
            return JsonResponse(None, status=403)
        return super(VerifySecondFactorJsonView, self).dispatch(request, *args, **kwargs)

    def post(self, request, *args, **kwargs):
        forms = self.get_forms()
        form = forms[request.POST['type']]
        if form.is_valid():
            return self.form_valid(form, forms)
        else:
            return self.form_invalid(forms)

    def form_invalid(self, forms):
        form = forms[self.request.POST['type']]
        return JsonResponse(form.errors.get_json_data(), status=400)


class VerifySecondFactorView(VerifySecondFactorMixin, TemplateView):
    template_name = 'u2f/verify_second_factor.html'

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
        if not url_has_allowed_host_and_scheme(url=redirect_to, allowed_hosts=self.request.get_host()):
            redirect_to = resolve_url(settings.LOGIN_REDIRECT_URL)
        return HttpResponseRedirect(redirect_to)


class TwoFactorSettingsView(TemplateView):
    template_name = 'u2f/two_factor_settings.html'

    def get_context_data(self, **kwargs):
        context= super(TwoFactorSettingsView, self).get_context_data(**kwargs)
        context['u2f_enabled'] = self.request.user.u2f_keys.exists()
        context['backup_codes'] = self.request.user.backup_codes.all()
        context['totp_enabled'] = self.request.user.totp_devices.exists()
        return context


class KeyManagementJsonView(View):
    def get_queryset(self):
        return self.request.user.u2f_keys.all()

    def get(self, request, *args, **kwargs):
        data = [{
            'id': key.id,
            'created_at': key.created_at.isoformat(),
            'last_used_at': key.last_used_at.isoformat() if key.last_used_at else None,
        } for key in self.get_queryset()]
        return JsonResponse({'data': data})

    def delete(self, request, *args, **kwargs):
        data = json.loads(request.body)
        key = get_object_or_404(self.get_queryset(), pk=data['key_id'])
        key.delete()
        return JsonResponse(None, status=204)


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


class BackupCodesJsonView(View):
    def get_queryset(self):
        return self.request.user.backup_codes.all()

    def get(self, request, *args, **kwargs):
        data = [{
            'id': code.id,
            'code': code.code,
        } for code in self.get_queryset()]
        return JsonResponse({'data': data})

    def post(self, request, *args, **kwargs):
        for i in range(10):
            self.request.user.backup_codes.create_backup_code()
        return JsonResponse({})


class BackupCodesView(ListView):
    template_name = 'u2f/backup_codes.html'

    def get_queryset(self):
        return self.request.user.backup_codes.all()

    def post(self, request):
        for i in range(10):
            self.request.user.backup_codes.create_backup_code()
        return HttpResponseRedirect(self.request.build_absolute_uri())


class AddTOTPDeviceMixin:
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
        return buf.getvalue().decode('utf-8')

    @cached_property
    def key(self):
        try:
            return b32decode(self.request.POST['base32_key'])
        except KeyError:
            return self.gen_key()

    def get_data(self, **kwargs):
        otp_auth = self.get_otpauth_url(self.key)
        return {
            'base32_key': b32encode(self.key).decode(),
            'otpauth': otp_auth,
            'qr_svg': self.get_qrcode(otp_auth),
        }

    def get_extra_form_kwargs(self):
        return {
            'user': self.request.user,
            'request': self.request,
            'appId': get_origin(self.request),
        }


class AddTOTPDeviceJsonView(AddTOTPDeviceMixin, View):
    def get(self, request, *args, **kwargs):
        data = self.get_data()
        return JsonResponse(data)

    def post(self, request, *args, **kwargs):
        form_kwargs = self.get_extra_form_kwargs()
        form_kwargs['data'] = request.POST
        form = TOTPForm(**form_kwargs)
        if form.is_valid():
            device = TOTPDevice(
                user=self.request.user,
                key=self.key,
            )
            if device.validate_token(form.cleaned_data['token']):
                device.save()
                return JsonResponse({})
            else:
                assert not device.pk
                form.add_error('token', TOTPForm.INVALID_ERROR_MESSAGE)
                return JsonResponse(form.errors.get_json_data(), status=400)
        return JsonResponse(form.errors.get_json_data(), status=400)


class AddTOTPDeviceView(AddTOTPDeviceMixin, FormView):
    form_class = TOTPForm
    template_name = 'u2f/totp_device.html'
    success_url = reverse_lazy('u2f:two-factor-settings')

    def get_context_data(self, **kwargs):
        kwargs = super(AddTOTPDeviceView, self).get_context_data(**kwargs)
        kwargs.update(self.get_data())
        return kwargs

    def get_form_kwargs(self):
        kwargs = super(AddTOTPDeviceView, self).get_form_kwargs()
        kwargs.update(self.get_extra_form_kwargs())
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
        if 'next' in self.request.GET and url_has_allowed_host_and_scheme(self.request.GET['next'], allowed_hosts=self.request.get_host()):
            return self.request.GET['next']
        else:
            return super(AddTOTPDeviceView, self).get_success_url()


class TOTPDeviceManagementJsonView(View):
    def get_queryset(self):
        return self.request.user.totp_devices.all()

    def get(self, request, *args, **kwargs):
        data = [{
            'id': device.id,
            'created_at': device.created_at.isoformat(),
            'last_used_at': device.last_used_at.isoformat() if device.last_used_at else None,
        } for device in self.get_queryset()]
        return JsonResponse({'data': data})

    def delete(self, request, *args, **kwargs):
        data = json.loads(request.body)
        device = get_object_or_404(self.get_queryset(), pk=data['device_id'])
        device.delete()
        return JsonResponse(None, status=200)


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


login = U2FLoginView.as_view()
two_factor_settings = login_required(TwoFactorSettingsView.as_view())

backup_codes = login_required(BackupCodesView.as_view())
backup_codes_json = login_required(BackupCodesJsonView.as_view())

add_key = login_required(AddKeyView.as_view())
add_key_json = login_required(AddKeyJsonView.as_view())

verify_second_factor = VerifySecondFactorView.as_view()
verify_second_factor_json = VerifySecondFactorJsonView.as_view()

keys = login_required(KeyManagementView.as_view())
keys_json = login_required(KeyManagementJsonView.as_view())

add_totp = login_required(AddTOTPDeviceView.as_view())
add_totp_json = login_required(AddTOTPDeviceJsonView.as_view())

totp_devices = login_required(TOTPDeviceManagementView.as_view())
totp_devices_json = login_required(TOTPDeviceManagementJsonView.as_view())
