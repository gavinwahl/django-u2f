import json

from django.views.generic import FormView, ListView
from django.contrib.auth.forms import AuthenticationForm
from django.contrib.auth import load_backend
from django.contrib.auth import views as auth_views
from django.contrib.auth.decorators import login_required
from django.contrib import auth, messages
from django.conf import settings
from django.dispatch import Signal
from django.http import HttpResponseRedirect
from django.core.urlresolvers import reverse
from django.utils.http import is_safe_url, urlencode
from django.shortcuts import resolve_url, get_object_or_404
from django.utils import timezone

from u2flib_server import u2f_v2 as u2f

from django_u2f.forms import KeyResponseForm


key_counter_nonincreasing = Signal(providing_args=["user", "device"])


class U2FLoginView(FormView):
    form_class = AuthenticationForm
    template_name = 'u2f/login.html'

    @property
    def is_admin(self):
        try:
            return self.kwargs['current_app'] == 'admin'
        except KeyError:
            return False

    def get_template_names(self):
        if self.is_admin:
            return 'admin/login.html'
        else:
            return self.template_name

    def form_valid(self, form):
        user = form.get_user()
        if not user.u2f_keys.exists():
            # no keys registered, use single-factor auth
            return original_auth_login_view(self.request, **self.kwargs)
        else:
            self.request.session['u2f_pre_verify_user_pk'] = user.pk
            self.request.session['u2f_pre_verify_user_backend'] = user.backend

            verify_key_url = reverse(verify_key)
            redirect_to = self.request.REQUEST.get(auth.REDIRECT_FIELD_NAME, '')
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
        kwargs[auth.REDIRECT_FIELD_NAME] = self.request.REQUEST.get(auth.REDIRECT_FIELD_NAME, '')
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


class VerifyKeyView(FormView):
    template_name = 'u2f/verify_key.html'
    form_class = KeyResponseForm

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

    def get_context_data(self, **kwargs):
        kwargs = super(VerifyKeyView, self).get_context_data(**kwargs)
        challenges = [
            u2f.start_authenticate(d.to_json()) for d in self.user.u2f_keys.all()
        ]
        self.request.session['u2f_authentication_challenges'] = challenges
        kwargs['challenges'] = challenges
        if self.request.GET.get('admin'):
            kwargs['base_template'] = 'admin/base_site.html'
        else:
            kwargs['base_template'] = 'base.html'
        return kwargs

    def form_valid(self, form):
        response = json.loads(form.cleaned_data['response'])
        challenges = self.request.session['u2f_authentication_challenges']
        try:
            # find the right challenge, the based on the key the user inserted
            challenge = [c for c in challenges if c['keyHandle'] == response['keyHandle']][0]
            device = self.user.u2f_keys.get(key_handle=response['keyHandle'])
            login_counter, touch_asserted = u2f.verify_authenticate(
                device.to_json(),
                challenge,
                response,
            )
        except Exception as e:
            form.add_error('__all__', str(e))
            return self.form_invalid(form)
        if login_counter <= device.last_counter_value:
            key_counter_nonincreasing.send(sender=self.__class__,
                user=self.user, device=device)
            form.add_error(None, "Login counter didn't increase; key may have "
                "been spoofed.")
            return self.form_invalid(form)
        device.last_used_at = timezone.now()
        device.last_counter_value = login_counter
        device.save()
        auth.login(self.request, self.user)

        del self.request.session['u2f_authentication_challenges']
        del self.request.session['u2f_pre_verify_user_pk']
        del self.request.session['u2f_pre_verify_user_backend']

        redirect_to = self.request.REQUEST.get(auth.REDIRECT_FIELD_NAME, '')
        if not is_safe_url(url=redirect_to, host=self.request.get_host()):
            redirect_to = resolve_url(settings.LOGIN_REDIRECT_URL)
        return HttpResponseRedirect(redirect_to)


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


add_key = login_required(AddKeyView.as_view())
verify_key = VerifyKeyView.as_view()
login = U2FLoginView.as_view()
keys = login_required(KeyManagementView.as_view())

original_auth_login_view = auth_views.login
auth_views.login = U2FLoginView.as_view()
