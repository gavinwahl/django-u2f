import json

from django import forms
from django.views.generic import FormView, ListView
from django.contrib.auth.forms import AuthenticationForm
from django.contrib.auth import load_backend
from django.contrib.auth.views import login as auth_login_view
from django.contrib.auth.decorators import login_required
from django.contrib import auth, messages
from django.conf import settings
from django.http import HttpResponseRedirect
from django.core.urlresolvers import reverse
from django.utils.http import is_safe_url
from django.shortcuts import resolve_url, get_object_or_404
from django.utils import timezone

from u2flib_server import u2f_v2 as u2f


class KeyResponseForm(forms.Form):
    response = forms.CharField()


class U2FLoginView(FormView):
    form_class = AuthenticationForm
    template_name = 'u2f/login.html'

    def form_valid(self, form):
        user = form.get_user()
        if not user.u2f_keys.exists():
            # no keys registered, use single-factor auth
            return auth_login_view(self.request)
        else:
            self.request.session['u2f_pre_verify_user_pk'] = user.pk
            self.request.session['u2f_pre_verify_user_backend'] = user.backend
            return HttpResponseRedirect(reverse(verify_key))


class AddKeyView(FormView):
    template_name = 'u2f/add_key.html'
    form_class = KeyResponseForm

    def get_origin(self):
        return '{scheme}://{host}'.format(scheme=self.request.scheme, host=self.request.get_host())

    def get_context_data(self, **kwargs):
        kwargs = super(AddKeyView, self).get_context_data(**kwargs)
        challenge = u2f.start_register(self.get_origin())
        self.request.session['u2f_registration_challenge'] = challenge
        kwargs['challenge'] = challenge
        # TODO: also blacklist the keys already added to the account (the
        # second argument of u2f.register)
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
        return kwargs

    def form_valid(self, form):
        response = json.loads(form.cleaned_data['response'])
        challenges = self.request.session['u2f_authentication_challenges']
        # find the right challenge, the based on the key the user inserted
        challenge = [c for c in challenges if c['keyHandle'] == response['keyHandle']][0]
        device = self.user.u2f_keys.get(key_handle=response['keyHandle'])
        login_counter, touch_asserted = u2f.verify_authenticate(
            device.to_json(),
            challenge,
            response,
        )
        # TODO: store login_counter and verify it's increasing
        device.last_used_at = timezone.now()
        device.save()
        auth.login(self.request, self.user)
        del self.request.session['u2f_authentication_challenges']

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
