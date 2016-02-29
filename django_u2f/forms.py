import json

import django
from django import forms
from django.utils import timezone
from django.utils.translation import ugettext_lazy as _

from cryptography.exceptions import InvalidSignature
from u2flib_server import u2f_v2 as u2f

from .models import BackupCode


class SecondFactorForm(forms.Form):
    def __init__(self, *args, **kwargs):
        self.user = kwargs.pop('user')
        self.request = kwargs.pop('request')
        return super(SecondFactorForm, self).__init__(*args, **kwargs)


class KeyResponseForm(SecondFactorForm):
    response = forms.CharField()

    def __init__(self, *args, **kwargs):
        super(KeyResponseForm, self).__init__(*args, **kwargs)
        if self.data:
            self.challenges = self.request.session['u2f_authentication_challenges']
        else:
            self.challenges = [
                u2f.start_authenticate(d.to_json()) for d in self.user.u2f_keys.all()
            ]
            self.request.session['u2f_authentication_challenges'] = self.challenges

    def validate_second_factor(self):
        response = json.loads(self.cleaned_data['response'])
        try:
            # find the right challenge, the based on the key the user inserted
            challenge = [c for c in self.challenges if c['keyHandle'] == response['keyHandle']][0]
            device = self.user.u2f_keys.get(key_handle=response['keyHandle'])
            login_counter, touch_asserted = u2f.verify_authenticate(
                device.to_json(),
                challenge,
                response,
            )
            # TODO: store login_counter and verify it's increasing
            device.last_used_at = timezone.now()
            device.save()
            del self.request.session['u2f_authentication_challenges']
            return True
        except InvalidSignature:
            self.add_error('__all__', 'U2F validation failed -- bad signature.')
        return False


class BackupCodeForm(SecondFactorForm):
    INVALID_ERROR_MESSAGE = _("That is not a valid backup code.")

    code = forms.CharField(label=_("Code"), widget=forms.TextInput(attrs={'autocomplete': 'off'}))

    def _validate_second_factor_legacy(self):
        # This implementation has a race condition where the same code could be
        # used twice, but Django < 1.9 doesn't return the count of deleted
        # objects.
        try:
            obj = self.user.backup_codes.get(code=self.cleaned_data['code'])
        except BackupCode.DoesNotExist:
             self.add_error('code', self.INVALID_ERROR_MESSAGE)
             return False
        obj.delete()
        return True

    def validate_second_factor(self):
        if django.VERSION < (1, 9):
            return self._validate_second_factor_legacy()

        count, _ = self.user.backup_codes.filter(code=self.cleaned_data['code']).delete()
        if count == 0:
            self.add_error('code', self.INVALID_ERROR_MESSAGE)
            return False
        elif count == 1:
            return True
        else:
            assert False, "Impossible, there should never be more than one object with the same code."


class TOTPForm(SecondFactorForm):
    INVALID_ERROR_MESSAGE = _("That token is invalid.")

    token = forms.CharField(
        min_length=6,
        max_length=6,
        label=_("Token"),
        widget=forms.TextInput(attrs={'autocomplete': 'off'})
    )

    def validate_second_factor(self):
        for device in self.user.totp_devices.all():
            if device.validate_token(self.cleaned_data['token']):
                device.last_used_at = timezone.now()
                device.save()
                return True
        self.add_error('token', self.INVALID_ERROR_MESSAGE)
        return False
