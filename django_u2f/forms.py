import json

from django import forms
from django.utils import timezone

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
        except Exception as e:
            self.add_error('__all__', str(e))
        return False


class BackupCodeForm(SecondFactorForm):
    INVALID_ERROR_MESSAGE = "That is not a valid backup code."

    code = forms.CharField()

    def validate_second_factor(self):
        try:
            obj = self.user.backup_codes.get(code=self.cleaned_data['code'])
        except BackupCode.DoesNotExist:
            self.add_error('code', self.INVALID_ERROR_MESSAGE)
            return False
        obj.delete()
        return True


class TOTPForm(SecondFactorForm):
    INVALID_ERROR_MESSAGE = "That token is invalid"

    token = forms.CharField(min_length=6, max_length=6)

    def validate_second_factor(self):
        for device in self.user.totp_devices.all():
            if device.validate_token(self.cleaned_data['token']):
                device.last_used_at = timezone.now()
                device.save()
                return True
        self.add_error('token', self.INVALID_ERROR_MESSAGE)
        return False
