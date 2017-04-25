import json

from django import forms
from django.utils import timezone
from django.utils.translation import ugettext_lazy as _

from u2flib_server import u2f


class SecondFactorForm(forms.Form):
    def __init__(self, *args, **kwargs):
        self.user = kwargs.pop('user')
        self.request = kwargs.pop('request')
        self.appId = kwargs.pop('appId')
        return super(SecondFactorForm, self).__init__(*args, **kwargs)


class KeyResponseForm(SecondFactorForm):
    response = forms.CharField()

    def __init__(self, *args, **kwargs):
        super(KeyResponseForm, self).__init__(*args, **kwargs)
        if self.data:
            self.sign_request = self.request.session['u2f_sign_request']
        else:
            self.sign_request = u2f.begin_authentication(self.appId, [
                d.to_json() for d in self.user.u2f_keys.all()
            ])
            self.request.session['u2f_sign_request'] = self.sign_request

    def validate_second_factor(self):
        response = json.loads(self.cleaned_data['response'])
        try:
            device, login_counter, _ = u2f.complete_authentication(self.sign_request, response)
            # TODO: store login_counter and verify it's increasing
            device = self.user.u2f_keys.get(key_handle=device['keyHandle'])
            device.last_used_at = timezone.now()
            device.save()
            del self.request.session['u2f_sign_request']
            return True
        except ValueError:
            self.add_error('__all__', 'U2F validation failed -- bad signature.')
        return False


class KeyRegistrationForm(SecondFactorForm):
    response = forms.CharField()


class BackupCodeForm(SecondFactorForm):
    INVALID_ERROR_MESSAGE = _("That is not a valid backup code.")

    code = forms.CharField(label=_("Code"), widget=forms.TextInput(attrs={'autocomplete': 'off'}))

    def validate_second_factor(self):
        count, _ = self.user.backup_codes.filter(code=self.cleaned_data['code']).delete()
        if count == 0:
            self.add_error('code', self.INVALID_ERROR_MESSAGE)
            return False
        elif count == 1:
            return True
        else:
            assert False, \
                "Impossible, there should never be more than one object with the same code."


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
