import json

from django import forms
from django.core.exceptions import ObjectDoesNotExist
from django.utils import timezone
from django.utils.translation import gettext_lazy as _

import webauthn
from webauthn import options_to_json, base64url_to_bytes
from webauthn.helpers.structs import PublicKeyCredentialDescriptor, AuthenticationCredential
from webauthn.helpers.exceptions import InvalidAuthenticationResponse


def get_origin(request):
    return '{scheme}://{host}'.format(
        scheme=request.scheme,
        host=request.get_host(),
    )


def get_rp_id(request):
    return request.get_host().strip(':{}'.format(request.get_port()))


class SecondFactorForm(forms.Form):
    def __init__(self, *args, **kwargs):
        self.user = kwargs.pop('user')
        self.request = kwargs.pop('request')
        self.appId = kwargs.pop('appId')
        return super(SecondFactorForm, self).__init__(*args, **kwargs)


def set_u2f_verification_session_vars(request, user):
    options = webauthn.generate_authentication_options(
        rp_id=get_rp_id(request),
        allow_credentials=[
            PublicKeyCredentialDescriptor(id=base64url_to_bytes(x.key_handle))
            for x in user.u2f_keys.all()
        ]
    )
    options = options_to_json(options)
    options = json.loads(options)

    options['extensions'] = {
        'appid': get_origin(request)
    }
    options = {'publicKey': options}
    request.session['u2f_sign_request'] = options
    request.session['expected_origin'] = get_origin(request)
    return options


class KeyResponseForm(SecondFactorForm):
    response = forms.CharField()

    def __init__(self, *args, **kwargs):
        super(KeyResponseForm, self).__init__(*args, **kwargs)
        if self.data:
            self.sign_request = self.request.session['u2f_sign_request']
        else:
            options = set_u2f_verification_session_vars(self.request, self.user)
            self.sign_request = options

    def validate_second_factor(self):
        response = self.cleaned_data['response']
        try:
            data = self.request.session['u2f_sign_request']['publicKey']
            json_data = json.loads(response)
            key = self.user.u2f_keys.get(key_handle=json_data['id'])
            expected_rp_id = data['rpId']
            # use appid as expected_rp_id if appid extension is True
            # https://github.com/duo-labs/py_webauthn/issues/116#issuecomment-1010385763
            if json_data['clientExtensionResults'].get('appid', False):
                expected_rp_id = key.app_id
            verification = webauthn.verify_authentication_response(
                credential=AuthenticationCredential.parse_raw(response),
                expected_challenge=base64url_to_bytes(data['challenge']),
                expected_rp_id=expected_rp_id,
                expected_origin=self.request.session['expected_origin'],
                credential_public_key=base64url_to_bytes(key.public_key),
                credential_current_sign_count=0,
                require_user_verification=False,
            )
            # TODO: store sign_count and verify it's increasing
            key.last_used_at = timezone.now()
            key.save()
            del self.request.session['u2f_sign_request']
            del self.request.session['expected_origin']
            return True
        except (ValueError, InvalidAuthenticationResponse) as e:
            self.add_error('__all__', 'Validation failed -- bad signature.')
        except ObjectDoesNotExist:
            self.add_error('__all__', 'Validation failed')
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
