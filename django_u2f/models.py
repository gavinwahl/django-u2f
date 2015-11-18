from __future__ import division

import datetime
import hmac
import six

from django.db import models
from django.conf import settings
from django.utils import timezone

from .oath import totp, T


class U2FKey(models.Model):
    user = models.ForeignKey(settings.AUTH_USER_MODEL, related_name='u2f_keys')
    created_at = models.DateTimeField(auto_now_add=True)
    last_used_at = models.DateTimeField(null=True)

    public_key = models.TextField()
    key_handle = models.TextField()
    app_id = models.TextField()

    def to_json(self):
        return {
            'publicKey': self.public_key,
            'keyHandle': self.key_handle,
            'appId': self.app_id,
        }


class BackupCode(models.Model):
    user = models.ForeignKey(settings.AUTH_USER_MODEL, related_name='backup_codes')
    code = models.CharField(max_length=8)

    class Meta:
        unique_together = [
            ('user', 'code')
        ]


class TOTPDevice(models.Model):
    user = models.ForeignKey(settings.AUTH_USER_MODEL, related_name='totp_devices')
    created_at = models.DateTimeField(auto_now_add=True)
    last_used_at = models.DateTimeField(null=True)

    key = models.BinaryField()
    # the T value of the most recently-used token. This prevents using the same
    # token twice.
    last_t = models.PositiveIntegerField(null=True)

    def validate_token(self, token):
        step = datetime.timedelta(seconds=30)
        now = timezone.now()
        slop = 1

        # not sure why django gives you a memory view instead of a bytes object
        key = six.binary_type(self.key)

        times_to_check = [now]
        for i in range(1, slop + 1):
            times_to_check.append(now - i * step)
            times_to_check.append(now + i * step)

        # prevent using the same token twice
        if self.last_t is not None:
            times_to_check = [t for t in times_to_check if T(t) > self.last_t]

        for t in times_to_check:
            if hmac.compare_digest(six.text_type(totp(key, t)), token):
                self.last_t = T(t)
                return True
        return False
