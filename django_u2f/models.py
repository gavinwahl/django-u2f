from django.db import models
from django.conf import settings


class U2FKey(models.Model):
    user = models.ForeignKey(settings.AUTH_USER_MODEL, related_name='u2f_keys')
    created_at = models.DateTimeField(auto_now_add=True)
    last_used_at = models.DateTimeField(null=True)
    last_counter_value = models.PositiveIntegerField(default=0)

    public_key = models.TextField()
    key_handle = models.TextField()
    app_id = models.TextField()

    def to_json(self):
        return {
            'publicKey': self.public_key,
            'keyHandle': self.key_handle,
            'appId': self.app_id,
        }
