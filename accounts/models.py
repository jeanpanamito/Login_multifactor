from django.db import models
from django.contrib.auth.models import AbstractUser
from django.utils import timezone
import uuid


class CustomUser(AbstractUser):
    MFA_METHOD_EMAIL = 'email'
    MFA_METHOD_SMS = 'sms'
    MFA_METHOD_SECURITY_Q = 'secq'
    MFA_METHOD_TOTP = 'totp'

    MFA_METHOD_CHOICES = [
        (MFA_METHOD_EMAIL, 'Código por correo'),
        (MFA_METHOD_SMS, 'Código por SMS'),
        (MFA_METHOD_SECURITY_Q, 'Pregunta de seguridad'),
        (MFA_METHOD_TOTP, 'Aplicación OTP (TOTP)'),
    ]

    phone_number = models.CharField(max_length=32, blank=True)
    is_email_verified = models.BooleanField(default=False)
    is_phone_verified = models.BooleanField(default=False)
    mfa_method = models.CharField(max_length=8, choices=MFA_METHOD_CHOICES, default=MFA_METHOD_EMAIL)
    failed_login_attempts = models.PositiveIntegerField(default=0)
    locked_until = models.DateTimeField(null=True, blank=True)
    last_session_key = models.CharField(max_length=64, null=True, blank=True)

    def is_locked(self) -> bool:
        if self.locked_until is None:
            return False
        return timezone.now() < self.locked_until


class VerificationCode(models.Model):
    TYPE_EMAIL = 'email'
    TYPE_SMS = 'sms'
    TYPE_ACTIVATION = 'activation'
    TYPE_UNLOCK = 'unlock'
    TYPE_LOGIN_MFA = 'login_mfa'

    PURPOSE_CHOICES = [
        (TYPE_EMAIL, 'Correo'),
        (TYPE_SMS, 'SMS'),
        (TYPE_ACTIVATION, 'Activación de cuenta'),
        (TYPE_UNLOCK, 'Desbloqueo'),
        (TYPE_LOGIN_MFA, 'MFA Login'),
    ]

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user = models.ForeignKey('CustomUser', on_delete=models.CASCADE, related_name='verification_codes')
    code = models.CharField(max_length=6)
    purpose = models.CharField(max_length=16)
    sent_to = models.CharField(max_length=128, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    expires_at = models.DateTimeField()
    used_at = models.DateTimeField(null=True, blank=True)

    def is_valid(self) -> bool:
        return self.used_at is None and timezone.now() <= self.expires_at


class SecurityQuestion(models.Model):
    user = models.OneToOneField('CustomUser', on_delete=models.CASCADE, related_name='security_question')
    question = models.CharField(max_length=255)
    answer = models.CharField(max_length=255)


class AccessLog(models.Model):
    ACTION_CREATE_USER = 'create_user'
    ACTION_LOGIN_SUCCESS = 'login_success'
    ACTION_LOGIN_FAILURE = 'login_failure'
    ACTION_LOGOUT = 'logout'

    action = models.CharField(max_length=32)
    user = models.ForeignKey('CustomUser', on_delete=models.SET_NULL, null=True, blank=True)
    ip_address = models.GenericIPAddressField(null=True, blank=True)
    user_agent = models.TextField(blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ['-created_at']

# Create your models here.
