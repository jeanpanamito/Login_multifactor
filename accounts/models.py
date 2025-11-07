from django.db import models
from django.contrib.auth.models import AbstractUser
from django.utils import timezone
from django.core.mail import send_mail
from django.conf import settings
import uuid
import random
from datetime import timedelta
from django.utils.crypto import get_random_string


class CustomUser(AbstractUser):
    """Modelo de usuario personalizado con soporte completo para MFA y gestión de cuenta"""
    
    # Métodos MFA
    MFA_METHOD_EMAIL = 'email'
    MFA_METHOD_SMS = 'sms'
    MFA_METHOD_SECURITY_Q = 'secq'
    MFA_METHOD_TOTP = 'totp'
    MFA_METHOD_USB_KEY = 'usb_key'

    MFA_METHOD_CHOICES = [
        (MFA_METHOD_EMAIL, 'Código por correo'),
        (MFA_METHOD_SMS, 'Código por SMS'),
        (MFA_METHOD_SECURITY_Q, 'Pregunta de seguridad'),
        (MFA_METHOD_TOTP, 'Aplicación OTP (TOTP)'),
        (MFA_METHOD_USB_KEY, 'Llave USB (YubiKey)'),
    ]

    # Métodos de activación
    ACTIVATION_EMAIL = 'email'
    ACTIVATION_PHONE = 'phone'
    
    ACTIVATION_METHOD_CHOICES = [
        (ACTIVATION_EMAIL, 'Correo electrónico'),
        (ACTIVATION_PHONE, 'Teléfono'),
    ]

    # Campos adicionales
    phone_number = models.CharField(max_length=32, blank=True)
    is_email_verified = models.BooleanField(default=False)
    is_phone_verified = models.BooleanField(default=False)
    mfa_method = models.CharField(max_length=8, choices=MFA_METHOD_CHOICES, default=MFA_METHOD_EMAIL)
    
    # RS1: Campos de activación
    activation_method = models.CharField(max_length=8, choices=ACTIVATION_METHOD_CHOICES, blank=True, null=True)
    activation_code = models.CharField(max_length=6, blank=True, null=True)
    activation_expires_at = models.DateTimeField(null=True, blank=True)
    
    # RS6: Control de bloqueo
    is_locked = models.BooleanField(default=False)
    failed_login_attempts = models.PositiveIntegerField(default=0)
    locked_until = models.DateTimeField(null=True, blank=True)
    
    # RS5: Gestión de sesión
    last_session_key = models.CharField(max_length=64, null=True, blank=True)

    def check_is_locked(self) -> bool:
        """RS6: Verifica si la cuenta está bloqueada"""
        if self.is_locked:
            return True
        if self.locked_until is None:
            return False
        return timezone.now() < self.locked_until

    # RS1: Método de activación
    def activate(self, code: str) -> bool:
        """
        RS1 F1.6: Valida el código de activación y activa la cuenta
        """
        if self.is_active:
            return False  # Ya está activa
        
        if not self.activation_code or not self.activation_expires_at:
            return False
        
        if self.activation_code != code:
            return False
        
        if timezone.now() > self.activation_expires_at:
            return False  # Código expirado
        
        # Activar cuenta
        self.is_active = True
        self.activation_code = None
        self.activation_expires_at = None
        if self.activation_method == self.ACTIVATION_EMAIL:
            self.is_email_verified = True
        elif self.activation_method == self.ACTIVATION_PHONE:
            self.is_phone_verified = True
        self.save(update_fields=['is_active', 'activation_code', 'activation_expires_at', 
                                'is_email_verified', 'is_phone_verified'])
        return True

    # RS2: Gestión de MFA
    def addMFADevice(self, method_type: str, **kwargs):
        """
        RS2 F2.3: Añade un nuevo método MFA al usuario
        """
        return MFAMethod.objects.create(
            user=self,
            method_type=method_type,
            is_enabled=True,
            **kwargs
        )

    def validateMFA(self, mfa_id: int, code: str) -> bool:
        """
        RS2 F2.5: Valida el código MFA proporcionado
        """
        try:
            mfa_method = self.mfa_methods.get(id=mfa_id, is_enabled=True)
            return mfa_method.validate(code)
        except MFAMethod.DoesNotExist:
            return False

    # RS3: Registro de intentos
    def logAttempt(self, attempt_type: str, success: bool, source_ip: str = None, 
                   source_device: str = None, failure_reason: str = None):
        """
        RS3: Registra un intento de acceso
        """
        return AccessAttempt.create(
            user=self,
            attempt_type=attempt_type,
            success=success,
            source_ip=source_ip,
            source_device=source_device,
            failure_reason=failure_reason
        )

    # RS4: Recuperación de contraseña
    def requestPasswordReset(self):
        """
        RS4 F4.2: Inicia el proceso de recuperación de contraseña
        """
        recovery = AccountRecovery.objects.create(user=self, recovery_email=self.email)
        recovery.generateCode()
        recovery.sendNotification()
        return recovery

    def validatePasswordReset(self, code: str, new_password: str) -> bool:
        """
        RS4 F4.6: Valida el código y cambia la contraseña
        """
        recovery = AccountRecovery.objects.filter(
            user=self,
            completed_at__isnull=True
        ).order_by('-requested_at').first()
        
        if not recovery:
            return False
        
        if not recovery.verifyCode(code):
            return False
        
        # Cambiar contraseña
        self.set_password(new_password)
        self.save(update_fields=['password'])
        
        # Marcar como completado
        recovery.completed_at = timezone.now()
        recovery.save(update_fields=['completed_at'])
        
        return True

    # RS5: Gestión de estado
    def deactivate(self):
        """
        RS5 F5.1: Desactiva temporalmente la cuenta
        """
        self.is_active = False
        self.save(update_fields=['is_active'])

    def reactivate(self):
        """
        RS5 F5.2: Reactiva la cuenta
        """
        self.is_active = True
        self.save(update_fields=['is_active'])

    def terminateActiveSession(self):
        """
        RS5 F5.3: Termina la sesión activa del usuario
        """
        if self.last_session_key:
            try:
                session = Session.objects.get(session_key=self.last_session_key, is_active=True)
                session.terminate()
            except Session.DoesNotExist:
                pass
            self.last_session_key = None
            self.save(update_fields=['last_session_key'])

    # RS6: Control de intentos fallidos
    def checkFailedAttempts(self, time_window_minutes: int = 15) -> int:
        """
        RS6 F6.3: Cuenta los intentos fallidos en un período de tiempo
        """
        cutoff_time = timezone.now() - timedelta(minutes=time_window_minutes)
        count = AccessAttempt.objects.filter(
            user=self,
            success=False,
            attempt_time__gte=cutoff_time
        ).count()
        return count

    def lock(self):
        """
        RS6 F6.4: Bloquea la cuenta automáticamente
        """
        self.is_locked = True
        self.locked_until = timezone.now() + timedelta(hours=1)
        self.save(update_fields=['is_locked', 'locked_until'])

    def unlock(self, code: str) -> bool:
        """
        RS6 F6.7: Desbloquea la cuenta usando el código de desbloqueo
        """
        unlock_request = AccountUnlock.objects.filter(
            user=self,
            completed_at__isnull=True
        ).order_by('-requested_at').first()
        
        if not unlock_request:
            return False
        
        if not unlock_request.verifyCode(code):
            return False
        
        # Desbloquear cuenta
        self.is_locked = False
        self.locked_until = None
        self.failed_login_attempts = 0
        self.save(update_fields=['is_locked', 'locked_until', 'failed_login_attempts'])
        
        # Marcar como completado
        unlock_request.completed_at = timezone.now()
        unlock_request.save(update_fields=['completed_at'])
        
        return True


class MFAMethod(models.Model):
    """RS2: Modelo para gestionar métodos MFA del usuario"""
    
    METHOD_EMAIL = 'EMAIL'
    METHOD_SMS = 'SMS'
    METHOD_TOTP = 'TOTP'
    METHOD_SECURITY_QUESTIONS = 'SECURITY_QUESTIONS'
    METHOD_USB_KEY = 'USB_KEY'
    
    METHOD_CHOICES = [
        (METHOD_EMAIL, 'Código por correo'),
        (METHOD_SMS, 'Código por SMS'),
        (METHOD_TOTP, 'Aplicación OTP (TOTP)'),
        (METHOD_SECURITY_QUESTIONS, 'Preguntas secretas'),
        (METHOD_USB_KEY, 'Llave USB (YubiKey)'),
    ]

    user = models.ForeignKey(CustomUser, on_delete=models.CASCADE, related_name='mfa_methods')
    method_type = models.CharField(max_length=20, choices=METHOD_CHOICES)
    is_enabled = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)
    
    # Para métodos que requieren configuración adicional
    device_name = models.CharField(max_length=128, blank=True)
    secret_key = models.CharField(max_length=255, blank=True)  # Para TOTP/USB

    def generateCode(self) -> str:
        """
        RS2 F2.4: Genera un código de verificación para métodos EMAIL/SMS
        """
        if self.method_type not in (self.METHOD_EMAIL, self.METHOD_SMS):
            return None
        
        code = f"{random.randint(0, 999999):06d}"
        # Crear VerificationCode
        VerificationCode.objects.create(
            user=self.user,
            code=code,
            purpose=VerificationCode.TYPE_LOGIN_MFA,
            sent_to=self.user.email if self.method_type == self.METHOD_EMAIL else self.user.phone_number,
            expires_at=timezone.now() + timedelta(minutes=10)
        )
        return code

    def sendNotification(self):
        """
        RS2 F2.4: Envía el código de verificación al usuario
        """
        if self.method_type == self.METHOD_EMAIL:
            code = self.generateCode()
            if code:
                subject = 'Código de verificación MFA'
                body = f"Tu código es: {code} (válido por 10 minutos)"
                send_mail(subject, body, settings.DEFAULT_FROM_EMAIL, [self.user.email])
        elif self.method_type == self.METHOD_SMS:
            code = self.generateCode()
            if code:
                # Simulación SMS (en producción usar servicio SMS)
                print(f"SMS a {self.user.phone_number}: Tu código es: {code} (válido por 10 minutos)")

    def validate(self, input_value: str) -> bool:
        """
        RS2 F2.4: Valida el código/token proporcionado según el tipo de método
        """
        if self.method_type == self.METHOD_EMAIL or self.method_type == self.METHOD_SMS:
            vc = VerificationCode.objects.filter(
                user=self.user,
                purpose=VerificationCode.TYPE_LOGIN_MFA
            ).order_by('-created_at').first()
            if vc and vc.is_valid() and vc.code == input_value:
                vc.used_at = timezone.now()
                vc.save(update_fields=['used_at'])
                return True
            return False
        elif self.method_type == self.METHOD_SECURITY_QUESTIONS:
            try:
                sq = self.security_question
                return sq.validateAnswer(input_value)
            except SecurityQuestion.DoesNotExist:
                return False
        elif self.method_type == self.METHOD_USB_KEY:
            # Para USB_KEY, validar token FIDO/U2F
            # En producción, usar biblioteca como python-fido2
            # Por ahora, simulación básica
            return input_value == self.secret_key
        elif self.method_type == self.METHOD_TOTP:
            # Usar django-otp para validar TOTP
            from django_otp.plugins.otp_totp.models import TOTPDevice
            device = TOTPDevice.objects.filter(user=self.user, confirmed=True).first()
            if device:
                return device.verify_token(input_value)
            return False
        return False

    def enable(self):
        """
        RS2 F2.3: Habilita el método MFA
        """
        self.is_enabled = True
        self.save(update_fields=['is_enabled'])

    def disable(self):
        """
        RS2 F2.3: Deshabilita el método MFA
        """
        self.is_enabled = False
        self.save(update_fields=['is_enabled'])


class SecurityQuestion(models.Model):
    """RS2: Preguntas de seguridad para MFA"""
    
    mfa_method = models.OneToOneField(MFAMethod, on_delete=models.CASCADE, related_name='security_question', null=True, blank=True)
    question = models.CharField(max_length=255)
    answer = models.CharField(max_length=255)  # Debería estar hasheado en producción

    def validateAnswer(self, answer: str) -> bool:
        """
        RS2 F2.4: Valida la respuesta del usuario
        """
        return self.answer.strip().lower() == answer.strip().lower()


class AccessAttempt(models.Model):
    """RS3: Registro de intentos de acceso y auditoría"""
    
    ATTEMPT_LOGIN = 'LOGIN'
    ATTEMPT_USER_CREATION = 'USER_CREATION'
    ATTEMPT_PASSWORD_RESET = 'PASSWORD_RESET'
    ATTEMPT_ACCOUNT_UNLOCK = 'ACCOUNT_UNLOCK'
    
    ATTEMPT_TYPE_CHOICES = [
        (ATTEMPT_LOGIN, 'Login'),
        (ATTEMPT_USER_CREATION, 'Creación de usuario'),
        (ATTEMPT_PASSWORD_RESET, 'Reseteo de contraseña'),
        (ATTEMPT_ACCOUNT_UNLOCK, 'Desbloqueo de cuenta'),
    ]

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user = models.ForeignKey(CustomUser, on_delete=models.SET_NULL, null=True, blank=True, related_name='access_attempts')
    attempt_type = models.CharField(max_length=32, choices=ATTEMPT_TYPE_CHOICES)
    attempt_time = models.DateTimeField(auto_now_add=True)
    success = models.BooleanField(default=False)
    source_ip = models.GenericIPAddressField(null=True, blank=True)
    source_device = models.TextField(blank=True)
    failure_reason = models.CharField(max_length=255, blank=True, default='')

    class Meta:
        ordering = ['-attempt_time']

    @staticmethod
    def create(user=None, attempt_type: str = None, success: bool = False, 
               source_ip: str = None, source_device: str = None, failure_reason: str = None):
        """
        RS3 F3.4: Método estático para crear registros de intento
        """
        return AccessAttempt.objects.create(
            user=user,
            attempt_type=attempt_type,
            success=success,
            source_ip=source_ip,
            source_device=source_device or '',
            failure_reason=failure_reason or ''
        )


class AccountRecovery(models.Model):
    """RS4: Gestión del proceso de recuperación de contraseña"""
    
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user = models.ForeignKey(CustomUser, on_delete=models.CASCADE, related_name='account_recoveries')
    recovery_email = models.EmailField()
    recovery_code = models.CharField(max_length=6, blank=True)
    requested_at = models.DateTimeField(auto_now_add=True)
    expires_at = models.DateTimeField(null=True, blank=True)
    completed_at = models.DateTimeField(null=True, blank=True)

    def generateCode(self):
        """
        RS4 F4.3: Genera un código de recuperación único
        """
        self.recovery_code = f"{random.randint(0, 999999):06d}"
        self.expires_at = timezone.now() + timedelta(minutes=30)
        self.save(update_fields=['recovery_code', 'expires_at'])

    def sendNotification(self):
        """
        RS4 F4.4: Envía el código de recuperación al correo
        """
        if self.recovery_code:
            subject = 'Código de recuperación de contraseña'
            body = f"Tu código de recuperación es: {self.recovery_code}\n"
            body += f"Válido por 30 minutos.\n"
            body += f"Si no solicitaste este código, ignora este mensaje."
            send_mail(subject, body, settings.DEFAULT_FROM_EMAIL, [self.recovery_email])

    def verifyCode(self, code: str) -> bool:
        """
        RS4 F4.6: Verifica el código de recuperación
        """
        if not self.recovery_code or not self.expires_at:
            return False
        if self.recovery_code != code:
            return False
        if timezone.now() > self.expires_at:
            return False
        if self.completed_at:
            return False  # Ya fue usado
        return True


class AccountUnlock(models.Model):
    """RS6: Gestión del proceso de desbloqueo de cuenta"""
    
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user = models.ForeignKey(CustomUser, on_delete=models.CASCADE, related_name='account_unlocks')
    unlock_code = models.CharField(max_length=6, blank=True)
    requested_at = models.DateTimeField(auto_now_add=True)
    expires_at = models.DateTimeField(null=True, blank=True)
    completed_at = models.DateTimeField(null=True, blank=True)

    def generateCode(self):
        """
        RS6 F6.6: Genera un código de desbloqueo único
        """
        self.unlock_code = f"{random.randint(0, 999999):06d}"
        self.expires_at = timezone.now() + timedelta(minutes=30)
        self.save(update_fields=['unlock_code', 'expires_at'])

    def sendNotification(self):
        """
        RS6 F6.6: Envía el código de desbloqueo al correo
        """
        if self.unlock_code:
            subject = 'Código de desbloqueo de cuenta'
            body = f"Tu código de desbloqueo es: {self.unlock_code}\n"
            body += f"Válido por 30 minutos.\n"
            body += f"Si no solicitaste este código, ignora este mensaje."
            send_mail(subject, body, settings.DEFAULT_FROM_EMAIL, [self.user.email])

    def verifyCode(self, code: str) -> bool:
        """
        RS6 F6.7: Verifica el código de desbloqueo
        """
        if not self.unlock_code or not self.expires_at:
            return False
        if self.unlock_code != code:
            return False
        if timezone.now() > self.expires_at:
            return False
        if self.completed_at:
            return False  # Ya fue usado
        return True


class Session(models.Model):
    """RS7: Gestión de sesiones de trabajo"""
    
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user = models.ForeignKey(CustomUser, on_delete=models.CASCADE, related_name='user_sessions')
    session_token = models.CharField(max_length=64, unique=True)
    started_at = models.DateTimeField(auto_now_add=True)
    last_activity_at = models.DateTimeField(auto_now_add=True)
    session_ip = models.GenericIPAddressField(null=True, blank=True)
    session_device = models.TextField(blank=True)
    is_active = models.BooleanField(default=True)
    terminated_at = models.DateTimeField(null=True, blank=True)
    expires_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        ordering = ['-last_activity_at']

    def updateLastActivity(self):
        """
        RS7 F7.3: Actualiza la última actividad de la sesión
        """
        self.last_activity_at = timezone.now()
        self.save(update_fields=['last_activity_at'])

    def isExpired(self, inactivity_minutes: int = 30) -> bool:
        """
        RS7 F7.5: Verifica si la sesión expiró por inactividad
        """
        if not self.is_active:
            return True
        if self.expires_at and timezone.now() > self.expires_at:
            return True
        cutoff = timezone.now() - timedelta(minutes=inactivity_minutes)
        return self.last_activity_at < cutoff

    def terminate(self):
        """
        RS7 F7.4: Termina la sesión (logout o expiración)
        """
        self.is_active = False
        self.terminated_at = timezone.now()
        self.save(update_fields=['is_active', 'terminated_at'])


class VerificationCode(models.Model):
    """Códigos de verificación para múltiples propósitos"""
    
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
    user = models.ForeignKey(CustomUser, on_delete=models.CASCADE, related_name='verification_codes')
    code = models.CharField(max_length=6)
    purpose = models.CharField(max_length=16)
    sent_to = models.CharField(max_length=128, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    expires_at = models.DateTimeField()
    used_at = models.DateTimeField(null=True, blank=True)

    def is_valid(self) -> bool:
        return self.used_at is None and timezone.now() <= self.expires_at


# Mantener AccessLog para compatibilidad (deprecated, usar AccessAttempt)
class AccessLog(models.Model):
    """Modelo legacy - usar AccessAttempt en su lugar"""
    
    ACTION_CREATE_USER = 'create_user'
    ACTION_LOGIN_SUCCESS = 'login_success'
    ACTION_LOGIN_FAILURE = 'login_failure'
    ACTION_LOGOUT = 'logout'

    action = models.CharField(max_length=32)
    user = models.ForeignKey(CustomUser, on_delete=models.SET_NULL, null=True, blank=True)
    ip_address = models.GenericIPAddressField(null=True, blank=True)
    user_agent = models.TextField(blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ['-created_at']
