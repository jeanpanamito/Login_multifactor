from django.shortcuts import render, redirect
from django.contrib import messages
from django.contrib.auth import authenticate, login, logout, get_user_model
from django.contrib.auth.decorators import login_required
from django.contrib.sessions.models import Session
from django.utils import timezone
from django.core.mail import send_mail
from django.conf import settings
from django.views.decorators.http import require_http_methods
from django import forms
import random
from datetime import timedelta
from django.utils.crypto import get_random_string
from django_otp.plugins.otp_totp.models import TOTPDevice

from .models import VerificationCode, AccessLog, SecurityQuestion


User = get_user_model()


def _client_ip(request):
    xff = request.META.get('HTTP_X_FORWARDED_FOR')
    if xff:
        return xff.split(',')[0].strip()
    return request.META.get('REMOTE_ADDR')


def _log(action: str, request, user=None):
    AccessLog.objects.create(
        action=action,
        user=user if isinstance(user, User) else None,
        ip_address=_client_ip(request),
        user_agent=request.META.get('HTTP_USER_AGENT', '')[:500],
    )


def _generate_code() -> str:
    return f"{random.randint(0, 999999):06d}"


def _issue_code(user: User, purpose: str, channel: str, destination: str):
    code = _generate_code()
    vc = VerificationCode.objects.create(
        user=user,
        code=code,
        purpose=purpose,
        sent_to=destination,
        expires_at=timezone.now() + timedelta(minutes=10),
    )
    subject = 'Código de verificación'
    body = f"Tu código es: {code} (válido por 10 minutos)"
    if channel == 'email':
        if destination:
            send_mail(subject, body, settings.DEFAULT_FROM_EMAIL, [destination])
    elif channel == 'sms':
        # Simulación SMS (consola)
        print(f"SMS a {destination}: {body}")
    return vc


class RegisterForm(forms.Form):
    first_name = forms.CharField(max_length=150)
    last_name = forms.CharField(max_length=150)
    email = forms.EmailField()
    phone_number = forms.CharField(max_length=32, required=False)
    mfa_method = forms.ChoiceField(choices=User.MFA_METHOD_CHOICES)


@require_http_methods(["GET", "POST"])
def register_view(request):
    form = RegisterForm(request.POST or None)
    if request.method == 'POST' and form.is_valid():
        data = form.cleaned_data
        # Generar usuario y contraseña
        base_username = data['email'].split('@')[0]
        username = base_username
        i = 1
        while User.objects.filter(username=username).exists():
            username = f"{base_username}{i}"
            i += 1
        temp_password = get_random_string(12)
        user = User.objects.create_user(
            username=username,
            email=data['email'],
            password=temp_password,
            first_name=data['first_name'],
            last_name=data['last_name'],
            phone_number=data.get('phone_number', ''),
            mfa_method=data['mfa_method'],
            is_active=False,
        )
        _log('create_user', request, user)
        totp_info = None
        # Enviar verificación (email o sms)
        if user.mfa_method == User.MFA_METHOD_TOTP:
            # Crear dispositivo TOTP y mostrar URI para enrolar en Authenticator
            device = TOTPDevice.objects.create(user=user, name='default', confirmed=True)
            totp_info = {
                'otpauth_url': device.config_url,
            }
            # Activar cuenta directamente para pruebas
            user.is_active = True
            user.is_email_verified = bool(user.email)
            user.save(update_fields=['is_active', 'is_email_verified'])
        else:
            if data['email']:
                _issue_code(user, VerificationCode.TYPE_ACTIVATION, 'email', data['email'])
            if user.phone_number:
                _issue_code(user, VerificationCode.TYPE_ACTIVATION, 'sms', user.phone_number)
        messages.success(request, f"Usuario creado. Usuario: {username}. Se envió un código de activación.")
        # Guardar credenciales iniciales visibles una sola vez
        request.session['last_temp_credentials'] = {'username': username, 'password': temp_password, 'totp': totp_info}
        return redirect('register')
    last_creds = request.session.pop('last_temp_credentials', None)
    return render(request, 'accounts/register.html', {'form': form, 'last_creds': last_creds})


class ActivateForm(forms.Form):
    username = forms.CharField()
    code = forms.CharField(max_length=6)


@require_http_methods(["GET", "POST"])
def activate_view(request):
    form = ActivateForm(request.POST or None)
    if request.method == 'POST' and form.is_valid():
        username = form.cleaned_data['username']
        code = form.cleaned_data['code']
        try:
            user = User.objects.get(username=username)
        except User.DoesNotExist:
            user = None
        if not user:
            messages.error(request, 'Usuario no encontrado.')
        else:
            vc = VerificationCode.objects.filter(user=user, purpose=VerificationCode.TYPE_ACTIVATION).order_by('-created_at').first()
            if vc and vc.is_valid() and vc.code == code:
                vc.used_at = timezone.now()
                vc.save(update_fields=['used_at'])
                # Marcar verificación en correo o teléfono según destino
                if vc.sent_to and '@' in vc.sent_to:
                    user.is_email_verified = True
                else:
                    user.is_phone_verified = True
                user.is_active = True
                user.save(update_fields=['is_email_verified', 'is_phone_verified', 'is_active'])
                messages.success(request, 'Cuenta activada. Ya puedes iniciar sesión.')
                return redirect('login')
            messages.error(request, 'Código inválido o expirado.')
    return render(request, 'accounts/activate.html', {'form': form})


class LoginForm(forms.Form):
    username = forms.CharField()
    password = forms.CharField(widget=forms.PasswordInput)


@require_http_methods(["GET", "POST"])
def login_view(request):
    if request.user.is_authenticated:
        return redirect('mfa')
    form = LoginForm(request.POST or None)
    if request.method == 'POST' and form.is_valid():
        username = form.cleaned_data['username']
        password = form.cleaned_data['password']
        try:
            user = User.objects.get(username=username)
        except User.DoesNotExist:
            user = None
        if user and user.is_locked():
            messages.error(request, 'Cuenta bloqueada temporalmente. Use el flujo de desbloqueo.')
            _log('login_failure', request, user)
            return redirect('unlock')
        user_auth = authenticate(request, username=username, password=password)
        if user_auth is not None:
            # Paso 1 OK, continuar a MFA
            request.session['pending_user_id'] = user_auth.id
            # emitir código si aplica
            if user_auth.mfa_method in (User.MFA_METHOD_EMAIL, User.MFA_METHOD_SMS):
                channel = 'email' if user_auth.mfa_method == User.MFA_METHOD_EMAIL else 'sms'
                dest = user_auth.email if channel == 'email' else user_auth.phone_number
                _issue_code(user_auth, VerificationCode.TYPE_LOGIN_MFA, channel, dest)
            return redirect('mfa')
        else:
            messages.error(request, 'Credenciales inválidas.')
            if user:
                user.failed_login_attempts = (user.failed_login_attempts or 0) + 1
                if user.failed_login_attempts >= 4:
                    user.locked_until = timezone.now() + timedelta(minutes=15)
                user.save(update_fields=['failed_login_attempts', 'locked_until'])
            _log('login_failure', request, user)
    return render(request, 'accounts/login.html', {'form': form})


class MFAForm(forms.Form):
    code = forms.CharField(max_length=6, required=False)
    answer = forms.CharField(max_length=255, required=False)


@require_http_methods(["GET", "POST"])
def mfa_view(request):
    pending_user_id = request.session.get('pending_user_id')
    if not pending_user_id:
        return redirect('login')
    user = User.objects.get(id=pending_user_id)
    form = MFAForm(request.POST or None)
    if request.method == 'POST' and form.is_valid():
        if user.mfa_method == User.MFA_METHOD_SECURITY_Q:
            answer = form.cleaned_data.get('answer', '')
            sq = getattr(user, 'security_question', None)
            if sq and sq.answer.strip().lower() == answer.strip().lower():
                # éxito
                _finalize_login(request, user)
                return redirect('login')
            messages.error(request, 'Respuesta incorrecta.')
        elif user.mfa_method in (User.MFA_METHOD_EMAIL, User.MFA_METHOD_SMS):
            code = form.cleaned_data.get('code', '')
            vc = VerificationCode.objects.filter(user=user, purpose=VerificationCode.TYPE_LOGIN_MFA).order_by('-created_at').first()
            if vc and vc.is_valid() and vc.code == code:
                vc.used_at = timezone.now()
                vc.save(update_fields=['used_at'])
                _finalize_login(request, user)
                return redirect('login')
            messages.error(request, 'Código inválido o expirado.')
        elif user.mfa_method == User.MFA_METHOD_TOTP:
            token = form.cleaned_data.get('code', '')
            device = TOTPDevice.objects.filter(user=user, confirmed=True).first()
            if device and token and device.verify_token(token):
                _finalize_login(request, user)
                return redirect('login')
            messages.error(request, 'Token TOTP inválido.')
    return render(request, 'accounts/mfa.html', {'form': form, 'user_obj': user})


def _finalize_login(request, user: User):
    # Enforce single session: end previous if exists
    if user.last_session_key:
        try:
            Session.objects.get(session_key=user.last_session_key).delete()
        except Session.DoesNotExist:
            pass
    login(request, user)
    request.session.set_expiry(60 * 60 * 2)
    user.last_session_key = request.session.session_key
    user.failed_login_attempts = 0
    user.locked_until = None
    user.save(update_fields=['last_session_key', 'failed_login_attempts', 'locked_until'])
    _log('login_success', request, user)


@login_required
def logout_view(request):
    _log('logout', request, request.user)
    logout(request)
    return redirect('login')


class UnlockForm(forms.Form):
    username = forms.CharField()
    code = forms.CharField(max_length=6, required=False)


@require_http_methods(["GET", "POST"])
def unlock_view(request):
    form = UnlockForm(request.POST or None)
    if request.method == 'POST' and form.is_valid():
        username = form.cleaned_data['username']
        code = form.cleaned_data.get('code')
        try:
            user = User.objects.get(username=username)
        except User.DoesNotExist:
            user = None
        if user and not code:
            # enviar código de desbloqueo al correo
            _issue_code(user, VerificationCode.TYPE_UNLOCK, 'email', user.email)
            messages.info(request, 'Se envió un código de desbloqueo a su correo.')
        elif user and code:
            vc = VerificationCode.objects.filter(user=user, purpose=VerificationCode.TYPE_UNLOCK).order_by('-created_at').first()
            if vc and vc.is_valid() and vc.code == code:
                vc.used_at = timezone.now()
                vc.save(update_fields=['used_at'])
                user.failed_login_attempts = 0
                user.locked_until = None
                user.save(update_fields=['failed_login_attempts', 'locked_until'])
                messages.success(request, 'Cuenta desbloqueada. Intente iniciar sesión nuevamente.')
                return redirect('login')
            messages.error(request, 'Código inválido o expirado.')
        else:
            messages.error(request, 'Usuario no encontrado.')
    return render(request, 'accounts/unlock.html', {'form': form})


class RecoverForm(forms.Form):
    email = forms.EmailField()


@require_http_methods(["GET", "POST"])
def recover_view(request):
    form = RecoverForm(request.POST or None)
    if request.method == 'POST' and form.is_valid():
        email = form.cleaned_data['email']
        try:
            user = User.objects.get(email=email)
        except User.DoesNotExist:
            user = None
        if user:
            # Enviar recordatorio del usuario y enlace de restablecimiento
            send_mail(
                'Recuperación de cuenta',
                f"Tu usuario es: {user.username}\nPara restablecer tu contraseña, ingresa al admin o implementa flujo de reset.",
                'no-reply@example.com',
                [email],
            )
            messages.success(request, 'Se enviaron instrucciones a su correo.')
        else:
            messages.error(request, 'Correo no encontrado.')
    return render(request, 'accounts/recover.html', {'form': form})


# Create your views here.
