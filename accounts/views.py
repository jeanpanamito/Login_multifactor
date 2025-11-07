from django.shortcuts import render, redirect
from django.contrib import messages
from django.contrib.auth import authenticate, login, logout, get_user_model
from django.contrib.auth.decorators import login_required
from django.contrib.sessions.models import Session as DjangoSession
from django.utils import timezone
from django.views.decorators.http import require_http_methods
from django import forms
from django.utils.crypto import get_random_string
from django_otp.plugins.otp_totp.models import TOTPDevice
from datetime import timedelta
import random

from .models import (
    VerificationCode, AccessLog, SecurityQuestion, 
    AccessAttempt, AccountRecovery, AccountUnlock, Session
)


User = get_user_model()


def _client_ip(request):
    """Obtiene la IP del cliente"""
    xff = request.META.get('HTTP_X_FORWARDED_FOR')
    if xff:
        return xff.split(',')[0].strip()
    return request.META.get('REMOTE_ADDR')


def _user_agent(request):
    """Obtiene el user agent del cliente"""
    return request.META.get('HTTP_USER_AGENT', '')[:500]


class RegisterForm(forms.Form):
    """RS1 F1.1: Formulario de registro"""
    first_name = forms.CharField(max_length=150)
    last_name = forms.CharField(max_length=150)
    email = forms.EmailField()
    phone_number = forms.CharField(max_length=32, required=False)
    activation_method = forms.ChoiceField(
        choices=User.ACTIVATION_METHOD_CHOICES,
        initial=User.ACTIVATION_EMAIL
    )


@require_http_methods(["GET", "POST"])
def register_view(request):
    """RS1: Vista de registro de nuevos usuarios"""
    form = RegisterForm(request.POST or None)
    if request.method == 'POST' and form.is_valid():
        data = form.cleaned_data
        
        # RS1 F1.2: Generar usuario y contraseña
        base_username = data['email'].split('@')[0]
        username = base_username
        i = 1
        while User.objects.filter(username=username).exists():
            username = f"{base_username}{i}"
            i += 1
        
        temp_password = get_random_string(12)
        
        # RS1 F1.3: Generar código de activación
        activation_code = f"{random.randint(0, 999999):06d}"
        activation_expires_at = timezone.now() + timedelta(minutes=30)
        
        # RS1 F1.2: Crear usuario con is_active=False
        user = User.objects.create_user(
            username=username,
            email=data['email'],
            password=temp_password,
            first_name=data['first_name'],
            last_name=data['last_name'],
            phone_number=data.get('phone_number', ''),
            is_active=False,
            activation_method=data['activation_method'],
            activation_code=activation_code,
            activation_expires_at=activation_expires_at,
        )
        
        # RS3 F3.1: Registrar creación de usuario
        user.logAttempt(
            attempt_type=AccessAttempt.ATTEMPT_USER_CREATION,
            success=True,
            source_ip=_client_ip(request),
            source_device=_user_agent(request)
        )
        
        # RS1 F1.4: Enviar notificación de activación
        if user.activation_method == User.ACTIVATION_EMAIL:
            from django.core.mail import send_mail
            from django.conf import settings
            subject = 'Código de activación de cuenta'
            body = f"Tu código de activación es: {activation_code}\n"
            body += f"Válido por 30 minutos.\n"
            body += f"Usuario: {username}\n"
            body += f"Contraseña temporal: {temp_password}"
            send_mail(subject, body, settings.DEFAULT_FROM_EMAIL, [user.email])
        elif user.activation_method == User.ACTIVATION_PHONE and user.phone_number:
            print(f"SMS a {user.phone_number}: Tu código de activación es: {activation_code}")
        
        messages.success(request, f"Usuario creado. Usuario: {username}. Se envió un código de activación.")
        request.session['last_temp_credentials'] = {'username': username, 'password': temp_password}
        return redirect('register')
    
    last_creds = request.session.pop('last_temp_credentials', None)
    return render(request, 'accounts/register.html', {'form': form, 'last_creds': last_creds})


class ActivateForm(forms.Form):
    """RS1 F1.5: Formulario de activación"""
    username = forms.CharField()
    code = forms.CharField(max_length=6)


@require_http_methods(["GET", "POST"])
def activate_view(request):
    """RS1 F1.5-F1.6: Vista de activación de cuenta"""
    form = ActivateForm(request.POST or None)
    if request.method == 'POST' and form.is_valid():
        username = form.cleaned_data['username']
        code = form.cleaned_data['code']
        
        try:
            user = User.objects.get(username=username)
        except User.DoesNotExist:
            messages.error(request, 'Usuario no encontrado.')
            return render(request, 'accounts/activate.html', {'form': form})
        
        # RS1 F1.6: Usar método User.activate(code)
        if user.activate(code):
            messages.success(request, 'Cuenta activada. Ya puedes iniciar sesión.')
            return redirect('login')
        else:
            messages.error(request, 'Código inválido o expirado.')
    
    return render(request, 'accounts/activate.html', {'form': form})


class LoginForm(forms.Form):
    """RS2 F2.1: Formulario de login primario"""
    username = forms.CharField()
    password = forms.CharField(widget=forms.PasswordInput)


@require_http_methods(["GET", "POST"])
def login_view(request):
    """RS2: Vista de login con detección de MFA"""
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
        
        # RS6: Verificar si está bloqueado
        if user and user.check_is_locked():
            messages.error(request, 'Cuenta bloqueada temporalmente. Use el flujo de desbloqueo.')
            user.logAttempt(
                attempt_type=AccessAttempt.ATTEMPT_LOGIN,
                success=False,
                source_ip=_client_ip(request),
                source_device=_user_agent(request),
                failure_reason='Cuenta bloqueada'
            )
            return redirect('unlock')
        
        # RS2 F2.1: Validar username y password
        user_auth = authenticate(request, username=username, password=password)
        
        if user_auth is not None:
            # RS3 F3.2: Registrar intento exitoso
            user_auth.logAttempt(
                attempt_type=AccessAttempt.ATTEMPT_LOGIN,
                success=True,
                source_ip=_client_ip(request),
                source_device=_user_agent(request)
            )
            
            # RS2 F2.2: Detectar MFA y preparar segundo factor
            request.session['pending_user_id'] = user_auth.id
            
            # RS2 F2.4: Generar y enviar código si aplica
            mfa_methods = user_auth.mfa_methods.filter(is_enabled=True)
            if mfa_methods.exists():
                mfa_method = mfa_methods.first()
                mfa_method.sendNotification()
                request.session['pending_mfa_id'] = mfa_method.id
            else:
                # Si no hay MFA configurado, usar el método por defecto del usuario
                # Crear un MFAMethod temporal si no existe
                if not user_auth.mfa_methods.exists():
                    mfa_method = user_auth.addMFADevice(user_auth.mfa_method.upper())
                    mfa_method.sendNotification()
                    request.session['pending_mfa_id'] = mfa_method.id
                else:
                    mfa_method = user_auth.mfa_methods.first()
                    mfa_method.sendNotification()
                    request.session['pending_mfa_id'] = mfa_method.id
            
            return redirect('mfa')
        else:
            # RS3 F3.2: Registrar intento fallido
            if user:
                user.logAttempt(
                    attempt_type=AccessAttempt.ATTEMPT_LOGIN,
                    success=False,
                    source_ip=_client_ip(request),
                    source_device=_user_agent(request),
                    failure_reason='Credenciales inválidas'
                )
                
                # RS6 F6.2-F6.4: Verificar y bloquear si es necesario
                failed_count = user.checkFailedAttempts()
                if failed_count >= 4:
                    user.lock()
                    messages.error(request, 'Cuenta bloqueada por múltiples intentos fallidos.')
                    return redirect('unlock')
                else:
                    user.failed_login_attempts = failed_count
                    user.save(update_fields=['failed_login_attempts'])
            
            messages.error(request, 'Credenciales inválidas.')
    
    return render(request, 'accounts/login.html', {'form': form})


class MFAForm(forms.Form):
    """RS2 F2.4: Formulario de verificación MFA"""
    code = forms.CharField(max_length=6, required=False)
    answer = forms.CharField(max_length=255, required=False)


@require_http_methods(["GET", "POST"])
def mfa_view(request):
    """RS2 F2.4-F2.5: Vista de verificación MFA"""
    pending_user_id = request.session.get('pending_user_id')
    if not pending_user_id:
        return redirect('login')
    
    user = User.objects.get(id=pending_user_id)
    mfa_id = request.session.get('pending_mfa_id')
    
    form = MFAForm(request.POST or None)
    if request.method == 'POST' and form.is_valid():
        code = form.cleaned_data.get('code', '')
        answer = form.cleaned_data.get('answer', '')
        
        # RS2 F2.5: Usar User.validateMFA() o validación directa
        if mfa_id:
            try:
                mfa_method = user.mfa_methods.get(id=mfa_id, is_enabled=True)
                input_value = code if code else answer
                if mfa_method.validate(input_value):
                    _finalize_login(request, user)
                    return redirect('login')
                else:
                    messages.error(request, 'Código o respuesta incorrecta.')
            except Exception as e:
                messages.error(request, 'Error al validar MFA.')
        else:
            messages.error(request, 'Método MFA no encontrado.')
    
    # Obtener método MFA activo para mostrar en template
    mfa_method = None
    if mfa_id:
        try:
            mfa_method = user.mfa_methods.get(id=mfa_id, is_enabled=True)
        except:
            pass
    
    return render(request, 'accounts/mfa.html', {
        'form': form, 
        'user_obj': user,
        'mfa_method': mfa_method
    })


def _finalize_login(request, user: User):
    """RS5 F5.3 y RS7 F7.1: Finaliza el login creando sesión"""
    # RS5 F5.3: Terminar sesión activa si existe
    user.terminateActiveSession()
    
    # RS7 F7.1: Crear nueva sesión
    session_token = get_random_string(64)
    session = Session.objects.create(
        user=user,
        session_token=session_token,
        session_ip=_client_ip(request),
        session_device=_user_agent(request),
        expires_at=timezone.now() + timedelta(hours=2)
    )
    
    # Login de Django
    login(request, user)
    request.session.set_expiry(60 * 60 * 2)  # 2 horas
    user.last_session_key = request.session.session_key
    user.failed_login_attempts = 0
    user.locked_until = None
    user.save(update_fields=['last_session_key', 'failed_login_attempts', 'locked_until'])
    
    # Guardar referencia a nuestra sesión
    request.session['custom_session_id'] = str(session.id)


@login_required
def logout_view(request):
    """RS7 F7.4: Vista de logout"""
    # Terminar sesión personalizada
    custom_session_id = request.session.get('custom_session_id')
    if custom_session_id:
        try:
            session = Session.objects.get(id=custom_session_id)
            session.terminate()
        except Session.DoesNotExist:
            pass
    
    # RS3: Registrar logout
    request.user.logAttempt(
        attempt_type=AccessAttempt.ATTEMPT_LOGIN,  # Usar tipo LOGIN para logout también
        success=True,
        source_ip=_client_ip(request),
        source_device=_user_agent(request)
    )
    
    logout(request)
    return redirect('login')


class UnlockForm(forms.Form):
    """RS6 F6.5: Formulario de desbloqueo"""
    username = forms.CharField()
    code = forms.CharField(max_length=6, required=False)


@require_http_methods(["GET", "POST"])
def unlock_view(request):
    """RS6 F6.5-F6.7: Vista de desbloqueo de cuenta"""
    form = UnlockForm(request.POST or None)
    if request.method == 'POST' and form.is_valid():
        username = form.cleaned_data['username']
        code = form.cleaned_data.get('code')
        
        try:
            user = User.objects.get(username=username)
        except User.DoesNotExist:
            messages.error(request, 'Usuario no encontrado.')
            return render(request, 'accounts/unlock.html', {'form': form})
        
        if not code:
            # RS6 F6.6: Iniciar proceso de desbloqueo
            unlock_request = AccountUnlock.objects.create(user=user)
            unlock_request.generateCode()
            unlock_request.sendNotification()
            
            # RS3 F3.3: Registrar intento de desbloqueo
            user.logAttempt(
                attempt_type=AccessAttempt.ATTEMPT_ACCOUNT_UNLOCK,
                success=False,
                source_ip=_client_ip(request),
                source_device=_user_agent(request)
            )
            
            messages.info(request, 'Se envió un código de desbloqueo a su correo.')
        elif code:
            # RS6 F6.7: Usar User.unlock(code)
            if user.unlock(code):
                # RS3 F3.3: Registrar desbloqueo exitoso
                user.logAttempt(
                    attempt_type=AccessAttempt.ATTEMPT_ACCOUNT_UNLOCK,
                    success=True,
                    source_ip=_client_ip(request),
                    source_device=_user_agent(request)
                )
                messages.success(request, 'Cuenta desbloqueada. Intente iniciar sesión nuevamente.')
                return redirect('login')
            else:
                messages.error(request, 'Código inválido o expirado.')
    
    return render(request, 'accounts/unlock.html', {'form': form})


class RecoverForm(forms.Form):
    """RS4 F4.1: Formulario de recuperación"""
    email = forms.EmailField()


@require_http_methods(["GET", "POST"])
def recover_view(request):
    """RS4 F4.1-F4.6: Vista de recuperación de contraseña"""
    form = RecoverForm(request.POST or None)
    if request.method == 'POST' and form.is_valid():
        email = form.cleaned_data['email']
        
        try:
            user = User.objects.get(email=email)
        except User.DoesNotExist:
            messages.error(request, 'Correo no encontrado.')
            return render(request, 'accounts/recover.html', {'form': form})
        
        # RS4 F4.2: Usar User.requestPasswordReset()
        recovery = user.requestPasswordReset()
        
        # RS3 F3.3: Registrar intento de reseteo
        user.logAttempt(
            attempt_type=AccessAttempt.ATTEMPT_PASSWORD_RESET,
            success=True,
            source_ip=_client_ip(request),
            source_device=_user_agent(request)
        )
        
        messages.success(request, 'Se enviaron instrucciones a su correo.')
        request.session['recovery_user_id'] = user.id
        return redirect('recover')
    
    # Si hay un usuario en proceso de recuperación, mostrar formulario de reset
    recovery_user_id = request.session.get('recovery_user_id')
    if recovery_user_id:
        try:
            user = User.objects.get(id=recovery_user_id)
            return render(request, 'accounts/recover.html', {
                'form': form,
                'show_reset_form': True,
                'user': user
            })
        except User.DoesNotExist:
            pass
    
    return render(request, 'accounts/recover.html', {'form': form})


@require_http_methods(["POST"])
def recover_reset_view(request):
    """RS4 F4.5-F4.6: Vista para resetear contraseña con código"""
    recovery_user_id = request.session.get('recovery_user_id')
    if not recovery_user_id:
        return redirect('recover')
    
    try:
        user = User.objects.get(id=recovery_user_id)
    except User.DoesNotExist:
        return redirect('recover')
    
    code = request.POST.get('code', '')
    new_password = request.POST.get('new_password', '')
    confirm_password = request.POST.get('confirm_password', '')
    
    if not code or not new_password:
        messages.error(request, 'Todos los campos son requeridos.')
        return redirect('recover')
    
    if new_password != confirm_password:
        messages.error(request, 'Las contraseñas no coinciden.')
        return redirect('recover')
    
    # RS4 F4.6: Usar User.validatePasswordReset()
    if user.validatePasswordReset(code, new_password):
        # RS3 F3.3: Registrar reseteo exitoso
        user.logAttempt(
            attempt_type=AccessAttempt.ATTEMPT_PASSWORD_RESET,
            success=True,
            source_ip=_client_ip(request),
            source_device=_user_agent(request)
        )
        messages.success(request, 'Contraseña restablecida exitosamente.')
        request.session.pop('recovery_user_id', None)
        return redirect('login')
    else:
        messages.error(request, 'Código inválido o expirado.')
        return redirect('recover')
