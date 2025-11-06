from django.contrib import admin
from django.contrib.auth.admin import UserAdmin
from .models import CustomUser, VerificationCode, SecurityQuestion, AccessLog


@admin.register(CustomUser)
class CustomUserAdmin(UserAdmin):
    fieldsets = UserAdmin.fieldsets + (
        (
            'MFA y estado',
            {
                'fields': (
                    'phone_number',
                    'is_email_verified',
                    'is_phone_verified',
                    'mfa_method',
                    'failed_login_attempts',
                    'locked_until',
                    'last_session_key',
                )
            },
        ),
    )
    list_display = ('username', 'email', 'phone_number', 'mfa_method', 'is_email_verified', 'is_phone_verified', 'is_active')


@admin.register(VerificationCode)
class VerificationCodeAdmin(admin.ModelAdmin):
    list_display = ('user', 'purpose', 'code', 'sent_to', 'created_at', 'expires_at', 'used_at')
    list_filter = ('purpose', 'created_at')


@admin.register(SecurityQuestion)
class SecurityQuestionAdmin(admin.ModelAdmin):
    list_display = ('user', 'question')


@admin.register(AccessLog)
class AccessLogAdmin(admin.ModelAdmin):
    list_display = ('action', 'user', 'ip_address', 'created_at')
    list_filter = ('action', 'created_at')

# Register your models here.
