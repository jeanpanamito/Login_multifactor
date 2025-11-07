from django.contrib import admin
from django.contrib.auth.admin import UserAdmin
from .models import (
    CustomUser, VerificationCode, SecurityQuestion, AccessLog,
    MFAMethod, AccessAttempt, AccountRecovery, AccountUnlock, Session
)


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
                    'activation_method',
                    'is_locked',
                    'failed_login_attempts',
                    'locked_until',
                    'last_session_key',
                )
            },
        ),
    )
    list_display = ('username', 'email', 'phone_number', 'mfa_method', 'is_email_verified', 'is_phone_verified', 'is_active', 'is_locked')


@admin.register(VerificationCode)
class VerificationCodeAdmin(admin.ModelAdmin):
    list_display = ('user', 'purpose', 'code', 'sent_to', 'created_at', 'expires_at', 'used_at')
    list_filter = ('purpose', 'created_at')
    search_fields = ('user__username', 'user__email', 'code')


@admin.register(SecurityQuestion)
class SecurityQuestionAdmin(admin.ModelAdmin):
    list_display = ('mfa_method', 'question')
    search_fields = ('question', 'mfa_method__user__username')
    readonly_fields = ('mfa_method',)


@admin.register(MFAMethod)
class MFAMethodAdmin(admin.ModelAdmin):
    list_display = ('user', 'method_type', 'is_enabled', 'device_name', 'created_at')
    list_filter = ('method_type', 'is_enabled', 'created_at')
    search_fields = ('user__username', 'user__email', 'device_name')
    readonly_fields = ('created_at',)


@admin.register(AccessAttempt)
class AccessAttemptAdmin(admin.ModelAdmin):
    list_display = ('user', 'attempt_type', 'attempt_time', 'success', 'source_ip', 'failure_reason')
    list_filter = ('attempt_type', 'success', 'attempt_time')
    search_fields = ('user__username', 'user__email', 'source_ip')
    readonly_fields = ('attempt_time',)
    date_hierarchy = 'attempt_time'


@admin.register(AccountRecovery)
class AccountRecoveryAdmin(admin.ModelAdmin):
    list_display = ('user', 'recovery_email', 'requested_at', 'expires_at', 'completed_at')
    list_filter = ('requested_at', 'completed_at')
    search_fields = ('user__username', 'user__email', 'recovery_email')
    readonly_fields = ('requested_at',)


@admin.register(AccountUnlock)
class AccountUnlockAdmin(admin.ModelAdmin):
    list_display = ('user', 'requested_at', 'expires_at', 'completed_at')
    list_filter = ('requested_at', 'completed_at')
    search_fields = ('user__username', 'user__email')
    readonly_fields = ('requested_at',)


@admin.register(Session)
class SessionAdmin(admin.ModelAdmin):
    list_display = ('user', 'session_token', 'started_at', 'last_activity_at', 'is_active', 'session_ip')
    list_filter = ('is_active', 'started_at')
    search_fields = ('user__username', 'user__email', 'session_token', 'session_ip')
    readonly_fields = ('started_at', 'last_activity_at')


@admin.register(AccessLog)
class AccessLogAdmin(admin.ModelAdmin):
    list_display = ('action', 'user', 'ip_address', 'created_at')
    list_filter = ('action', 'created_at')
    search_fields = ('user__username', 'user__email', 'ip_address')
