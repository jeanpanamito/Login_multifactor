from django.urls import path
from . import views


urlpatterns = [
    path('register/', views.register_view, name='register'),
    path('activate/', views.activate_view, name='activate'),
    path('login/', views.login_view, name='login'),
    path('mfa/', views.mfa_view, name='mfa'),
    path('logout/', views.logout_view, name='logout'),
    path('unlock/', views.unlock_view, name='unlock'),
    path('recover/', views.recover_view, name='recover'),
    path('recover/reset/', views.recover_reset_view, name='recover_reset'),
]


