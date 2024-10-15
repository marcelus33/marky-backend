from django.urls import path
from .views import RegisterView, LoginView, VerifyEmailView, PasswordRecoveryView, PasswordChangeView

urlpatterns = [
    path('register/', RegisterView.as_view(), name='register'),
    path('verify/', VerifyEmailView.as_view(), name='verify'),
    path('login/', LoginView.as_view(), name='login'),
    path('password-recovery/', PasswordRecoveryView.as_view(), name='password-recovery'),
    path('password-change/', PasswordChangeView.as_view(), name='password-change'),
]
