from django.contrib.auth.views import (
    PasswordResetView,
    PasswordResetDoneView,
    PasswordResetConfirmView,
    PasswordResetCompleteView,
)
from django.urls import path

from .views import (
    UserChangePasswordView,
    UserRegisterView,
    UserLoginView,
    UserLogoutView,
    UserResendVerificationView,
    UserVerifyView,
    home_view
)

urlpatterns = [
    path("", home_view, name="home-page"),
    path("register/", UserRegisterView.as_view(), name="register-page"),
    path("resend-verification/", UserResendVerificationView.as_view(), name="resend_verification-page"),
    path("verify/<uidb64>/<token>/", UserVerifyView.as_view(), name="user-verify-page"),
    path("login/", UserLoginView.as_view(), name="login-page"),
    path("logout/", UserLogoutView.as_view(), name="logout-page"),
    path("password/change/", UserChangePasswordView.as_view(), name="password_change-page"),
    path("password_reset/",
        PasswordResetView.as_view(template_name="password_reset/password_reset.html"),
        name="password_reset"),
    path("password_reset/done/",
        PasswordResetDoneView.as_view(template_name="password_reset/password_reset_done.html"),
        name="password_reset_done"),
    path("reset/<uidb64>/<token>/",
        PasswordResetConfirmView.as_view(template_name="password_reset/password_reset_confirm.html"),
        name="password_reset_confirm"),
    path("reset/done/",
        PasswordResetCompleteView.as_view(template_name="password_reset/password_reset_complete.html"),
        name="password_reset_complete"),
]
