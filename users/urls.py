from django.urls import path
from .views import UserChangePasswordView, UserRegisterView, UserLoginView, UserLogoutView, home_view

urlpatterns = [
    path("", home_view, name="home-page"),
    path("register/", UserRegisterView.as_view(), name="register-page"),
    path("login/", UserLoginView.as_view(), name="login-page"),
    path("logout/", UserLogoutView.as_view(), name="logout-page"),
    path("password/change/", UserChangePasswordView.as_view(), name="password_change-page"),
]
