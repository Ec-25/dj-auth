from django.contrib.auth import login
from django.contrib.auth.decorators import login_required
from django.contrib.auth.views import LoginView, LogoutView, PasswordChangeView
from django.shortcuts import redirect, render
from django.urls import reverse_lazy
from django.views.generic import CreateView

from .forms import UserChangePasswordForm, UserRegisterForm, UserLoginForm
from .models import User


@login_required(login_url=reverse_lazy("login-page"))
def home_view(request):
    return render(request, "home.html")


class UserRegisterView(CreateView):
    model = User
    form_class = UserRegisterForm
    template_name = "register.html"
    success_url = reverse_lazy("login-page")

    def form_valid(self, form):
        user = form.save()
        login(self.request, user)
        return redirect("home-page")

    def form_invalid(self, form):
        return super().form_invalid(form)

    def dispatch(self, request, *args, **kwargs):
        if request.user.is_authenticated:
            return redirect("home-page")
        return super().dispatch(request, *args, **kwargs)


class UserLoginView(LoginView):
    form_class = UserLoginForm
    template_name = "login.html"

    def get_success_url(self):
        return reverse_lazy("home-page")

    def form_invalid(self, form):
        return super().form_invalid(form)

    def dispatch(self, request, *args, **kwargs):
        if request.user.is_authenticated:
            return redirect("home-page")
        return super().dispatch(request, *args, **kwargs)


class UserLogoutView(LogoutView):
    template_name = "logout.html"
    # next_page = reverse_lazy("login-page")


class UserChangePasswordView(PasswordChangeView):
    form_class = UserChangePasswordForm
    template_name = "change_password.html"
    success_url = reverse_lazy("home-page")

    def form_valid(self, form):
        form.save()
        return super().form_valid(form)

    def form_invalid(self, form):
        return super().form_invalid(form)

    def dispatch(self, request, *args, **kwargs):
        if not request.user.is_authenticated:
            return redirect("login-page")
        return super().dispatch(request, *args, **kwargs)
