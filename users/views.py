from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.contrib.auth.views import LoginView, LogoutView, PasswordChangeView
from django.shortcuts import redirect, render
from django.urls import reverse_lazy
from django.views.generic import View, CreateView

from .forms import ResendVerificationForm, UserChangePasswordForm, UserRegisterForm, UserLoginForm
from .models import User
from .utils import (
    generate_user_verification_tokens,
    send_email_with_user_verification_link,
    get_user_from_uidb64,
    verify_user,
    verify_user_token
)


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

        uidb64, token = generate_user_verification_tokens(user)
        verification_url = self.request.build_absolute_uri(
            reverse_lazy("user-verify-page",
                         kwargs={"uidb64": uidb64, "token": token})
        )

        send_email_with_user_verification_link(user, verification_url)
        return render(self.request, "verify/email_sent.html", {"user": user})

    def form_invalid(self, form):
        return super().form_invalid(form)

    def dispatch(self, request, *args, **kwargs):
        if request.user.is_authenticated:
            return redirect("home-page")
        return super().dispatch(request, *args, **kwargs)


class UserVerifyView(View):
    def get(self, request, uidb64, token):
        user = get_user_from_uidb64(uidb64)

        if user and verify_user_token(user, token):
            verify_user(user)
            messages.success(
                request, "Your account is now activated. You can log in.")
            return redirect("login-page")

        else:
            return render(request, "verify/invalid_link.html")


class UserResendVerificationView(View):
    def get(self, request):
        form = ResendVerificationForm()
        return render(request, "verify/resend_verification.html", {"form": form})

    def post(self, request):
        form = ResendVerificationForm(request.POST)

        if form.is_valid():
            email = form.cleaned_data["email"]
            user = User.objects.filter(email=email).first()

            if user:
                if user.is_active:
                    messages.success(
                        request, "Your account is now activated. You can log in.")
                    return redirect("login-page")
                else:
                    uidb64, token = generate_user_verification_tokens(user)
                    verification_url = request.build_absolute_uri(
                        reverse_lazy("user-verify-page",
                                     kwargs={"uidb64": uidb64, "token": token})
                    )
                    send_email_with_user_verification_link(
                        user, verification_url)
                    return render(self.request, "verify/email_sent.html", {"user": user})

            messages.error(
                request, "An account with this email was not found.", extra_tags="danger")
            return redirect("resend_verification-page")


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
