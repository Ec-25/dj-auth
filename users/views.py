from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.contrib.auth.mixins import LoginRequiredMixin
from django.contrib.auth.views import LoginView, LogoutView, PasswordChangeView
from django.shortcuts import redirect, render
from django.urls import reverse_lazy
from django.views.generic import View, CreateView, UpdateView

from .forms import ResendVerificationForm, UserChangePasswordForm, UserDeleteForm, UserRegisterForm, UserLoginForm, UserUpdateForm
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
    next_page = reverse_lazy("home-page")

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


class UserProfileView(LoginRequiredMixin, View):
    template_name = "profile.html"
    login_url = reverse_lazy("login-page")

    def get(self, request, *args, **kwargs):
        return render(request, self.template_name)


class UserUpdateView(LoginRequiredMixin, UpdateView):
    model = User
    form_class = UserUpdateForm
    template_name = "update_profile.html"
    success_url = reverse_lazy("profile-page")
    login_url = reverse_lazy("login-page")

    def get_object(self, queryset=None):
        """Only allows the user to edit their own profile."""
        return self.request.user

    def form_valid(self, form):
        messages.success(
            self.request, "Your profile has been updated successfully.")
        return super().form_valid(form)

    def form_invalid(self, form):
        messages.error(
            self.request, "There was an error updating your profile. Please check the form.", extra_tags="danger")
        return super().form_invalid(form)


class UserDeleteView(LoginRequiredMixin, View):
    model = User
    template_name = "delete_profile.html"
    success_url = reverse_lazy("login-page")
    login_url = reverse_lazy("login-page")

    def get(self, request, *args, **kwargs):
        return render(request, self.template_name)

    def post(self, request, *args, **kwargs):
        form = UserDeleteForm(request.POST)
        if form.is_valid():
            user = request.user
            if user.check_password(form.cleaned_data["password"]):
                user.change_status(False)
                messages.success(
                    request, "Your account has been disabled successfully.")
                return redirect(self.success_url)

            messages.error(
                request, "Incorrect password. Please try again.", extra_tags="danger")
            return render(request, self.template_name, {"form": form})

        else:
            messages.error(
                request, "There was an error deactivating your account. Please check the form.", extra_tags="danger")
            return render(request, self.template_name, {"form": form})
