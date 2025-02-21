from django import forms
from django.contrib.auth.forms import UserCreationForm, AuthenticationForm, PasswordChangeForm

from .models import User


class UserRegisterForm(UserCreationForm):
    username = forms.CharField(widget=forms.TextInput(attrs={
        "class": "form-control",
        "placeholder": "username",
        "maxlength": "127"
    }), label="Username", required=True)
    email = forms.CharField(widget=forms.EmailInput(attrs={
        "class": "form-control",
        "placeholder": "example@email.net",
        "maxlength": "127"
    }), label="Email", required=True)
    first_name = forms.CharField(widget=forms.TextInput(attrs={
        "class": "form-control",
        "placeholder": "first name",
        "maxlength": "127"
    }), label="First Name", required=False)
    last_name = forms.CharField(widget=forms.TextInput(attrs={
        "class": "form-control",
        "placeholder": "last name",
        "maxlength": "127"
    }), label="Last Name", required=False)
    password1 = forms.CharField(widget=forms.PasswordInput(attrs={
        "class": "form-control",
        "placeholder": "password",
        "maxlength": "127"
    }), label="Password", required=True)
    password2 = forms.CharField(widget=forms.PasswordInput(attrs={
        "class": "form-control",
        "placeholder": "confirm password",
        "maxlength": "127"
    }), label="Confirm Password", required=True)

    class Meta:
        model = User
        fields = ["username", "email", "first_name",
                  "last_name", "password1", "password2"]

    def clean_username(self):
        username = self.cleaned_data.get("username")
        if User.objects.filter(username=username).exclude(pk=self.instance.pk).exists():
            raise forms.ValidationError("This username is already registered.")
        return username

    def clean_email(self):
        email = self.cleaned_data.get("email")
        if User.objects.filter(email=email).exclude(pk=self.instance.pk).exists():
            raise forms.ValidationError("This email is already registered.")
        return email

    def save(self, commit=True):
        user = super().save(commit=False)
        user.email = self.cleaned_data["email"]
        if commit:
            user.save()
        return user


class ResendVerificationForm(forms.Form):
    email = forms.EmailField(
        label="Email",
        widget=forms.EmailInput(
            attrs={"class": "form-control", "placeholder": "Enter your email"})
    )


class UserLoginForm(AuthenticationForm):
    username = forms.CharField(widget=forms.TextInput(attrs={
        "class": "form-control",
        "placeholder": "username",
        "maxlength": "127"
    }), label="Username", required=True)
    password = forms.CharField(widget=forms.PasswordInput(attrs={
        "class": "form-control",
        "placeholder": "password",
        "maxlength": "127"
    }), label="Password", required=True)


class UserChangePasswordForm(PasswordChangeForm):
    old_password = forms.CharField(widget=forms.PasswordInput(attrs={
        "class": "form-control",
        "placeholder": "",
        "maxlength": "127"
    }), label="Old Password", required=True)
    new_password1 = forms.CharField(widget=forms.PasswordInput(attrs={
        "class": "form-control",
        "placeholder": "",
        "maxlength": "127"
    }), label="New Password", required=True)
    new_password2 = forms.CharField(widget=forms.PasswordInput(attrs={
        "class": "form-control",
        "placeholder": "",
        "maxlength": "127"
    }), label="Confirm New Password", required=True)


class UserUpdateForm(forms.ModelForm):
    username = forms.CharField(widget=forms.TextInput(attrs={
        "class": "form-control",
        "placeholder": "username",
        "maxlength": "127"
    }), label="Username", required=True)
    email = forms.CharField(widget=forms.EmailInput(attrs={
        "class": "form-control",
        "placeholder": "example@email.net",
        "maxlength": "127"
    }), label="Email", required=True)
    first_name = forms.CharField(widget=forms.TextInput(attrs={
        "class": "form-control",
        "placeholder": "first name",
        "maxlength": "127"
    }), label="First Name", required=False)
    last_name = forms.CharField(widget=forms.TextInput(attrs={
        "class": "form-control",
        "placeholder": "last name",
        "maxlength": "127"
    }), label="Last Name", required=False)

    class Meta:
        model = User
        fields = ["username", "email", "first_name", "last_name"]


class UserDeleteForm(forms.ModelForm):
    class Meta:
        model = User
        fields = ["password"]
        widgets = {
            "password": forms.PasswordInput(
                attrs={"class": "form-control", "placeholder": "Enter your password"})
        }
