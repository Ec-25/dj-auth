from django.conf import settings
from django.contrib.auth.tokens import default_token_generator
from django.core.mail import send_mail
from django.shortcuts import get_object_or_404
from django.utils.encoding import force_bytes
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode

from .models import User


def generate_user_verification_tokens(user: User) -> tuple[str, str]:
    uidb64 = urlsafe_base64_encode(force_bytes(user.pk))
    token = default_token_generator.make_token(user)
    return uidb64, token


def get_user_from_uidb64(uidb64: str) -> User | None:
    try:
        uid = urlsafe_base64_decode(uidb64).decode()
        user = get_object_or_404(User, pk=uid)
    except (TypeError, ValueError, OverflowError, User.DoesNotExist):
        user = None
    return user


def verify_user_token(user: User, token: str) -> bool:
    return default_token_generator.check_token(user, token)


def verify_user(user: User) -> None:
    user.change_status(True)
    return


def send_email_with_user_verification_link(user: User, verification_url: str) -> None:
    subject = "dj-Auth: Verify your account"
    message = f"""Hello {user.first_name}, thank you for registering on 'dj-Auth'.
        Please click on the following link to activate your account on 'dj-Auth':
        {verification_url}"""
    send_mail(
        subject=subject,
        message=message,
        from_email=settings.DEFAULT_FROM_EMAIL,
        recipient_list=[user.email],
        fail_silently=False,
    )
    return
