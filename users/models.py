from django.contrib.auth.models import (
    AbstractBaseUser,
    PermissionsMixin,
    Group as Grp,
)
from django.db import models

from .managers import UserManager


class User(AbstractBaseUser, PermissionsMixin):
    """
    Custom user model that uses email as the unique identifier.
    Includes fields for personal details and timestamps.
    """

    id = models.BigAutoField(primary_key=True, editable=False)
    username = models.CharField(
        max_length=255, verbose_name="Username", unique=True)
    email = models.EmailField(
        max_length=255, verbose_name="Email Address", unique=True)
    first_name = models.CharField(max_length=255, verbose_name="First Name")
    last_name = models.CharField(max_length=255, verbose_name="Last Name")
    is_active = models.BooleanField(default=False)
    is_staff = models.BooleanField(default=False)
    is_superuser = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    last_login = models.DateTimeField(auto_now=True, null=True)

    USERNAME_FIELD = "username"
    REQUIRED_FIELDS = ["email", "first_name", "last_name"]

    objects = UserManager()

    def __str__(self):
        return self.username

    @property
    def full_name(self):
        return f"{self.last_name}, {self.first_name}"

    def change_status(self, new_status: bool):
        if self.is_active != new_status:
            self.is_active = new_status
            self.save(update_fields=["is_active"])
        return


class Group(Grp):
    """
    Extends the default Group model to include a description field.
    """

    description = models.TextField(blank=True, null=True)

    class Meta:
        verbose_name = "group"
        verbose_name_plural = "groups"
