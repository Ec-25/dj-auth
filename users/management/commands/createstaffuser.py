from django.core.management.base import BaseCommand
from getpass import getpass

from users.models import User


class Command(BaseCommand):
    help = "Create a staff user"

    def handle(self, *args, **options):
        username = input("Enter username: ")
        if User.objects.filter(username=username).exists():
            self.stdout.write(self.style.ERROR(
                f"User '{username}' already exists"))
            return

        email = input("Enter email: ")
        first_name = input("Enter first name: ")
        last_name = input("Enter last name: ")

        eqPass = False
        while not eqPass:
            password = getpass("Enter password: ")
            password2 = getpass("Enter password again: ")
            if password == password2:
                eqPass = True
            else:
                self.stdout.write(self.style.ERROR(
                    "Passwords do not match. Please try again."))

        user = User.objects.create_staffuser(
            email=email,
            username=username,
            first_name=first_name,
            last_name=last_name,
            password=password
        )
        self.stdout.write(self.style.SUCCESS(
            f"User {username} created successfully"))
