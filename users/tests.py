from django.core import mail
from django.core.management import call_command
from django.test import TestCase
from django.urls import reverse
from django.contrib.auth.tokens import default_token_generator
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.utils.encoding import force_bytes

from io import StringIO
from unittest.mock import patch

from .models import User


class UserAuthTests(TestCase):
    def setUp(self):
        self.user = User.objects.create_user(
            username="testuser",
            email="testuser@example.com",
            password="securepassword"
        )

    def test_register_view(self):
        """Try registering a new user."""
        response = self.client.post(reverse("register-page"), {
            "username": "newuser",
            "email": "newuser@example.com",
            "password1": "securepassword",
            "password2": "securepassword",
        })
        self.assertEqual(response.status_code, 302)
        self.assertTrue(User.objects.filter(username="newuser").exists())

    def test_register_redirect_if_logged_in(self):
        """An authenticated user should not be able to access the registration page."""
        self.client.login(username="testuser", password="securepassword")
        response = self.client.get(reverse("register-page"))
        self.assertEqual(response.status_code, 302)

    def test_login_view(self):
        """Tests that a user can log in."""
        response = self.client.post(reverse("login-page"), {
            "username": "testuser",
            "password": "securepassword",
        })
        self.assertEqual(response.status_code, 302)
        self.assertTrue(response.wsgi_request.user.is_authenticated)

    def test_login_redirect_if_logged_in(self):
        """An authenticated user should not access the login page."""
        self.client.login(username="testuser", password="securepassword")
        response = self.client.get(reverse("login-page"))
        self.assertEqual(response.status_code, 302)

    def test_logout_view(self):
        """Test whether a user can log out."""
        self.client.login(username="testuser", password="securepassword")
        response = self.client.post(reverse("logout-page"))
        self.assertEqual(response.status_code, 200)
        self.assertFalse(response.wsgi_request.user.is_authenticated)

    def test_home_view_requires_login(self):
        """The home view should require authentication."""
        response = self.client.get(reverse("home-page"))
        self.assertEqual(response.status_code, 302)

        self.client.login(username="testuser", password="securepassword")
        response = self.client.get(reverse("home-page"))
        self.assertEqual(response.status_code, 200)

    def test_change_password_view(self):
        """Tests that a user can change their password."""
        self.client.login(username="testuser", password="securepassword")
        response = self.client.post(reverse("password_change-page"), {
            "old_password": "securepassword",
            "new_password1": "newsecurepassword",
            "new_password2": "newsecurepassword",
        })
        self.assertEqual(response.status_code, 302)
        self.user.refresh_from_db()
        self.assertTrue(self.user.check_password("newsecurepassword"))

    def test_change_password_requires_login(self):
        """You cannot change your password without being authenticated."""
        response = self.client.get(reverse("password_change-page"))
        self.assertEqual(response.status_code, 302)

    def test_password_reset_view(self):
        url = reverse("password_reset")
        response = self.client.get(url)
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "password_reset/password_reset.html")

    def test_password_reset_email_sent(self):
        url = reverse("password_reset")
        self.client.post(url, {"email": self.user.email})

        # Verify that the email has been sent
        self.assertEqual(len(mail.outbox), 1)
        email = mail.outbox[0]
        self.assertIn("Password reset on", email.subject)
        self.assertIn(self.user.email, email.to)

    def test_password_reset_confirm_and_complete(self):
        # Submit a password reset request
        url = reverse("password_reset")
        self.client.post(url, {"email": self.user.email})

        # Get the sent mail
        email = mail.outbox[0]

        # Recover password reset link
        reset_url = email.body.split(
            "http://testserver")[1].split()[0]

        uidb64, token = [s for s in reset_url.split("/") if s][-2:]

        url = f"/auth/reset/{uidb64}/set-password/"
        self.client.get(url)

        # set the token
        session = self.client.session
        session["_password_reset_token"] = token
        session.save()

        valid_data = {
            "new_password1": "new1password",
            "new_password2": "new1password"
        }

        # make the request with the tokens on the client and the new password in the body
        response = self.client.post(url, valid_data)

        self.assertRedirects(response, reverse("password_reset_complete"))
        self.user.refresh_from_db()
        self.assertTrue(self.user.check_password("new1password"))

    def test_password_reset_with_invalid_password(self):
        url = reverse("password_reset")
        self.client.post(url, {"email": self.user.email})

        email = mail.outbox[0]

        reset_url = email.body.split(
            "http://testserver")[1].split()[0]

        uidb64, token = [s for s in reset_url.split("/") if s][-2:]

        url = f"/auth/reset/{uidb64}/set-password/"
        self.client.get(url)

        session = self.client.session
        session["_password_reset_token"] = token
        session.save()

        valid_data = {
            "new_password1": "sortkey",
            "new_password2": "sortkey"
        }

        response = self.client.post(url, valid_data)
        self.assertTrue(response.status_code, 200)
        self.user.refresh_from_db()
        self.assertFalse(self.user.check_password("sortkey"))

    def test_password_reset_invalid_token(self):
        url = reverse("password_reset")
        self.client.post(url, {"email": self.user.email})

        email = mail.outbox[0]

        reset_url = email.body.split(
            "http://testserver")[1].split()[0]

        uidb64, _ = [s for s in reset_url.split("/") if s][-2:]

        url = f"/auth/reset/{uidb64}/set-password/"
        self.client.get(url)

        session = self.client.session
        session["_password_reset_token"] = "invalid-token"
        session.save()

        valid_data = {
            "new_password1": "new1password",
            "new_password2": "new1password"
        }

        response = self.client.post(url, valid_data)
        self.assertTrue(response.status_code, 200)
        self.user.refresh_from_db()
        self.assertFalse(self.user.check_password("new1password"))


class CommandsTests(TestCase):
    def setUp(self):
        # Create a test user
        User.objects.create_user(
            username="existinguser",
            email="existing@example.com",
            first_name="Alice",
            last_name="Smith",
            password="password123"
        )

    @patch("builtins.input")
    @patch("getpass.getpass")
    def test_create_user_command(self, mock_getpass, mock_input):
        # Simulate input responses
        mock_input.side_effect = [
            "testuser",       # username
            "test@example.com",  # email
            "John",           # first name
            "Doe",            # last name
        ]

        # Simulate passwords
        mock_getpass.side_effect = ["password123",
                                    "password123"]

        # Run the create user command
        out = StringIO()
        call_command("createuser", stdout=out)

        # Check that the answer is correct
        self.assertIn("User testuser created successfully", out.getvalue())

        # Verify that the user has been created in the database
        user = User.objects.get(username="testuser")
        self.assertEqual(user.email, "test@example.com")
        self.assertEqual(user.first_name, "John")
        self.assertEqual(user.last_name, "Doe")
        self.assertTrue(user.check_password("password123"))

    @patch("builtins.input")
    def test_create_user_existing_username(self, mock_input):
        mock_input.side_effect = [
            "existinguser",
            "existing@example.com",
            "Alice",
            "Smith",
        ]

        usersCount = User.objects.all().count()

        out = StringIO()
        call_command("createstaffuser", stdout=out)
        self.assertIn("User 'existinguser' already exists", out.getvalue())

        self.assertEqual(usersCount, User.objects.all().count())

    @patch("builtins.input")
    @patch("getpass.getpass")
    def test_create_staffuser_command(self, mock_getpass, mock_input):
        mock_input.side_effect = [
            "testuser",
            "test@example.com",
            "John",
            "Doe",
        ]

        mock_getpass.side_effect = ["password123",
                                    "password123"]

        out = StringIO()
        call_command("createstaffuser", stdout=out)

        self.assertIn("User testuser created successfully", out.getvalue())

        user = User.objects.get(username="testuser")
        self.assertEqual(user.email, "test@example.com")
        self.assertEqual(user.first_name, "John")
        self.assertEqual(user.last_name, "Doe")
        self.assertTrue(user.check_password("password123"))

    @patch("builtins.input")
    def test_create_staffuser_existing_username(self, mock_input):
        mock_input.side_effect = [
            "existinguser",
            "existing@example.com",
            "Alice",
            "Smith",
        ]

        usersCount = User.objects.all().count()

        out = StringIO()
        call_command("createstaffuser", stdout=out)
        self.assertIn("User 'existinguser' already exists", out.getvalue())

        self.assertEqual(usersCount, User.objects.all().count())
