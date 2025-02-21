from django.contrib.messages import get_messages
from django.core import mail
from django.core.management import call_command
from django.test import TestCase
from django.urls import reverse

from io import StringIO
from unittest.mock import patch

from users.utils import generate_user_verification_tokens

from .models import User


class UserAuthTests(TestCase):
    def setUp(self):
        self.user = User.objects.create_user(
            username="testuser",
            email="testuser@example.com",
            password="securepassword",
            is_active=True
        )

    def test_register_user_successfully(self):
        register_url = reverse("register-page")

        data = {
            "username": "test",
            "email": "test@example.com",
            "password1": "Testpassword123!",
            "password2": "Testpassword123!",
        }
        response = self.client.post(register_url, data)

        user = User.objects.get(email=data["email"])
        self.assertTrue(user)
        self.assertEqual(user.email, "test@example.com")
        self.assertFalse(user.is_active)

        self.assertEqual(len(mail.outbox), 1)
        self.assertIn("Verify your account", mail.outbox[0].subject)

        self.assertTemplateUsed(response, "verify/email_sent.html")

    def test_register_user_invalid_data(self):
        register_url = reverse("register-page")

        data = {
            "username": "",
            "email": "invalidemail",
            "password1": "short",
            "password2": "short",
        }
        response = self.client.post(register_url, data)

        # No user should be created (only the setup user)
        self.assertEqual(User.objects.count(), 1)

        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "register.html")
        self.assertContains(response, "This field is required.")

    def test_verify_user_successfully(self):
        user = User.objects.create_user(
            username="testuser2",
            email="test2@example.com",
            password="Testpassword123!",
            is_active=False,
        )
        uidb64, token = generate_user_verification_tokens(user)

        verify_url = reverse("user-verify-page",
                             kwargs={"uidb64": uidb64, "token": token})

        response = self.client.get(verify_url)

        user.refresh_from_db()
        self.assertTrue(user.is_active)

        self.assertRedirects(response, reverse("login-page"))

    def test_verify_user_invalid_link(self):
        user = User.objects.create_user(
            username="testuser2",
            email="test2@example.com",
            password="Testpassword123!",
            is_active=False,
        )

        uidb64 = "invalid"
        token = "invalid"
        invalid_url = reverse("user-verify-page",
                              kwargs={"uidb64": uidb64, "token": token})

        response = self.client.get(invalid_url)

        user.refresh_from_db()
        self.assertFalse(user.is_active)

        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "verify/invalid_link.html")

    def test_register_redirect_if_logged_in(self):
        """An authenticated user should not be able to access the registration page."""
        self.client.login(username="testuser", password="securepassword")
        response = self.client.get(reverse("register-page"))
        self.assertEqual(response.status_code, 302)

    def test_resend_verification_email_successfully(self):
        """You must resend the email if the user is not verified"""
        User.objects.create_user(
            username="testuser2",
            email="test2@example.com",
            password="Testpassword123!",
            is_active=False,
        )

        resend_url = reverse("resend_verification-page")
        response = self.client.post(
            resend_url, {"email": "test2@example.com"})

        self.assertEqual(len(mail.outbox), 1)
        self.assertIn("Verify your account", mail.outbox[0].subject)

        self.assertTemplateUsed(response, "verify/email_sent.html")

    def test_user_already_verified(self):
        """If the user is already activated, it should display a success message"""
        resend_url = reverse("resend_verification-page")
        response = self.client.post(
            resend_url, {"email": self.user.email}, follow=True)

        messages = list(get_messages(response.wsgi_request))
        self.assertEqual(
            str(messages[0]), "Your account is now activated. You can log in.")

        self.assertRedirects(response, reverse("login-page"))

    def test_email_not_found(self):
        """If the email does not exist, it should display an error message"""
        resend_url = reverse("resend_verification-page")
        response = self.client.post(
            resend_url, {"email": "nonexistent@example.com"}, follow=True)

        messages = list(get_messages(response.wsgi_request))
        self.assertEqual(
            str(messages[0]), "An account with this email was not found.")

        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "verify/resend_verification.html")

    def test_get_resend_verification_page(self):
        """The page with the form should render correctly."""
        resend_url = reverse("resend_verification-page")
        response = self.client.get(resend_url)
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "verify/resend_verification.html")

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

    def test_view_profile_authenticated_user(self):
        """Test that a logged-in user can view their profile."""
        self.client.login(username="testuser", password="securepassword")

        url = reverse("profile-page")
        response = self.client.get(url)

        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "profile.html")
        self.assertEqual(response.context["user"], self.user)

    def test_view_profile_unauthenticated_user(self):
        """Test that an unauthenticated user is redirected to login page."""
        url = reverse("profile-page")
        response = self.client.get(url)

        self.assertRedirects(response, f"/auth/login/?next={url}")

    def test_update_view_authenticated_user(self):
        """Test that a logged-in user can update their profile."""
        self.client.login(username="testuser", password="securepassword")

        data = {
            "first_name": "NewFirstName",
            "last_name": "NewLastName",
            "email": "newemail@example.com",
            "username": "newusername"
        }

        url = reverse("profile-update-page")
        response = self.client.post(url, data)

        self.assertRedirects(response, reverse("profile-page"))

        self.user.refresh_from_db()
        self.assertEqual(self.user.first_name, "NewFirstName")
        self.assertEqual(self.user.last_name, "NewLastName")
        self.assertEqual(self.user.email, "newemail@example.com")
        self.assertEqual(self.user.username, "newusername")

        messages = list(get_messages(response.wsgi_request))
        self.assertEqual(
            str(messages[0]), "Your profile has been updated successfully.")

    def test_update_view_unauthenticated_user(self):
        """Test that an unauthenticated user is redirected to login page."""
        url = reverse("profile-update-page")
        response = self.client.get(url)

        self.assertRedirects(response, f"/auth/login/?next={url}")

    def test_update_view_invalid_form_data(self):
        """Test that submitting invalid data in the form gives an error."""
        self.client.login(username="testuser", password="securepassword")

        data = {
            "first_name": "NewFirstName",
            "last_name": "NewLastName",
            "email": "invalidemail",
            "username": "newusername"
        }

        url = reverse("profile-update-page")
        response = self.client.post(url, data)

        htmlErrors = response.context.get("errors")
        self.assertEqual(response.status_code, 200)
        self.assertIsNotNone(htmlErrors)
        self.assertIn("Enter a valid email address.", htmlErrors)

    def test_delete_view_authenticated_user(self):
        """Test that a logged-in user can delete their profile."""
        self.client.login(username="testuser", password="securepassword")

        data = {
            "password": "securepassword"
        }

        url = reverse("profile-delete-page")
        response = self.client.post(url, data)

        self.user.refresh_from_db()
        self.assertFalse(self.user.is_active)

        messages = list(get_messages(response.wsgi_request))
        self.assertEqual(
            str(messages[0]), "Your account has been disabled successfully.")

    def test_delete_view_unauthenticated_user(self):
        """Test that an unauthenticated user is redirected to login page."""
        url = reverse("profile-delete-page")
        response = self.client.get(url)

        self.assertRedirects(response, f"/auth/login/?next={url}")

    def test_delete_view_invalid_form_data(self):
        """Test that submitting invalid data in the form gives an error."""
        self.client.login(username="testuser", password="securepassword")

        data = {
            "password": "falsePassword"
        }

        url = reverse("profile-delete-page")
        response = self.client.post(url, data)

        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "delete_profile.html")
        messages = list(get_messages(response.wsgi_request))
        self.assertEqual(
            str(messages[0]), "Incorrect password. Please try again.")

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
