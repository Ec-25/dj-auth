from django.test import TestCase
from django.urls import reverse

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
