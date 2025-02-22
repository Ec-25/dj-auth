
# dj-auth

## **Description:**
This module handles user authentication and authorization for access to the server. It provides functionality for user registration, login, password changes, and managing user roles.

![dj-auth-image](https://github.com/user-attachments/assets/54e63fc1-5cfe-430d-b085-0b3873ff93db)

## Table of Contents
- [Description](#description)
- [Required environment variables](#required-environment-variables)
    - [Optional variables](#optional-variables)
- [Main Classes and Methods](#main-classes-and-methods)
    - [Custom Management Commands](#custom-management-commands)
- [Form Endpoints](#form-endpoints)
- [Run Server](#run-server)
- [Run Tests](#run-tests)

## Required environment variables
Before starting the application, make sure you have set the following variables in your environment or `.env` file:

```
SECRET_KEY="your-secret-key"  # Secret key for Django application
EMAIL_HOST_USER="your-email"  # Your email address
EMAIL_HOST_PASSWORD="your-email-password"  # Your email password
```

### Optional variables
These variables are optional and control the behavior of the application:

```
ALLOWED_HOSTS="host1,host2"    # Comma-separated list of allowed hosts
DEBUG="True"                   # Set to False in production environment for security
EMAIL_HOST="smtp.gmail.com"    # SMTP server for sending emails (default: smtp.gmail.com)
EMAIL_PORT="587"               # Port for SMTP (default: 587)
EMAIL_USE_TLS="True"           # Whether to use TLS for email (default: True)
```

## Main Classes and Methods
Explanation of the module's classes and functions:

### `UserManager`
#### `create_user(email, password, **extra_fields)`
#### `create_staffuser(email, password, **extra_fields)`
#### `create_superuser(email, password, **extra_fields)`
A custom manager to handle user creation and management.

### `User`
#### `__init__(email, username, first_name, last_name, password)`
Custom user model that uses email as a unique identifier, with fields for personal details and timestamps.

### `Group`
#### `__init__(name, description)`
Extends the default group model to include a description field.

## Custom Management Commands

This module also includes custom management commands for creating users interactively from the command line.

### `createuser` command
This command allows you to create a new regular user interactively. When running `python manage.py createuser`, the system will prompt you to input the user's details (email, username, first name, last name, and password) one by one, securely masking the password as you type it.

Example usage:
```
python manage.py createuser
```
It will prompt you for the following inputs:
- Email address
- Username
- First name
- Last name
- Password (masked input)

### `createstaffuser` command
Similar to `createuser`, this command will create a staff user interactively. The only difference is that the user will have staff permissions.

Example usage:
```
python manage.py createstaffuser
```
It will prompt you for the same details as `createuser`, but it will create a staff user.

### `createsuperuser` command
This is the default Django command for creating a superuser interactively, with admin permissions.

## Form Endpoints
The following are the main endpoints for user-related actions:

### Users: `/auth/`
- `GET /` - Sample home page.
- `GET /register/` - Page for user registration.
- `POST /register/` - Submit registration form.
- `GET /resend-verification/` - Page to resend the activation email.
- `POST /resend-verification/` - Submit the form to resend the email.
- `GET /verify/<uidb64>/<token>/` - Account activation point.
- `GET /login/` - Page for user login.
- `POST /login/` - Submit login form.
- `POST /logout/` - Logs out the current user.
- `GET /profile/` - Page to view profile data.
- `GET /profile/update/` - Page to update profile data.
- `POST /profile/update/` - Submit profile update form.
- `GET /profile/delete/` - Page to disable profile.
- `POST /profile/delete/` - Submit deactivation confirmation form.
- `GET /password/change/` - Page to change the user's password.
- `POST /password/change/` - Submit the password change form.

### Password Reset: /password_reset/
- `GET /password_reset/` - Page to request a password reset.
- `POST /password_reset/` - Submit the email to reset the password.
- `GET /password_reset/done/` - Page indicating that the reset email has been sent.
- `GET /reset/<uidb64>/<token>/` - Page to confirm the password reset with the provided token.
- `POST /reset/<uidb64>/<token>/` - Submit the new password after confirmation.
- `GET /reset/done/` - Page indicating that the password has been successfully reset.

## Run Server
To start the server, run:

```bash
python manage.py runserver
```

## Run Tests
To run the unit tests:

```bash
python manage.py test
```
