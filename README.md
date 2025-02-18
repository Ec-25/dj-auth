
# dj-auth

## **Description:**
This module handles user authentication and authorization for access to the server. It provides functionality for user registration, login, password changes, and managing user roles.

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
```

### Optional variables
These variables are optional and control the behavior of the application:

```
ALLOWED_HOSTS="host1,host2"    # Comma-separated list of allowed hosts
DEBUG="True"                   # Set to False in production environment for security
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
- `GET /login/` - Page for user login.
- `POST /login/` - Submit login form.
- `POST /logout/` - Logs out the current user.
- `GET /password/change/` - Page to change the user's password.
- `POST /password/change/` - Submit the password change form.

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
