# Exam Preparation Portal

A secure Django-based web application for creating, managing, and taking online examinations.

## Security Enhancements

This project has undergone a comprehensive security upgrade to address various vulnerabilities:

- **Environment-Based Configuration**: All sensitive credentials moved to environment variables
- **Enhanced Authentication**: Account lockout, secure password reset, and session management
- **Improved Cryptography**: Secure key generation and data encryption
- **HTTPS and Security Headers**: Content Security Policy, HSTS, and HTTPS enforcement
- **CSRF Protection**: Consistent CSRF token handling across the application
- **Email Security**: Secure email configuration with error handling
- **Session Security**: Automatic timeouts, secure cookies, and protection against session fixation

## Setup Instructions

### Prerequisites

- Python 3.8+
- PostgreSQL database
- Virtual environment (recommended)

### Installation

1. Clone the repository:
   ```bash
   git clone <repository-url>
   cd Exam
   ```

2. Create and activate a virtual environment:
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```

3. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

4. Create a `.env` file with the following variables:
   ```
   DEBUG=True
   SECRET_KEY=your_secret_key
   DB_NAME=your_db_name
   DB_USER=your_db_user
   DB_PASSWORD=your_db_password
   DB_HOST=localhost
   DB_PORT=5432
   EMAIL_BACKEND=django.core.mail.backends.smtp.EmailBackend
   EMAIL_HOST=smtp.example.com
   EMAIL_PORT=587
   EMAIL_HOST_USER=your_email@example.com
   EMAIL_HOST_PASSWORD=your_email_password
   EMAIL_USE_TLS=True
   EMAIL_FROM=noreply@example.com
   ```

5. Apply migrations:
   ```bash
   python manage.py migrate
   ```

6. Create a superuser:
   ```bash
   python manage.py createsuperuser
   ```

### Running the Application

#### Standard Development Server (HTTP only)

```bash
python manage.py runserver
```

#### Development Server with HTTPS Support

For testing security features that require HTTPS:

```bash
python run_https_server.py
```

This will generate self-signed certificates and start the server with HTTPS support. Note that you'll need to accept the security warning in your browser since it's using a self-signed certificate.

### Production Deployment

In production, make sure to:

1. Set `DEBUG=False` in your environment variables
2. Use a proper web server (Gunicorn, uWSGI) behind a reverse proxy (Nginx, Apache)
3. Configure your web server to handle HTTPS with valid certificates
4. Set all security-related environment variables appropriately

## Security Best Practices

### For Developers

1. Never commit sensitive information like credentials or secret keys
2. Always validate and sanitize user inputs
3. Use prepared statements for database queries
4. Implement proper error handling and logging
5. Keep dependencies up-to-date
6. Apply the principle of least privilege

### For Administrators

1. Regularly update the application and its dependencies
2. Monitor for suspicious activities
3. Implement regular backups
4. Use strong passwords and enforce password policies
5. Restrict access to administrative interfaces
6. Configure a proper firewall