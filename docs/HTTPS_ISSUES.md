# Development Server HTTPS Issues Resolution Guide

If you're seeing errors like:
```
ERROR You're accessing the development server over HTTPS, but it only supports HTTP.
```

This guide will help you resolve the issue.

## Why This Happens

1. **HSTS Settings**: Your browser might have saved HSTS (HTTP Strict Transport Security) settings from a previous visit to the site in production.
2. **Browser Cache**: Your browser might be caching redirects from HTTPS to HTTP.
3. **Django Settings**: Some Django settings might still be enforcing HTTPS.

## Solution 1: Use the HTTP-Only Server Command

We've created a custom management command that will help run the server in HTTP-only mode.

```bash
python manage.py httprunserver --http-only
```

## Solution 2: Clear HSTS Settings

We've created a script that will help clear HSTS settings for the development domain.

```bash
python clear_hsts.py
```

Then visit http://127.0.0.1:8000 in your browser to clear the HSTS settings.

## Solution 3: Use a Different Browser or Incognito Mode

If the above solutions don't work, try using a different browser or opening the site in incognito/private mode.

## Solution 4: Run the Server with the Development Script

We've created a script that will run the server with the correct settings:

```bash
./run_dev_server.sh
```

## Advanced Solution: Modify Browser Settings

### Chrome
1. Go to chrome://net-internals/#hsts
2. In the "Delete domain security policies" section, enter your domain (e.g., localhost or 127.0.0.1)
3. Click "Delete"

### Firefox
1. Go to about:config
2. Search for "security.ssl.strict_mode"
3. Set it to false for development

## Last Resort: Disable Development Server HTTPS Checking

If none of the above solutions work, you can try disabling the development server's HTTPS check by editing the Django source code (not recommended for production):

1. Find the Django installation: `python -c "import django; print(django.__path__[0])"`
2. Edit the file: `[django-path]/core/servers/basehttp.py`
3. Find the `ServerHandler.handle_one_request` method
4. Comment out the HTTPS check code (the part that checks for 'HTTPS' in self.environ)

Remember to only use this in development and never in production!