import os
from django.core.management.commands.runserver import Command as BaseCommand

class Command(BaseCommand):
    """
    Custom runserver command that ignores SSL/HTTPS errors
    """
    help = "Runs the server with HTTP support only, ignoring HTTPS requests"
    
    def add_arguments(self, parser):
        super().add_arguments(parser)
        parser.add_argument('--http-only', action='store_true', help='Run in HTTP-only mode')
    
    def handle(self, *args, **options):
        # Set environment variables to disable HTTPS enforcement
        os.environ['PYTHONHTTPSVERIFY'] = '0'
        os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'
        
        # Add some helpful messaging
        if options.get('http_only', False):
            self.stdout.write(self.style.SUCCESS('Running in HTTP-only mode. HTTPS requests will be ignored.'))
            self.stdout.write('If you see errors like "ERROR You\'re accessing the development server over HTTPS, but it only supports HTTP."')
            self.stdout.write('Try clearing your browser HSTS settings or use a different browser/incognito mode.')
            
        # Run the standard runserver command
        super().handle(*args, **options)