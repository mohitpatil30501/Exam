#!/usr/bin/env python
"""
Clear HSTS settings for development
This script creates a simple HTTP server that sets HSTS headers with max-age=0
to clear any previously set HSTS settings for the domain in the browser.
"""
import http.server
import socketserver

PORT = 8000
CLEAR_HSTS_HEADER = "Strict-Transport-Security: max-age=0"

class ClearHSTSHandler(http.server.SimpleHTTPRequestHandler):
    def end_headers(self):
        self.send_header("Strict-Transport-Security", "max-age=0")
        super().end_headers()
        
    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-type", "text/html")
        self.end_headers()
        self.wfile.write(b"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>HSTS Cleared</title>
            <style>
                body { font-family: Arial, sans-serif; max-width: 800px; margin: 20px auto; padding: 0 20px; }
                .success { color: green; }
                .info { background-color: #f5f5f5; padding: 15px; border-radius: 5px; }
            </style>
        </head>
        <body>
            <h1>HSTS Settings Cleared</h1>
            <p class="success">✓ Successfully cleared HSTS settings for this domain</p>
            <div class="info">
                <p>The HSTS (HTTP Strict Transport Security) header has been set to max-age=0, which instructs 
                your browser to forget any previous HSTS settings for this domain.</p>
                <p>You should now be able to access the development server using HTTP without being 
                redirected to HTTPS.</p>
            </div>
            <h2>Next steps:</h2>
            <ol>
                <li>Close this window/tab</li>
                <li>Run the development server with <code>python manage.py runserver</code></li>
                <li>Access the site at <a href="http://127.0.0.1:8000">http://127.0.0.1:8000</a></li>
            </ol>
        </body>
        </html>
        """)

if __name__ == "__main__":
    with socketserver.TCPServer(("", PORT), ClearHSTSHandler) as httpd:
        print(f"Serving at http://127.0.0.1:{PORT}")
        print("Visit this URL in your browser to clear HSTS settings")
        print("Press Ctrl+C to stop the server once you've visited the URL")
        httpd.serve_forever()