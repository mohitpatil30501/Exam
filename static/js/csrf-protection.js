/**
 * This is a base template for including in all HTML files
 * to ensure CSRF protection in AJAX requests is consistent
 */

// Common CSRF token handling for all AJAX requests
$(document).ready(function() {
    // Get CSRF token from cookie
    function getCsrfToken() {
        let cookieValue = null;
        if (document.cookie && document.cookie !== '') {
            const cookies = document.cookie.split(';');
            for (let i = 0; i < cookies.length; i++) {
                const cookie = cookies[i].trim();
                if (cookie.substring(0, 'csrftoken='.length) === 'csrftoken=') {
                    cookieValue = decodeURIComponent(cookie.substring('csrftoken='.length));
                    break;
                }
            }
        }
        return cookieValue;
    }

    // Set CSRF token for all AJAX requests
    const csrftoken = getCsrfToken();
    $.ajaxSetup({
        beforeSend: function(xhr, settings) {
            if (!(/^(GET|HEAD|OPTIONS|TRACE)$/.test(settings.type)) && !this.crossDomain) {
                xhr.setRequestHeader("X-CSRFToken", csrftoken);
            }
        }
    });
    
    // Periodically refresh the CSRF token to prevent expiration
    setInterval(function() {
        $.get('/api/refresh-csrf/');
    }, 1800000); // Refresh every 30 minutes
});

// Helper function to sanitize data to prevent XSS attacks
function sanitizeHtml(text) {
    if (!text) return '';
    return text
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#039;');
}

// Helper function to validate form input
function validateInput(input, pattern, errorMsg) {
    const $input = $(input);
    const $errorContainer = $input.siblings('.error-message');
    
    if (!$errorContainer.length) {
        $input.after('<div class="error-message text-danger"></div>');
        $errorContainer = $input.siblings('.error-message');
    }
    
    if (!pattern.test($input.val())) {
        $errorContainer.text(errorMsg);
        return false;
    } else {
        $errorContainer.text('');
        return true;
    }
}