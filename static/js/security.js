/**
 * Security Utilities for JavaScript - ensures CSRF token is included in all AJAX requests
 * This file should be included before any other JavaScript files that make AJAX requests
 */

// Function to get CSRF token from cookie
function getCookie(name) {
    let cookieValue = null;
    if (document.cookie && document.cookie !== '') {
        const cookies = document.cookie.split(';');
        for (let i = 0; i < cookies.length; i++) {
            const cookie = cookies[i].trim();
            // Does this cookie string begin with the name we want?
            if (cookie.substring(0, name.length + 1) === (name + '=')) {
                cookieValue = decodeURIComponent(cookie.substring(name.length + 1));
                break;
            }
        }
    }
    return cookieValue;
}

// Setup jQuery AJAX to include CSRF token in all requests
$(document).ready(function() {
    const csrftoken = getCookie('csrftoken');
    
    // Set CSRF token for all AJAX requests
    $.ajaxSetup({
        beforeSend: function(xhr, settings) {
            // Skip for certain request types
            if (!(/^(GET|HEAD|OPTIONS|TRACE)$/.test(settings.type)) && !this.crossDomain) {
                xhr.setRequestHeader("X-CSRFToken", csrftoken);
            }
        }
    });
    
    // Additional security measures
    // Prevent clickjacking
    if (window.self === window.top) {
        // Not in an iframe
        const securityHeader = document.createElement('meta');
        securityHeader.setAttribute('http-equiv', 'X-Frame-Options');
        securityHeader.setAttribute('content', 'DENY');
        document.head.appendChild(securityHeader);
    } else {
        // In an iframe - potential clickjacking attempt
        console.warn('This page is loaded in an iframe, which may indicate a clickjacking attempt');
    }
    
    // Set Content-Security-Policy
    const cspHeader = document.createElement('meta');
    cspHeader.setAttribute('http-equiv', 'Content-Security-Policy');
    cspHeader.setAttribute('content', "default-src 'self'; script-src 'self' 'unsafe-inline' 'unsafe-eval'; style-src 'self' 'unsafe-inline';");
    document.head.appendChild(cspHeader);
    
    // Session timeout warning
    let sessionTimeoutWarning = parseInt(localStorage.getItem('sessionTimeoutWarning') || '1800'); // default 30 minutes
    let sessionTimeout = parseInt(localStorage.getItem('sessionTimeout') || '1800'); // default 30 minutes
    
    // Setup warning 5 minutes before timeout
    if (sessionTimeout > 300) { // only if more than 5 minutes
        setTimeout(function() {
            alert("Your session will expire in 5 minutes. Please save your work and refresh the page to continue.");
        }, (sessionTimeout - 300) * 1000);
    }
    
    // Auto-logout timeout
    setTimeout(function() {
        alert("Your session has expired. You will be redirected to the login page.");
        window.location.href = '/logout';
    }, sessionTimeout * 1000);
});

// Additional function to explicitly refresh CSRF token
function refreshCSRFToken() {
    $.get('/api/refresh-csrf/', function(data) {
        // This endpoint should return a new CSRF token
        // The cookie will be set automatically by Django
        console.log("CSRF token refreshed");
    });
}