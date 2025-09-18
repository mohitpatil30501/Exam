$(document).ready(function() {
  // Toggle password visibility
  $('.toggle-password').click(function() {
    const targetId = $(this).data('target');
    const passwordInput = $('#' + targetId);
    const icon = $(this).find('span');
    
    // Toggle password visibility
    if (passwordInput.attr('type') === 'password') {
      passwordInput.attr('type', 'text');
      icon.removeClass('fa-eye').addClass('fa-eye-slash');
    } else {
      passwordInput.attr('type', 'password');
      icon.removeClass('fa-eye-slash').addClass('fa-eye');
    }
  });
  
  // Password strength checker
  $('#password').on('input', function() {
    const password = $(this).val();
    const strength = checkPasswordStrength(password);
    updatePasswordStrengthIndicator(strength);
  });
  
  // Confirm password validation
  $('#confirm_password').on('input', function() {
    validatePasswordMatch();
  });
  
  $('#password').on('input', function() {
    if ($('#confirm_password').val().length > 0) {
      validatePasswordMatch();
    }
  });
  
  // Handle form submission
  $('#reset-form').submit(function(e) {
    e.preventDefault();
    
    // Show loading spinner
    $('#reset-loading').removeClass('d-none');
    $('#reset-submit').prop('disabled', true);
    
    const password = $('#password').val();
    const confirmPassword = $('#confirm_password').val();
    
    // Validate passwords
    if (password.length < 8) {
      showError('Password must be at least 8 characters long');
      return false;
    }
    
    if (password !== confirmPassword) {
      showError('Passwords do not match');
      return false;
    }
    
    const strength = checkPasswordStrength(password);
    if (strength.score < 2) {
      showError('Password is too weak. Please choose a stronger password.');
      return false;
    }
    
    // Collect form data
    const formData = $(this).serialize();
    var url = $(this).attr('action');
    var type = $(this).attr('method');
    
    // Submit form via AJAX
    $.ajax({
      url: url,
      type: type,
      data: formData,
      success: function(data) {
        if (data.status) {
          $('#reset-msg').html('<div class="alert alert-success">' + data.data.message + '</div>');
          $('#reset-form').hide();
          
          // Redirect to login page after 3 seconds
          setTimeout(function() {
            window.location.href = '/accounts/login';
          }, 3000);
        } else {
          if (data.code == 400) {
            window.location.href = '/error?error=400 - BAD REQUEST&message=' + data.data.message;
          } else {
            showError(data.data.message || 'Failed to reset password');
          }
        }
      },
      error: function(data) {
        console.log('An error occurred.');
        console.log(data);
        showError('An error occurred. Please try again.');
      },
      complete: function() {
        // Hide loading spinner
        $('#reset-loading').addClass('d-none');
        $('#reset-submit').prop('disabled', false);
      }
    });
    
    return false;
  });
  
  function showError(message) {
    $('#reset-msg').html('<div class="alert alert-danger">' + message + '</div>');
    $('#reset-loading').addClass('d-none');
    $('#reset-submit').prop('disabled', false);
  }
  
  function validatePasswordMatch() {
    const password = $('#password').val();
    const confirmPassword = $('#confirm_password').val();
    
    if (password !== confirmPassword) {
      $('#confirm_password').addClass('is-invalid');
      return false;
    } else {
      $('#confirm_password').removeClass('is-invalid').addClass('is-valid');
      return true;
    }
  }
  
  function checkPasswordStrength(password) {
    let score = 0;
    let feedback = [];
    
    // Length check
    if (password.length < 8) {
      feedback.push('Password is too short');
    } else {
      score += 1;
    }
    
    // Complexity checks
    if (/[A-Z]/.test(password)) score += 1;
    else feedback.push('Add uppercase letters');
    
    if (/[a-z]/.test(password)) score += 1;
    else feedback.push('Add lowercase letters');
    
    if (/[0-9]/.test(password)) score += 1;
    else feedback.push('Add numbers');
    
    if (/[^A-Za-z0-9]/.test(password)) score += 1;
    else feedback.push('Add special characters');
    
    // Common patterns check
    if (/(.)\1\1/.test(password)) {
      score -= 1;
      feedback.push('Avoid repeated characters');
    }
    
    if (/^(123|abc|qwerty|password|admin|welcome)/i.test(password)) {
      score -= 1;
      feedback.push('Avoid common patterns');
    }
    
    return {
      score: Math.max(0, Math.min(5, score)),
      feedback: feedback
    };
  }
  
  function updatePasswordStrengthIndicator(strength) {
    const progressBar = $('#password-strength .progress-bar');
    const feedback = $('#password-feedback');
    
    // Update progress bar
    const percentage = (strength.score / 5) * 100;
    progressBar.css('width', percentage + '%');
    
    // Update color based on score
    progressBar.removeClass('bg-danger bg-warning bg-info bg-success');
    if (strength.score <= 1) progressBar.addClass('bg-danger');
    else if (strength.score === 2) progressBar.addClass('bg-warning');
    else if (strength.score === 3) progressBar.addClass('bg-info');
    else progressBar.addClass('bg-success');
    
    // Show feedback
    if (strength.feedback.length > 0) {
      feedback.html('<small class="text-muted">' + strength.feedback.join(', ') + '</small>');
    } else {
      feedback.html('<small class="text-success">Strong password!</small>');
    }
  }
});