// Common utility functions for the Certificate Authentication System

// Logout function
function logout() {
    localStorage.removeItem('user');
    window.location.href = 'index.html';
}

// Format date helper
function formatDate(dateString) {
    const date = new Date(dateString);
    return date.toLocaleDateString() + ' ' + date.toLocaleTimeString();
}

// Show loading state
function showLoading(element, text = 'Loading...') {
    element.innerHTML = `<p class="loading">${text}</p>`;
}

// Show error message
function showError(element, message) {
    element.innerHTML = `<div class="error">❌ ${message}</div>`;
}

// Show success message
function showSuccess(element, message) {
    element.innerHTML = `<div class="success">✅ ${message}</div>`;
}

// Copy text to clipboard
function copyToClipboard(text) {
    navigator.clipboard.writeText(text).then(() => {
        alert('Copied to clipboard!');
    }).catch(err => {
        console.error('Failed to copy: ', err);
        // Fallback for older browsers
        const textArea = document.createElement('textarea');
        textArea.value = text;
        document.body.appendChild(textArea);
        textArea.select();
        document.execCommand('copy');
        document.body.removeChild(textArea);
        alert('Copied to clipboard!');
    });
}

// Validate file type
function validateFileType(file) {
    const allowedTypes = ['application/pdf', 'image/jpeg', 'image/jpg', 'image/png'];
    return allowedTypes.includes(file.type);
}

// Validate file size (max 10MB)
function validateFileSize(file, maxSizeMB = 10) {
    const maxSize = maxSizeMB * 1024 * 1024; // Convert to bytes
    return file.size <= maxSize;
}

// Format file size
function formatFileSize(bytes) {
    if (bytes === 0) return '0 Bytes';
    const k = 1024;
    const sizes = ['Bytes', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
}

// Generate random certificate ID (client-side helper)
function generateTempId() {
    return 'TEMP-' + Math.random().toString(36).substr(2, 8).toUpperCase();
}

// Validate certificate ID format
function isValidCertificateId(id) {
    return /^CERT-[A-F0-9]{8}$/i.test(id);
}

// Simple QR code data validation
function isValidQRData(data) {
    try {
        const parsed = JSON.parse(data);
        return parsed.id && parsed.hash && parsed.url;
    } catch (e) {
        return false;
    }
}

// Format QR data for display
function formatQRData(qrData) {
    try {
        const data = typeof qrData === 'string' ? JSON.parse(qrData) : qrData;
        return {
            id: data.id,
            hash: data.hash ? data.hash.substring(0, 16) + '...' : 'N/A',
            url: data.url
        };
    } catch (e) {
        return null;
    }
}

// Check if user is authenticated
function checkAuth() {
    const user = JSON.parse(localStorage.getItem('user') || '{}');
    return user.username && user.role;
}

// Get current user
function getCurrentUser() {
    return JSON.parse(localStorage.getItem('user') || '{}');
}

// Redirect if not authenticated
function requireAuth(allowedRoles = []) {
    const user = getCurrentUser();

    if (!user.username) {
        window.location.href = 'index.html';
        return false;
    }

    if (allowedRoles.length > 0 && !allowedRoles.includes(user.role)) {
        alert('Access denied. Insufficient permissions.');
        window.location.href = 'index.html';
        return false;
    }

    return true;
}

// Simple notification system
function showNotification(message, type = 'info', duration = 3000) {
    // Remove existing notifications
    const existingNotification = document.querySelector('.notification');
    if (existingNotification) {
        existingNotification.remove();
    }

    // Create notification element
    const notification = document.createElement('div');
    notification.className = `notification notification-${type}`;
    notification.innerHTML = `
        <span>${message}</span>
        <button onclick="this.parentElement.remove()" style="background: none; border: none; color: inherit; font-size: 1.2em; cursor: pointer; margin-left: 10px;">&times;</button>
    `;

    // Add styles
    notification.style.cssText = `
        position: fixed;
        top: 20px;
        right: 20px;
        padding: 15px 20px;
        border-radius: 10px;
        color: white;
        font-weight: 500;
        z-index: 1000;
        max-width: 400px;
        box-shadow: 0 10px 30px rgba(0,0,0,0.2);
        animation: slideInRight 0.3s ease-out;
    `;

    // Set background color based on type
    switch (type) {
        case 'success':
            notification.style.background = 'linear-gradient(135deg, #38a169, #2f855a)';
            break;
        case 'error':
            notification.style.background = 'linear-gradient(135deg, #e53e3e, #c53030)';
            break;
        case 'warning':
            notification.style.background = 'linear-gradient(135deg, #d69e2e, #b7791f)';
            break;
        default:
            notification.style.background = 'linear-gradient(135deg, #667eea, #764ba2)';
    }

    // Add animation keyframes if not already added
    if (!document.querySelector('#notification-styles')) {
        const style = document.createElement('style');
        style.id = 'notification-styles';
        style.textContent = `
            @keyframes slideInRight {
                from {
                    transform: translateX(100%);
                    opacity: 0;
                }
                to {
                    transform: translateX(0);
                    opacity: 1;
                }
            }
        `;
        document.head.appendChild(style);
    }

    // Add to page
    document.body.appendChild(notification);

    // Auto remove after duration
    if (duration > 0) {
        setTimeout(() => {
            notification.remove();
        }, duration);
    }
}

// Hash string (simple client-side hashing for demo purposes)
function simpleHash(str) {
    let hash = 0;
    for (let i = 0; i < str.length; i++) {
        const char = str.charCodeAt(i);
        hash = ((hash << 5) - hash) + char;
        hash = hash & hash; // Convert to 32-bit integer
    }
    return Math.abs(hash).toString(16).padStart(8, '0').toUpperCase();
}

// Debounce function for input events
function debounce(func, wait) {
    let timeout;
    return function executedFunction(...args) {
        const later = () => {
            clearTimeout(timeout);
            func(...args);
        };
        clearTimeout(timeout);
        timeout = setTimeout(later, wait);
    };
}

// Form validation helpers
function validateForm(formElement) {
    const inputs = formElement.querySelectorAll('input[required], textarea[required]');
    let isValid = true;

    inputs.forEach(input => {
        if (!input.value.trim()) {
            input.style.borderColor = '#e53e3e';
            isValid = false;
        } else {
            input.style.borderColor = '#e2e8f0';
        }
    });

    return isValid;
}

// Reset form validation styles
function resetFormValidation(formElement) {
    const inputs = formElement.querySelectorAll('input, textarea');
    inputs.forEach(input => {
        input.style.borderColor = '#e2e8f0';
    });
}

// Initialize common functionality when DOM is loaded
document.addEventListener('DOMContentLoaded', function() {
    // Add loading animation styles if not present
    if (!document.querySelector('#common-styles')) {
        const style = document.createElement('style');
        style.id = 'common-styles';
        style.textContent = `
            .loading {
                position: relative;
            }
            .loading::after {
                content: '';
                display: inline-block;
                width: 16px;
                height: 16px;
                border: 2px solid #4a5568;
                border-radius: 50%;
                border-top-color: transparent;
                animation: spin 1s linear infinite;
                margin-left: 8px;
            }
            @keyframes spin {
                0% { transform: rotate(0deg); }
                100% { transform: rotate(360deg); }
            }
        `;
        document.head.appendChild(style);
    }

    // Auto-focus first input on forms
    const firstInput = document.querySelector('input[type="text"], input[type="email"], input[type="password"]');
    if (firstInput) {
        firstInput.focus();
    }

    // Add click handlers for copy buttons (if any)
    document.querySelectorAll('[data-copy]').forEach(button => {
        button.addEventListener('click', function() {
            const textToCopy = this.getAttribute('data-copy');
            copyToClipboard(textToCopy);
        });
    });
});

// Export functions for use in other scripts (if using modules)
if (typeof module !== 'undefined' && module.exports) {
    module.exports = {
        logout,
        formatDate,
        showLoading,
        showError,
        showSuccess,
        copyToClipboard,
        validateFileType,
        validateFileSize,
        formatFileSize,
        isValidCertificateId,
        isValidQRData,
        formatQRData,
        checkAuth,
        getCurrentUser,
        requireAuth,
        showNotification,
        simpleHash,
        debounce,
        validateForm,
        resetFormValidation
    };
}

console.log('🔒 Certificate Authentication System - Common Scripts Loaded');
