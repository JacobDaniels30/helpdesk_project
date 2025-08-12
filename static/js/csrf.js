/**
 * CSRF Token Handler
 * Automatically adds CSRF tokens to forms and AJAX requests
 */

class CSRFHandler {
    constructor() {
        this.token = this.getToken();
        this.init();
    }

    getToken() {
        const meta = document.querySelector('meta[name="csrf-token"]');
        return meta ? meta.getAttribute('content') : null;
    }

    init() {
        this.addToForms();
        this.addToAjax();
    }

    addToForms() {
        // Add CSRF token to all forms
        document.addEventListener('DOMContentLoaded', () => {
            const forms = document.querySelectorAll('form[method="POST"]');
            forms.forEach(form => {
                if (!form.querySelector('input[name="csrf_token"]')) {
                    const input = document.createElement('input');
                    input.type = 'hidden';
                    input.name = 'csrf_token';
                    input.value = this.token;
                    form.appendChild(input);
                }
            });
        });
    }

    addToAjax() {
        // Add CSRF token to all AJAX requests
        const originalFetch = window.fetch;
        window.fetch = (url, options = {}) => {
            if (options.method && options.method.toUpperCase() !== 'GET') {
                options.headers = {
                    ...options.headers,
                    'X-CSRF-Token': this.token
                };
            }
            return originalFetch(url, options);
        };

        // Also handle XMLHttpRequest
        const originalOpen = XMLHttpRequest.prototype.open;
        XMLHttpRequest.prototype.open = function(method, url, ...args) {
            if (method.toUpperCase() !== 'GET') {
                this.setRequestHeader('X-CSRF-Token', this.token);
            }
            return originalOpen.call(this, method, url, ...args);
        };
    }

    refreshToken() {
        // Method to refresh token if needed
        fetch('/csrf-token', {
            method: 'GET',
            headers: {
                'X-Requested-With': 'XMLHttpRequest'
            }
        })
        .then(response => response.json())
        .then(data => {
            this.token = data.token;
            const meta = document.querySelector('meta[name="csrf-token"]');
            if (meta) {
                meta.setAttribute('content', this.token);
            }
        });
    }
}

// Initialize CSRF handler
const csrfHandler = new CSRFHandler();
