document.addEventListener('DOMContentLoaded', function() {
    const passwordInput = document.getElementById('password');
    const requirements = {
        length: { regex: /.{12,}/, text: 'At least 12 characters long' },
        uppercase: { regex: /[A-Z]/, text: 'Contains an uppercase letter' },
        lowercase: { regex: /[a-z]/, text: 'Contains a lowercase letter' },
        number: { regex: /[0-9]/, text: 'Contains a number' },
        special: { regex: /[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?~]/, text: 'Contains a special character' }
    };

    function validatePassword(password) {
        const results = {};
        for (const [key, requirement] of Object.entries(requirements)) {
            results[key] = requirement.regex.test(password);
        }
        return results;
    }

    function updateRequirements(results) {
        for (const [key, valid] of Object.entries(results)) {
            const element = document.getElementById(`req-${key}`);
            if (element) {
                if (valid) {
                    element.classList.add('valid');
                } else {
                    element.classList.remove('valid');
                }
            }
        }
    }

    // Create requirement elements if they don't exist
    if (!document.querySelector('.password-requirements')) {
        const container = document.createElement('div');
        container.className = 'password-requirements';
        
        for (const [key, requirement] of Object.entries(requirements)) {
            const req = document.createElement('div');
            req.id = `req-${key}`;
            req.className = 'requirement';
            req.textContent = requirement.text;
            container.appendChild(req);
        }

        // Insert after password input
        passwordInput.parentNode.insertBefore(container, passwordInput.nextSibling);
    }

    // Add event listener for password input
    passwordInput.addEventListener('input', function(e) {
        const results = validatePassword(e.target.value);
        updateRequirements(results);
    });
});
