document.addEventListener('DOMContentLoaded', function() {

    // Hide setup authentication and audit sections when OS type is Windows
    const osTypeSelect = document.getElementById('os_type');
    const setupAuthSection = document.getElementById('setup_auth_section');
    const setupUserInput = document.getElementById('setup_user');
    const auditConfigSection = document.getElementById('audit_config_section');

    if (osTypeSelect && setupAuthSection && setupUserInput) {
        const originalRequired = setupUserInput.required;

        function toggleOSSpecificSections() {
            if (osTypeSelect.value === 'windows') {
                setupAuthSection.classList.add('hidden');
                setupUserInput.required = false;
                setupUserInput.readOnly = true;
                
                // Hide audit config section for Windows
                if (auditConfigSection) {
                    auditConfigSection.style.display = 'none';
                }
            } else {
                setupAuthSection.classList.remove('hidden');
                setupUserInput.readOnly = false;
                setupUserInput.required = originalRequired;
                
                // Show audit config section for Linux
                if (auditConfigSection) {
                    auditConfigSection.style.display = 'block';
                }
            }
        }

        toggleOSSpecificSections();
        osTypeSelect.addEventListener('change', toggleOSSpecificSections);
    }

});
