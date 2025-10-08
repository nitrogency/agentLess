document.addEventListener('DOMContentLoaded', function() {
    const randomUserCheckbox = document.getElementById('random_user');
    const sshUserInput = document.getElementById('ssh_user');
    const sshGroupInput = document.getElementById('ssh_group');
    const randomKeyCheckbox = document.getElementById('random_key');
    const sshKeyPathInput = document.getElementById('ssh_key_path');
    
    // Only proceed if elements exist (for add-device page)
    if (randomUserCheckbox && sshUserInput && sshGroupInput) {
        let savedSshUser = '';
        let savedSshGroup = '';
        let savedUserPlaceholder = sshUserInput.placeholder;
        let savedGroupPlaceholder = sshGroupInput.placeholder;

        // Function to toggle SSH user and group fields based on random user checkbox
        function toggleSshFields() {
            if (randomUserCheckbox.checked) {
                // Save current values and placeholders before disabling
                savedSshUser = sshUserInput.value;
                savedSshGroup = sshGroupInput.value;
                savedUserPlaceholder = sshUserInput.placeholder;
                savedGroupPlaceholder = sshGroupInput.placeholder;
                
                // Clear and disable fields, update placeholders
                sshUserInput.value = '';
                sshGroupInput.value = '';
                sshUserInput.placeholder = "Will be generated from wordlist";
                sshGroupInput.placeholder = "Will be generated from wordlist";
                sshUserInput.required = false;
                sshGroupInput.required = false;
                sshUserInput.disabled = true;
                sshGroupInput.disabled = true;
            } else {
                // Restore saved values, placeholders and enable fields
                sshUserInput.value = savedSshUser;
                sshGroupInput.value = savedSshGroup;
                sshUserInput.placeholder = savedUserPlaceholder;
                sshGroupInput.placeholder = savedGroupPlaceholder;
                sshUserInput.required = true;
                sshGroupInput.required = true;
                sshUserInput.disabled = false;
                sshGroupInput.disabled = false;
            }
        }

        // Initial setup and event listener
        toggleSshFields();
        randomUserCheckbox.addEventListener('change', toggleSshFields);
    }

    // Handle SSH key path field (for both add and edit pages)
    if (randomKeyCheckbox && sshKeyPathInput) {
        let savedSshKeyPath = '';
        let savedKeyPathPlaceholder = sshKeyPathInput.placeholder;

        // Function to toggle SSH key path field based on random key checkbox
        function toggleSshKeyPathField() {
            if (randomKeyCheckbox.checked) {
                // Save current value and placeholder before disabling
                savedSshKeyPath = sshKeyPathInput.value;
                savedKeyPathPlaceholder = sshKeyPathInput.placeholder;
                
                // Clear and disable field, update placeholder
                sshKeyPathInput.value = '';
                sshKeyPathInput.placeholder = "Will be generated automatically";
                sshKeyPathInput.required = false;
                sshKeyPathInput.disabled = true;
            } else {
                // Restore saved value, placeholder and enable field
                sshKeyPathInput.value = savedSshKeyPath;
                sshKeyPathInput.placeholder = savedKeyPathPlaceholder;
                sshKeyPathInput.required = true;
                sshKeyPathInput.disabled = false;
            }
        }

        // Initial setup and event listener
        toggleSshKeyPathField();
        randomKeyCheckbox.addEventListener('change', toggleSshKeyPathField);
    }

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
                setupUserInput.disabled = true;
                
                // Hide audit config section for Windows
                if (auditConfigSection) {
                    auditConfigSection.style.display = 'none';
                }
            } else {
                setupAuthSection.classList.remove('hidden');
                setupUserInput.disabled = false;
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

    // Handle firewall mode selection
    const firewallModeSelect = document.getElementById('firewall_mode');
    const firewallAllowedIpsGroup = document.getElementById('firewall_allowed_ips_group');
    const firewallAllowedIpsInput = document.getElementById('firewall_allowed_ips');

    if (firewallModeSelect && firewallAllowedIpsGroup && firewallAllowedIpsInput) {
        function toggleFirewallAllowedIps() {
            if (firewallModeSelect.value === 'ssh_restricted') {
                firewallAllowedIpsGroup.style.display = 'block';
                firewallAllowedIpsInput.required = false; // Optional field - monitoring server will always be allowed
            } else {
                firewallAllowedIpsGroup.style.display = 'none';
                firewallAllowedIpsInput.required = false;
            }
        }

        // Initial setup and event listener
        toggleFirewallAllowedIps();
        firewallModeSelect.addEventListener('change', toggleFirewallAllowedIps);
    }
});
