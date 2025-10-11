document.addEventListener('DOMContentLoaded', function() {
    // Dynamic ruleset switching based on architecture
    const auditArchSelect = document.getElementById('audit_arch');
    const auditRulesetSelect = document.getElementById('audit_ruleset');
    
    if (auditArchSelect && auditRulesetSelect && window.rulesetData) {
        function updateRulesetOptions() {
            const selectedArch = auditArchSelect.value || 'x64';
            const rulesets = window.rulesetData[selectedArch] || [];
            const currentSelection = auditRulesetSelect.value;
            
            // Clear existing options
            auditRulesetSelect.innerHTML = '';
            
            // Add options from the ruleset data
            rulesets.forEach(function(ruleset) {
                const option = document.createElement('option');
                option.value = ruleset.Filename;
                option.textContent = ruleset.DisplayName;
                
                // Preserve selection if it exists in the new architecture
                if (ruleset.Filename === currentSelection) {
                    option.selected = true;
                } else if (!currentSelection && ruleset.IsDefault) {
                    // Select default if no current selection
                    option.selected = true;
                }
                
                auditRulesetSelect.appendChild(option);
            });
        }
        
        // Update rulesets when architecture changes
        auditArchSelect.addEventListener('change', updateRulesetOptions);
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
