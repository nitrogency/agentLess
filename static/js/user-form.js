document.addEventListener('DOMContentLoaded', function() {
    // Get elements
    const isAdminCheckbox = document.getElementById('isAdmin');
    const canAddDevices = document.getElementById('canAddDevices');
    const canModifyDevices = document.getElementById('canModifyDevices');
    const canAddUsers = document.getElementById('canAddUsers');
    const canModifyUsers = document.getElementById('canModifyUsers');
    
    // Only proceed if elements exist
    if (isAdminCheckbox) {
        function updatePermissions() {
            const isAdmin = isAdminCheckbox.checked;
            
            if (isAdmin) {
                // If admin is checked, check and disable other permissions
                if (canAddDevices) {
                    canAddDevices.checked = true;
                    canAddDevices.disabled = true;
                }
                if (canModifyDevices) {
                    canModifyDevices.checked = true;
                    canModifyDevices.disabled = true;
                }
                if (canAddUsers) {
                    canAddUsers.checked = true;
                    canAddUsers.disabled = true;
                }
                if (canModifyUsers) {
                    canModifyUsers.checked = true;
                    canModifyUsers.disabled = true;
                }
            } else {
                // If admin is unchecked, enable other permissions
                if (canAddDevices) canAddDevices.disabled = false;
                if (canModifyDevices) canModifyDevices.disabled = false;
                if (canAddUsers) canAddUsers.disabled = false;
                if (canModifyUsers) canModifyUsers.disabled = false;
            }
        }
        
        // Set initial state
        updatePermissions();
        
        // Add event listener for checkbox changes
        isAdminCheckbox.addEventListener('change', updatePermissions);
    }
});
