// Password change form toggle
const togglePasswordForm = document.getElementById('togglePasswordForm');
const passwordChangeForm = document.getElementById('passwordChangeForm');
const cancelPasswordChange = document.getElementById('cancelPasswordChange');

togglePasswordForm.addEventListener('click', () => {
    passwordChangeForm.classList.toggle('hidden');
    if (!passwordChangeForm.classList.contains('hidden')) {
        togglePasswordForm.textContent = 'Hide Form';
    } else {
        togglePasswordForm.textContent = 'Change Password';
    }
});

cancelPasswordChange.addEventListener('click', () => {
    passwordChangeForm.classList.add('hidden');
    togglePasswordForm.textContent = 'Change Password';
    passwordChangeForm.reset();
});

// Password change form handling
passwordChangeForm.addEventListener('submit', async (e) => {
    e.preventDefault();
    
    const currentPassword = document.getElementById('currentPassword').value;
    const newPassword = document.getElementById('newPassword').value;
    const confirmPassword = document.getElementById('confirmPassword').value;
    
    // Validate passwords match
    if (newPassword !== confirmPassword) {
        showNotification('New passwords do not match', 'error');
        return;
    }
    
    // Validate password length
    if (newPassword.length < 6) {
        showNotification('New password must be at least 6 characters long', 'error');
        return;
    }
    
    try {
        const response = await fetch('/auth/change-password', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${localStorage.getItem('token')}`
            },
            body: JSON.stringify({ currentPassword, newPassword })
        });
        
        const data = await response.json();
        
        if (response.ok) {
            showNotification('Password updated successfully', 'success');
            // Hide form and reset
            passwordChangeForm.classList.add('hidden');
            togglePasswordForm.textContent = 'Change Password';
            passwordChangeForm.reset();
        } else {
            showNotification(data.error || 'Failed to update password', 'error');
        }
    } catch (error) {
        console.error('Password change error:', error);
        showNotification('An error occurred while changing password', 'error');
    }
});

// Helper function to show notifications
function showNotification(message, type = 'info') {
    const notification = document.createElement('div');
    notification.className = `fixed top-4 right-4 px-6 py-3 rounded-lg text-white ${
        type === 'success' ? 'bg-green-600' : 
        type === 'error' ? 'bg-red-600' : 
        'bg-blue-600'
    }`;
    notification.textContent = message;
    
    document.body.appendChild(notification);
    
    // Remove notification after 3 seconds
    setTimeout(() => {
        notification.remove();
    }, 3000);
} 