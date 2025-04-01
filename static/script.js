
document.addEventListener('DOMContentLoaded', function() {
    const generateButton = document.getElementById('generate-password');
    const passwordField = document.getElementById('password-field');

    generateButton.addEventListener('click', function() {
        const password = generateStrongPassword(16);
        passwordField.value = password;
    });
});

function generateStrongPassword(length) {
    const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()_+~`|}{[]:;?><,./-=";
    let password = "";
    for (let i = 0; i < length; i++) {
        const randomIndex = Math.floor(Math.random() * charset.length);
        password += charset[randomIndex];
    }
    return password;
}
