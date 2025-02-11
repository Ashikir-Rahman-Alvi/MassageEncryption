// Security configurations
const SECURITY = {
    PBKDF2_ITERATIONS: 600000,
    // Updated to OWASP recommendation
    MIN_PASSWORD_LENGTH: 8,
    MAX_ATTEMPTS: 5,
    ATTEMPT_TIMEOUT: 30000 // 30 seconds
};

let failedAttempts = 0;
let lastAttemptTime = 0;

function validateInputs() {
    const text = document.getElementById('inputText').value;
    const password = document.getElementById('password').value;

    if (!text || !password) {
        showStatus('Both fields are required', 'error');
        return false;
    }

    if (password.length < SECURITY.MIN_PASSWORD_LENGTH) {
        showStatus(`Password must be at least ${SECURITY.MIN_PASSWORD_LENGTH} characters`, 'error');
        return false;
    }

    return true;
}

function checkPasswordStrength(password) {
    const strengthMeter = document.getElementById('password-strength');
    let strength = 0;

    if (password.length >= SECURITY.MIN_PASSWORD_LENGTH) strength++;
    if (password.match(/[A-Z]/)) strength++;
    if (password.match(/[0-9]/)) strength++;
    if (password.match(/[^A-Za-z0-9]/)) strength++;

    strengthMeter.className = `password-strength strength-${Math.min(strength, 3)}`;
}

async function encryptText() {
    if (!validateInputs()) return;

    try {
        const text = new TextEncoder().encode(document.getElementById('inputText').value);
        const password = document.getElementById('password').value;

        // Security: Wipe sensitive data after use
        /*  window.setTimeout(() => {
                document.getElementById('inputText').value = '';
                document.getElementById('password').value = '';
            }, 0);*/

        const salt = crypto.getRandomValues(new Uint8Array(32)); // Larger salt
        const iv = crypto.getRandomValues(new Uint8Array(16)); // Larger IV

        const key = await deriveKey(password, salt);
        const encrypted = await crypto.subtle.encrypt(
            {
                name: "AES-GCM", iv, tagLength: 128
            },
            key,
            text
        );

        const combined = new Uint8Array([
            ...salt,
            ...iv,
            ...new Uint8Array(encrypted)
        ]);

        document.getElementById('outputText').value = base64url(combined);
        showStatus('Encrypted successfully');
    } catch (error) {
        showStatus('Encryption failed', 'error');
        console.error(error); // Detailed errors only in console
    }
}

async function decryptText() {
    // Rate limiting
    const now = Date.now();
    if (now - lastAttemptTime < SECURITY.ATTEMPT_TIMEOUT) {
        showStatus('Too many attempts. Please wait 30 seconds', 'error');
        return;
    }

    if (failedAttempts >= SECURITY.MAX_ATTEMPTS) {
        showStatus('Maximum attempts reached. Please wait 30 seconds', 'error');
        return;
    }

    if (!validateInputs()) return;

    try {
        const encryptedData = document.getElementById('inputText').value;
        const password = document.getElementById('password').value;

        const combined = base64urlToBytes(encryptedData);
        const salt = combined.slice(0, 32);
        const iv = combined.slice(32, 48);
        const data = combined.slice(48);

        const key = await deriveKey(password, salt);
        const decrypted = await crypto.subtle.decrypt(
            {
                name: "AES-GCM", iv
            },
            key,
            data
        );

        document.getElementById('outputText').value =
        new TextDecoder().decode(decrypted);
        failedAttempts = 0;
        showStatus('Decrypted successfully');
    } catch (error) {
        failedAttempts++;
        lastAttemptTime = Date.now();
        showStatus('Decryption failed. Check password/data', 'error');
        console.error(error);
    }
}

// Secure base64 URL-safe encoding
function base64url(buffer) {
    return btoa(String.fromCharCode(...new Uint8Array(buffer)))
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/, '');
}

function base64urlToBytes(base64) {
    const padding = '='.repeat((4 - (base64.length % 4)) % 4);
    const sanitized = (base64 + padding)
    .replace(/-/g, '+')
    .replace(/_/g, '/');
    return Uint8Array.from(atob(sanitized), c => c.charCodeAt(0));
}

async function deriveKey(password, salt) {
    const keyMaterial = await crypto.subtle.importKey(
        "raw",
        new TextEncoder().encode(password),
        {
            name: "PBKDF2"
        },
        false,
        ["deriveKey"]
    );

    return crypto.subtle.deriveKey(
        {
            name: "PBKDF2",
            salt,
            iterations: SECURITY.PBKDF2_ITERATIONS,
            hash: "SHA-384"
        },
        keyMaterial,
        {
            name: "AES-GCM", length: 256
        },
        false,
        ["encrypt", "decrypt"]
    );
}

function togglePassword() {
    var passwordField = document.getElementById("password");
    var eyeIcon = document.getElementById("eyeIcon");

    if (passwordField.type === "password") {
        passwordField.type = "text";
        eyeIcon.innerHTML = '<path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/><circle cx="12" cy="12" r="3"/><line x1="2" y1="2" x2="22" y2="22" stroke="black" stroke-width="2"/>';
    } else {
        passwordField.type = "password";
        eyeIcon.innerHTML = '<path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/><circle cx="12" cy="12" r="3"/>';
    }
}

async function copyResult() {
    const output = document.getElementById('outputText');
    const button = document.querySelector('.copy-button');

    try {
        await navigator.clipboard.writeText(output.value);
        button.classList.add('copied');
        showStatus('Copied to clipboard!');
        setTimeout(() => button.classList.remove('copied'), 2000);
    } catch (err) {
        showStatus('Failed to copy', 'error');
    }
}

function showStatus(message, type = 'success') {
    const status = document.getElementById('status');
    status.className = `status-message ${type}`;
    status.textContent = message;
    status.style.display = 'block';
    setTimeout(() => status.style.display = 'none', 5000);
}

function resetFields() {
    document.getElementById("inputText").value = "";
    document.getElementById("password").value = "";
    document.getElementById("outputText").value = "";
    document.getElementById("password-strength").className = "password-strength"; // Reset strength bar
}

// Add security event listeners
document.addEventListener('DOMContentLoaded', () => {
    document.getElementById('password').addEventListener('keypress', e => {
        if (e.key === 'Enter') decryptText();
    });

    window.addEventListener('beforeunload',
        () => {
            document.getElementById('inputText').value = '';
            document.getElementById('password').value = '';
            document.getElementById('outputText').value = '';
            document.getElementById("password-strength").className = "password-strength"; // Reset strength bar
        });
});


function continuousCall() {

    const sss = document.getElementById('password').value;
    const textbox =  document.getElementById('inputText').value;

    if (sss == "") {

        document.getElementById("password-strength").className = "password-strength"; // Reset strength bar

    }
    


    setTimeout(continuousCall, 100);
}

continuousCall(); // Start the continuous call