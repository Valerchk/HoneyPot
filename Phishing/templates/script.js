// Gestion de la soumission de l'email (index.html)
const emailForm = document.getElementById('email-form');
if (emailForm) {
    emailForm.addEventListener('submit', function(e) {
        e.preventDefault();
        const email = document.getElementById('email').value;
        sessionStorage.setItem('userEmail', email);
        window.location.href = 'password.html';
    });
}

// Affichage de l'email sur la page mot de passe (password.html)
window.addEventListener('DOMContentLoaded', (event) => {
    const emailDisplay = document.getElementById('email-display');
    if (emailDisplay) {
        const userEmail = sessionStorage.getItem('userEmail');
        if (userEmail) {
            emailDisplay.textContent = userEmail;
        }
    }

    // Gestion de la soumission du mot de passe (password.html)
    const form = document.querySelector('form');
    if (form) {
        form.addEventListener('submit', function(e) {
            e.preventDefault();
            const password = document.getElementById('password').value;
            if (password) {
                // Redirige vers la page de validation de connexion
                window.location.href = 'connect.html';
            }
        });
    }
});
