// Interactions légères, sans dépendance externe.

document.addEventListener('DOMContentLoaded', () => {
  initPasswordToggle();
  initLoginSubmitLoader();
  initUserMenu();
});

function initPasswordToggle() {
  const toggle = document.querySelector('[data-toggle-password]');
  const input = document.querySelector('[data-password-input]');
  if (!toggle || !input) return;

  toggle.addEventListener('click', () => {
    const isHidden = input.type === 'password';
    input.type = isHidden ? 'text' : 'password';
    toggle.setAttribute('aria-label', isHidden ? 'Masquer le mot de passe' : 'Afficher le mot de passe');
    toggle.querySelector('[data-icon-show]').style.display = isHidden ? 'none' : 'block';
    toggle.querySelector('[data-icon-hide]').style.display = isHidden ? 'block' : 'none';
  });
}

function initLoginSubmitLoader() {
  const form = document.querySelector('[data-login-form]');
  if (!form) return;

  form.addEventListener('submit', () => {
    const button = form.querySelector('[data-submit-button]');
    if (!button) return;
    button.disabled = true;
    button.querySelector('[data-btn-label]').textContent = 'Connexion en cours…';
    const spinner = button.querySelector('[data-spinner]');
    if (spinner) spinner.style.display = 'inline-block';
  });
}

function initUserMenu() {
  const menu = document.querySelector('[data-user-menu]');
  if (!menu) return;
  const trigger = menu.querySelector('[data-user-menu-trigger]');

  trigger.addEventListener('click', (event) => {
    event.stopPropagation();
    menu.classList.toggle('is-open');
  });

  document.addEventListener('click', (event) => {
    if (!menu.contains(event.target)) {
      menu.classList.remove('is-open');
    }
  });

  document.addEventListener('keydown', (event) => {
    if (event.key === 'Escape') menu.classList.remove('is-open');
  });
}
