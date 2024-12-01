const btnLoginPopup = document.querySelector('#openLoginPopup'); // Seleciona o botão de login
const wrapper = document.querySelector('.wrapper'); // Seleciona a wrapper (caixa do popup)
const overlay = document.querySelector('.overlay'); // Seleciona o overlay (fundo escuro)
const iconClose = document.querySelector('.icon-close'); // Seleciona o ícone de fechar
const registerLink = document.querySelector('.register-link'); // Link de cadastro
const loginLink = document.querySelector('.login-link'); // Link de login
const updateLink = document.querySelector('.update-link'); // Link de "Esqueceu sua senha?"
const cardLinks = document.querySelectorAll('.card-link'); // Seleciona todos os links dos cards

// Abre o popup de login ao clicar no botão de login (do header)
btnLoginPopup.addEventListener('click', () => {
    wrapper.classList.add('show');
    overlay.classList.add('show');
    wrapper.querySelector('.form-box.login').style.display = 'block'; // Mostra o formulário de login
    wrapper.querySelector('.form-box.register').style.display = 'none'; // Oculta o formulário de registro
    wrapper.querySelector('.form-box.update').style.display = 'none'; // Oculta o formulário de atualização
});

// Abre o popup de login ao clicar em qualquer card (se existirem)
cardLinks.forEach(cardLink => {
    cardLink.addEventListener('click', (e) => {
        e.preventDefault(); // Previne o redirecionamento para "login.html"
        wrapper.classList.add('show');
        overlay.classList.add('show');
        wrapper.querySelector('.form-box.login').style.display = 'block'; // Mostra o formulário de login
        wrapper.querySelector('.form-box.register').style.display = 'none'; // Oculta o formulário de registro
        wrapper.querySelector('.form-box.update').style.display = 'none'; // Oculta o formulário de atualização
    });
});

// Fecha o popup ao clicar no ícone de fechar
iconClose.addEventListener('click', () => {
    wrapper.classList.remove('show');
    overlay.classList.remove('show');
});

// Abre o formulário de cadastro ao clicar no link de cadastro
registerLink.addEventListener('click', (e) => {
    e.preventDefault();
    wrapper.querySelector('.form-box.login').style.display = 'none'; // Oculta login
    wrapper.querySelector('.form-box.register').style.display = 'block'; // Exibe registro
    wrapper.querySelector('.form-box.update').style.display = 'none'; // Oculta o formulário de atualização
});

// Abre o formulário de login ao clicar no link de login (dentro do popup de cadastro)
loginLink.addEventListener('click', (e) => {
    e.preventDefault();
    wrapper.querySelector('.form-box.register').style.display = 'none'; // Oculta registro
    wrapper.querySelector('.form-box.login').style.display = 'block'; // Exibe login
    wrapper.querySelector('.form-box.update').style.display = 'none'; // Oculta o formulário de atualização
});

// Abre o formulário de atualização de senha ao clicar no link "Esqueceu sua senha?"
updateLink.addEventListener('click', (e) => {
    e.preventDefault();
    wrapper.querySelector('.form-box.login').style.display = 'none'; // Oculta login
    wrapper.querySelector('.form-box.register').style.display = 'none'; // Oculta registro
    wrapper.querySelector('.form-box.update').style.display = 'block'; // Exibe atualização de senha
});