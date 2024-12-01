const express = require('express');
const bodyParser = require('body-parser');
const db = require('./db');
const path = require('path');
const multer = require('multer');
const session = require('express-session');
const fs = require('fs');
const { promisify } = require('util');
const { google } = require('googleapis'); // Adicionando a API do Google
const oauth2Client = new google.auth.OAuth2(
    '579497627903-i3fi5b6utr3do1a87rtuei7jmcu6hh9u.apps.googleusercontent.com', // Substitua pelo seu client ID
    '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', // Substitua pelo seu client secret
    'http://localhost:5505/auth/google/callback' // Substitua pelo seu URL de redirecionamento
);
const bcrypt = require('bcrypt');
const xlsx = require("xlsx");

const app = express();

app.use(express.json());
app.use(bodyParser.json({limit: '50mb'}));
app.use(bodyParser.urlencoded({limit: '50mb', extended: true}));
app.use(express.static('public'));
app.use('/img', express.static(path.join(__dirname, 'img')));


// Configuração da sessão
app.use(session({
    secret: 'seuSegredoAqui',
    resave: false,
    saveUninitialized: false,
    cookie: {
        secure: false,
        maxAge: 24 * 60 * 60 * 1000 // 24 horas
    }
}));

// Configuração do Google OAuth
const SCOPES = ['profile', 'email'];

// Rota para iniciar o login com o Google
app.get('/auth/google', (req, res) => {
    const url = oauth2Client.generateAuthUrl({
        access_type: 'offline',
        scope: SCOPES
    });
    res.redirect(url);
});

// Rota para o Google redirecionar após o login
app.get('/auth/google/callback', async (req, res) => {
    const code = req.query.code;
    
    try {
        const { tokens } = await oauth2Client.getToken(code);
        oauth2Client.setCredentials(tokens);
        
        // Obter as informações do perfil do Google
        const people = google.people({ version: 'v1', auth: oauth2Client });
        const me = await people.people.get({
            resourceName: 'people/me',
            personFields: 'names,emailAddresses,photos'
        });
        
        // Processamento do login ou cadastro
        const googleUser = me.data;
        const { name, emailAddresses, photos } = googleUser;
        const email = emailAddresses[0].value;
        const profilePic = photos && photos[0].url;

        // Verificação de usuário no banco de dados
        db.query('SELECT * FROM usuario WHERE email = ?', [email], (err, results) => {
            if (err) {
                console.error(err);
                return res.status(500).json({ message: 'Erro ao verificar usuário no banco de dados.' });
            }
            
            if (results.length > 0) {
                req.session.user = { 
                    id: results[0].id, 
                    nome: results[0].nome, 
                    email: results[0].email, 
                    profilePic: results[0].profilePic 
                };
                return res.redirect('/index');
            } else {
                const insertQuery = 'INSERT INTO usuario (nome, email, profilePic) VALUES (?, ?, ?)';
                db.query(insertQuery, [name, email, profilePic], (err, results) => {
                    if (err) {
                        console.error(err);
                        return res.status(500).json({ message: 'Erro ao criar novo usuário no banco de dados.' });
                    }
                    
                    req.session.user = { 
                        id: results.insertId, 
                        nome: name, 
                        email, 
                        profilePic 
                    };
                    res.redirect('/');
                });
            }
        });
    } catch (error) {
        console.error(error);
        res.status(500).json({ message: 'Erro ao autenticar com o Google.' });
    }
});

// Configuração para upload de imagens de perfil
const storage = multer.diskStorage({
    destination: path.join(__dirname, 'public', 'img'),
    filename: (req, file, cb) => {
        const userId = req.session.user?.id || 'default';
        const ext = path.extname(file.originalname);
        cb(null, `profile_${userId}${ext}`);
    }
});

const upload = multer({
    storage: storage,
    limits: {
        fileSize: 5 * 1024 * 1024 // 5MB
    },
    fileFilter: function (req, file, cb) {
        const filetypes = /jpeg|jpg|png|gif/;
        const mimetype = filetypes.test(file.mimetype);
        const extname = filetypes.test(path.extname(file.originalname).toLowerCase());

        if (mimetype && extname) {
            return cb(null, true);
        }
        cb(new Error('Apenas imagens são permitidas!'));
    }
});

// middleware para verificar autenticação em rotas protegidas
function verificarAutenticacao(req, res, next) {
    if (req.session.user) {
        console.log('Usuário autenticado:', req.session.user);
        next(); // usuário autenticado, segue para a rota
    } else {
        console.log('Usuário não autenticado');
        res.redirect('/'); // redireciona para a página inicial se não estiver autenticado
    }
}

// rota inicial
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'public/home.html'));
});

// rota de login
app.post('/login', (req, res) => {
    const { email, senha } = req.body;
    const query = 'SELECT * FROM usuario WHERE email = ?';
    db.query(query, [email], (err, results) => {
        if (err) {
            console.error('Erro no login:', err);
            return res.status(500).send('Erro no servidor.');
        }
        if (results.length === 0) {
            return res.status(401).send('Usuário não encontrado.');
        }
        const user = results[0];
        // Comparar senha hashada
        bcrypt.compare(senha, user.senha, (err, isMatch) => {
            if (err) {
                console.error('Erro ao comparar senhas:', err);
                return res.status(500).send('Erro no servidor.');
            }
            if (!isMatch) {
                return res.status(401).send('Senha incorreta.');
            }
            req.session.user = {
                id: user.id,
                nome: user.nome,
                email: user.email,
            };
            return res.status(200).json({ message: 'Login realizado com sucesso!' });
        });
    });
});

// rota de cadastro
app.post('/cadastro', (req, res) => {
    const { nome, email, senha } = req.body;
    const checkUserQuery = 'SELECT * FROM usuario WHERE email = ?';
    db.query(checkUserQuery, [email], (err, results) => {
        if (err) {
            console.error('Erro ao verificar usuário:', err);
            return res.status(500).send('Erro no servidor.');
        }
        if (results.length > 0) {
            return res.status(409).send('Usuário já cadastrado.');
        }
        // Hash da senha
        bcrypt.hash(senha, 10, (err, hashedSenha) => {
            if (err) {
                console.error('Erro ao criptografar senha:', err);
                return res.status(500).send('Erro ao processar senha.');
            }
            const insertQuery = 'INSERT INTO usuario (nome, email, senha) VALUES (?, ?, ?)';
            db.query(insertQuery, [nome, email, hashedSenha], (err, results) => {
                if (err) {
                    console.error('Erro ao criar usuário:', err);
                    return res.status(500).send('Erro ao cadastrar usuário.');
                }
                return res.status(201).send('Cadastro realizado com sucesso!');
            });
        });
    });
});


// Rota para enviar contato
app.post('/contato', (req, res) => {
    const { nome, email, telefone, mensagem } = req.body;
    if (!nome || !email || !telefone || !mensagem) {
        return res.json({ success: false, message: 'Todos os campos são obrigatórios.' });
    }
    db.query(
        'INSERT INTO contato (nome, email, telefone, mensagem) VALUES (?, ?, ?, ?)', 
        [nome, email, telefone, mensagem], 
        (err, results) => {
            if (err) {
                console.error(err);
                return res.json({ success: false, message: 'Erro ao enviar a mensagem.' });
            }
            res.json({ success: true, message: 'Mensagem enviada com sucesso!' });
        }
    );
});

app.post('/atualizarPerfil', verificarAutenticacao, (req, res) => {
    const { nome, email, senha } = req.body;
    const userId = req.session.user.id;

    let query = 'UPDATE usuario SET nome = ?, email = ?';
    const params = [nome, email];

    if (senha) {
        query += ', senha = ?';
        params.push(senha);  // Se uma senha for fornecida, ela será atualizada
    }

    query += ' WHERE id = ?';
    params.push(userId);

    db.query(query, params, (err) => {
        if (err) {
            console.error('Erro ao atualizar perfil:', err);
            return res.status(500).json({ message: 'Erro ao atualizar perfil' });
        }
        res.json({ message: 'Perfil atualizado com sucesso!' });
    });
});

//rota protegida - dashboard
app.get('/index', verificarAutenticacao, (req, res) => {
    res.sendFile(path.join(__dirname, 'public/dashboard/index.html')); 
});


// Rota para atualizar a senha do usuário
app.post('/atualizarSenha', (req, res) => {
    const { email, newPassword } = req.body;
    // Usando Promises em vez de await
    db.query('SELECT * FROM usuario WHERE email = ?', [email], (error, results) => {
        if (error) {
            console.error(error);
            return res.json({ success: false, message: 'Erro ao verificar o usuário.' });
        }

        if (results.length > 0) {
            // Atualizar a senha no banco de dados
            db.query('UPDATE usuario SET senha = ? WHERE email = ?', [newPassword, email], (error, results) => {
                if (error) {
                    console.error(error);
                    return res.json({ success: false, message: 'Erro ao atualizar a senha.' });
                }

                res.json({ success: true });
            });
        } else {
            res.json({ success: false, message: 'Usuário não encontrado.' });
        }
    });
});

//rota para bd
app.get('/getUserData', verificarAutenticacao, (req, res) => {
    const usuarioId = req.session.user.id;

    const query = 'SELECT nome, email, senha, profilePic FROM usuario WHERE id = ?';
    db.query(query, [usuarioId], (err, results) => {
        if (err) {
            return res.status(500).json({ message: 'Erro ao buscar dados do usuário' });
        }
        res.json(results[0]);
    });
});

//rota protegida para o usuario
app.get('/user', verificarAutenticacao, (req, res) => {
    const userId = req.session.user.id;
    
    const query = 'SELECT nome, email, senha, profilePic FROM usuario WHERE id = ?';
    db.query(query, [userId], (err, results) => {
        if (err) {
            return res.status(500).json({ message: 'Erro ao buscar dados do usuário' });
        }
        if (results.length > 0) {
            res.json(results[0]);
        } else {
            res.status(404).json({ message: 'Usuário não encontrado' });
        }
    });
}); 

//atualizar imagem
app.post('/upload-profile-image', verificarAutenticacao, upload.single('profilePic'), async (req, res) => {
    if (!req.file) {
        return res.status(400).json({ message: 'Nenhum arquivo foi enviado' });
    }

    try {
        const userId = req.session.user.id;
        const imagePath = req.file.filename;

        const query = 'UPDATE usuario SET profilePic = ? WHERE id = ?';
        db.query(query, [imagePath, userId], (err) => {
            if (err) {
                console.error('Erro ao atualizar foto de perfil no banco:', err);
                return res.status(500).json({ message: 'Erro ao atualizar foto' });
            }
            res.json({
                message: 'Imagem atualizada com sucesso!',
                filename: imagePath
            });
        });
    } catch (error) {
        console.error('Erro no upload de imagem:', error);
        res.status(500).json({ message: 'Erro no upload de imagem' });
    }
});

// rota de logout
app.post('/logout', (req, res) => {
    req.session.destroy((err) => {
        if (err) {
            return res.status(500).json({ message: 'Erro ao encerrar sessão.' });
        }
        res.status(200).json({ message: 'Logout realizado com sucesso!' });
    });
});
app.use(express.static(path.join(__dirname, 'public')));
app.use('/uploads', express.static('uploads'));





// Rota para `perfil.html`
app.get('/perfil', verificarAutenticacao, (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'perfil.html'));
});

// Rota para obter dados do usuário
app.get('/user', verificarAutenticacao, (req, res) => {
    const userId = req.session.user.id;
    db.query('SELECT nome, email, profilePic FROM usuario WHERE id = ?', [userId], (err, results) => {
        if (err) return res.status(500).json({ message: 'Erro no servidor.' });
        if (results.length === 0) return res.status(404).json({ message: 'Usuário não encontrado.' });
        res.json(results[0]);
    });
});

// Rota para atualizar o perfil do usuário
app.post('/atualizarPerfil', verificarAutenticacao, (req, res) => {
    const { nome, email, senha } = req.body;
    const userId = req.session.user.id;

    const updates = [];
    const params = [];
    if (nome) { updates.push('nome = ?'); params.push(nome); }
    if (email) { updates.push('email = ?'); params.push(email); }
    if (senha) { updates.push('senha = ?'); params.push(senha); }

    params.push(userId);

    const query = `UPDATE usuario SET ${updates.join(', ')} WHERE id = ?`;
    db.query(query, params, (err) => {
        if (err) return res.status(500).json({ message: 'Erro ao atualizar o perfil.' });
        res.json({ message: 'Perfil atualizado com sucesso!' });
    });
});

// Rota para upload de imagem
app.post('/upload-profile-image', verificarAutenticacao, upload.single('profilePic'), (req, res) => {
    if (!req.file) {
        return res.status(400).json({ message: 'Nenhuma imagem enviada.' });
    }

    const userId = req.session.user.id;
    const imagePath = req.file.filename;

    const query = 'UPDATE usuario SET profilePic = ? WHERE id = ?';
    db.query(query, [imagePath, userId], (err) => {
        if (err) return res.status(500).json({ message: 'Erro ao salvar imagem.' });
        res.json({ message: 'Imagem atualizada com sucesso!', filename: imagePath });
    });
});
app.get("/api/energy-data", (req, res) => {
    try {
        const workbookPath = path.join(__dirname, "planilha.xlsx");
        const workbook = xlsx.readFile(workbookPath);
        const sheet = workbook.Sheets["Planilha"];
        const jsonData = xlsx.utils.sheet_to_json(sheet);

        const processedData = jsonData.map((item) => {
            const consumoMensal = parseFloat(item["Consumo Mensal(kWh)"]) || 0;
            const custoEstimado = parseFloat(item["Custo Estimado(R$)"]) || 0;
            return {
                aparelho: item["Aparelho"],
                consumoMensal,
                custoEstimado,
            };
        });

        res.json(processedData);
    } catch (err) {
        console.error("Erro ao ler a planilha:", err.message);
        res.status(500).json({ error: "Erro ao processar a planilha. Verifique o caminho e o formato do arquivo." });
    }
});



// inicializar o servidor
app.listen(5505, () => {
    console.log('Servidor rodando na porta 5505');
});