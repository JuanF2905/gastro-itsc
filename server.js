const express = require('express');
const cors = require('cors');
const http = require('http');
const { Server } = require('socket.io');
const sqlite3 = require('sqlite3').verbose();
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt'); // NUEVO: Importación para encriptar contraseñas

const app = express();
const server = http.createServer(app);

// Habilitar comunicación con el frontend
app.use(cors());
app.use(express.json());

const io = new Server(server, { cors: { origin: '*' } });
const JWT_SECRET = 'itsc_gastro_super_secret_key_2026';

// ==========================================
// CAPA DE DATOS (DAL): CONFIGURACIÓN SQLITE
// ==========================================
const db = new sqlite3.Database('./gastronomia.db', (err) => {
    if (err) console.error('Error conectando a la base de datos:', err.message);
    else console.log('🗄️ Base de datos SQL conectada (gastronomia.db)');
});

// Crear tablas relacionales si no existen
db.serialize(() => {
    db.run(`CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT,
        email TEXT UNIQUE,
        usuario TEXT UNIQUE,
        password TEXT
    )`);

    db.run(`CREATE TABLE IF NOT EXISTS videos (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        title TEXT,
        desc TEXT,
        url TEXT,
        author TEXT,
        type TEXT DEFAULT 'youtube'
    )`);
});

// Variables en memoria solo para el chat en vivo
const chatMessages = [
    { sender: "Sistema Culinario", usuario: "sistema", text: "¡El servidor persistente está en línea!", time: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }) }
];
const onlineUsers = {};

// ==========================================
// CAPA LÓGICA (BLL): RUTAS DE AUTENTICACIÓN
// ==========================================

// 1. Registro Seguro (Hashing)
app.post('/api/auth/register', async (req, res) => {
    const { name, email, usuario, password } = req.body;
    
    try {
        // Encriptar la contraseña con un "salt" de 10 rondas de seguridad
        const hashedPassword = await bcrypt.hash(password, 10);
        
        const query = `INSERT INTO users (name, email, usuario, password) VALUES (?, ?, ?, ?)`;
        db.run(query, [name, email, usuario, hashedPassword], function(err) {
            if (err) {
                if (err.message.includes('UNIQUE')) return res.status(400).json({ error: 'El correo o usuario ya existe en la base de datos.' });
                return res.status(500).json({ error: 'Error interno del servidor.' });
            }
            res.status(201).json({ message: 'Usuario creado', user: { name, email, usuario } });
        });
    } catch (error) {
        res.status(500).json({ error: 'Error encriptando la contraseña' });
    }
});

// 2. Login Seguro (Validación Hash)
app.post('/api/auth/login', (req, res) => {
    const { identifier, password } = req.body;
    
    const query = `SELECT * FROM users WHERE usuario = ? OR email = ?`;
    db.get(query, [identifier, identifier], async (err, user) => {
        if (err) return res.status(500).json({ error: 'Error consultando la base de datos.' });
        if (!user) return res.status(401).json({ error: 'Credenciales incorrectas.' });
        
        try {
            // Comparar la contraseña ingresada con el hash guardado en la base de datos
            const isMatch = await bcrypt.compare(password, user.password);
            
            if (!isMatch) {
                return res.status(401).json({ error: 'Credenciales incorrectas.' });
            }
            
            const token = jwt.sign({ id: user.id, usuario: user.usuario }, JWT_SECRET, { expiresIn: '8h' });
            
            // Retornamos el usuario sin el hash de contraseña
            const safeUser = { name: user.name, email: user.email, usuario: user.usuario };
            res.json({ message: 'Acceso concedido', token, user: safeUser });
            
        } catch (error) {
            res.status(500).json({ error: 'Error verificando seguridad' });
        }
    });
});

// 3. Actualizar Perfil
app.put('/api/user/profile', (req, res) => {
    const { usuario, newName } = req.body;
    db.run(`UPDATE users SET name = ? WHERE usuario = ?`, [newName, usuario], function(err) {
        if (err) return res.status(500).json({ error: 'Error al actualizar perfil' });
        res.json({ message: 'Perfil actualizado', user: { name: newName, usuario } });
    });
});

// 4. Cambiar Contraseña Segura (Hashing)
app.put('/api/user/password', (req, res) => {
    const { usuario, currentPassword, newPassword } = req.body;
    
    db.get(`SELECT password FROM users WHERE usuario = ?`, [usuario], async (err, user) => {
        if (err || !user) return res.status(404).json({ error: 'Usuario no encontrado' });
        
        try {
            // Verificar que la contraseña actual proporcionada es correcta
            const isMatch = await bcrypt.compare(currentPassword, user.password);
            if (!isMatch) return res.status(401).json({ error: 'Contraseña actual incorrecta' });
            
            // Encriptar la nueva contraseña
            const hashedNewPassword = await bcrypt.hash(newPassword, 10);
            
            db.run(`UPDATE users SET password = ? WHERE usuario = ?`, [hashedNewPassword, usuario], function(err2) {
                if (err2) return res.status(500).json({ error: 'Error al actualizar contraseña' });
                res.json({ message: 'Contraseña actualizada' });
            });
            
        } catch (error) {
            res.status(500).json({ error: 'Error de encriptación al actualizar' });
        }
    });
});

// ==========================================
// CAPA LÓGICA: RUTAS DE VIDEOTECA
// ==========================================
app.get('/api/videos', (req, res) => {
    db.all(`SELECT * FROM videos ORDER BY id DESC`, [], (err, rows) => {
        if (err) return res.status(500).json({ error: 'Error consultando videos' });
        
        const formattedVideos = rows.map(r => ({
            id: 'local_' + r.id,
            title: r.title,
            desc: r.desc,
            videoId: r.url.includes('v=') ? r.url.split('v=')[1].split('&')[0] : r.url.split('/').pop(),
            type: r.url.includes('tiktok') ? 'tiktok' : (r.url.includes('instagram') ? 'instagram' : 'youtube'),
            tag: 'Aporte de: ' + r.author,
            isLocal: false
        }));
        res.json(formattedVideos);
    });
});

app.post('/api/videos/upload', (req, res) => {
    const { title, desc, url, author } = req.body;
    const query = `INSERT INTO videos (title, desc, url, author) VALUES (?, ?, ?, ?)`;
    
    db.run(query, [title, desc, url, author], function(err) {
        if (err) return res.status(500).json({ error: 'Error al guardar video en DB' });
        res.status(200).json({ message: 'Video registrado exitosamente' });
    });
});

// ==========================================
// CONTROLADOR DE WEBSOCKETS (TIEMPO REAL)
// ==========================================
io.on('connection', (socket) => {
    socket.on('join_chat', (user) => {
        onlineUsers[socket.id] = user;
        io.emit('update_online_users', Object.values(onlineUsers));
        socket.emit('load_chat_history', chatMessages);
    });

    socket.on('send_message', (msg) => {
        chatMessages.push(msg);
        io.emit('receive_message', msg);
    });

    socket.on('disconnect', () => {
        delete onlineUsers[socket.id];
        io.emit('update_online_users', Object.values(onlineUsers));
    });
});

// Inicializar Servidor
const PORT = process.env.PORT || 3000;
server.listen(PORT, () => {
    console.log(`✅ Servidor ITSC activo en puerto ${PORT}`);
    console.log('🔒 Sistema de seguridad Hashing Activado');
});