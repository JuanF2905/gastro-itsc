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
// OBLIGAR A RENDER A RECONSTRUIR TABLAS SI SE BORRA POR INACTIVIDAD
db.serialize(() => {
    // 1. Tabla de Usuarios
    db.run(`CREATE TABLE IF NOT EXISTS usuarios (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        email TEXT UNIQUE NOT NULL,
        usuario TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL
    )`);

    // 2. NUEVA: Tabla de Configuración (Para los interruptores del Admin)
    db.run(`CREATE TABLE IF NOT EXISTS configuracion (
        id INTEGER PRIMARY KEY,
        foro BOOLEAN,
        videos BOOLEAN,
        cursos BOOLEAN,
        registro BOOLEAN
    )`, () => {
        // Si la tabla está vacía, encendemos todos los módulos por defecto (1 = true)
        db.get("SELECT * FROM configuracion WHERE id = 1", (err, row) => {
            if (!row) {
                db.run("INSERT INTO configuracion (id, foro, videos, cursos, registro) VALUES (1, 1, 1, 1, 1)");
            }
        });
    });
});

// ==========================================
// RUTAS DE CONFIGURACIÓN GLOBAL (NUBE)
// ==========================================
// A. Leer la configuración (Lo usan los estudiantes al abrir la app)
app.get('/api/settings', (req, res) => {
    db.get("SELECT * FROM configuracion WHERE id = 1", (err, row) => {
        if (err || !row) return res.json({ foro: 1, videos: 1, cursos: 1, registro: 1 });
        res.json(row);
    });
});

// B. Guardar la configuración (Lo usa el Admin al mover los interruptores)
app.put('/api/settings', verifyAdmin, (req, res) => {
    const { foro, videos, cursos, registro } = req.body;
    db.run("UPDATE configuracion SET foro = ?, videos = ?, cursos = ?, registro = ? WHERE id = 1", 
        [foro ? 1 : 0, videos ? 1 : 0, cursos ? 1 : 0, registro ? 1 : 0], 
        (err) => {
            if(err) return res.status(500).json({error: 'Error guardando configuraciones'});
            res.json({message: 'Módulos actualizados en toda la plataforma'});
        }
    );
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

// ==========================================
// RUTAS DE ADMINISTRACIÓN (PANEL DE CONTROL)
// ==========================================

// 1. Middleware de seguridad: Verifica que la petición venga del Admin
const verifyAdmin = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    // Validamos el token que definimos en admin.html
    if (authHeader === 'Bearer simulated_token_123') {
        next();
    } else {
        res.status(403).json({ error: 'Acceso denegado. Token de administrador inválido o ausente.' });
    }
};

// 2. Ruta para obtener todos los estudiantes (GET)
app.get('/api/admin/users', verifyAdmin, (req, res) => {
    // Busca en la tabla de usuarios (adaptado por si tu tabla se llama 'usuarios' o 'users')
    const query = "SELECT name, email, usuario FROM usuarios";
    db.all(query, [], (err, rows) => {
        if (err) {
            // Plan de contingencia si la tabla se llama 'users' en inglés
            db.all("SELECT name, email, usuario FROM users", [], (err2, rows2) => {
                if (err2) return res.status(500).json({ error: 'Error al leer la base de datos' });
                res.json(rows2);
            });
        } else {
            res.json(rows);
        }
    });
});

// 3. Ruta para eliminar un estudiante (DELETE)
app.delete('/api/admin/users/:usuario', verifyAdmin, (req, res) => {
    const username = req.params.usuario;
    const query = "DELETE FROM usuarios WHERE usuario = ?";
    
    db.run(query, [username], function(err) {
        if (err) {
            db.run("DELETE FROM users WHERE usuario = ?", [username], function(err2) {
                if (err2) return res.status(500).json({ error: 'Error al eliminar' });
                res.json({ message: 'Estudiante eliminado exitosamente' });
            });
        } else {
            res.json({ message: 'Estudiante eliminado exitosamente' });
        }
    });
});

// Inicializar Servidor
const PORT = process.env.PORT || 3000;
server.listen(PORT, () => {
    console.log(`✅ Servidor ITSC activo en puerto ${PORT}`);
    console.log('🔒 Sistema de seguridad Hashing Activado');
});