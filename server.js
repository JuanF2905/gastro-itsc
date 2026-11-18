const express = require('express');
const cors = require('cors');
const http = require('http');
const { Server } = require('socket.io');
const { Pool } = require('pg');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');

const app = express();
const server = http.createServer(app);

// Habilitar comunicación con el frontend
app.use(cors());
app.use(express.json());

const io = new Server(server, { cors: { origin: '*' } });
const JWT_SECRET = 'itsc_gastro_super_secret_key_2026';

// ==========================================
// MIDDLEWARE DE SEGURIDAD (ADMIN)
// ==========================================
const verifyAdmin = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    if (authHeader === 'Bearer simulated_token_123') {
        next();
    } else {
        res.status(403).json({ error: 'Acceso denegado. Token de administrador inválido o ausente.' });
    }
};

// ==========================================
// CAPA DE DATOS (DAL): CONEXIÓN A SUPABASE
// ==========================================
const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: { rejectUnauthorized: false }
});

async function initDB() {
    try {
        // 1. Tabla de Usuarios
        await pool.query(`
            CREATE TABLE IF NOT EXISTS usuarios (
                id SERIAL PRIMARY KEY,
                name TEXT NOT NULL,
                email TEXT UNIQUE NOT NULL,
                usuario TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL
            );
        `);

        // 2. Tabla de Configuración (Interruptores del Admin)
        await pool.query(`
            CREATE TABLE IF NOT EXISTS configuracion (
                id INTEGER PRIMARY KEY,
                foro INTEGER DEFAULT 1,
                videos INTEGER DEFAULT 1,
                cursos INTEGER DEFAULT 1,
                registro INTEGER DEFAULT 1
            );
        `);

        await pool.query(`
            INSERT INTO configuracion (id, foro, videos, cursos, registro)
            VALUES (1, 1, 1, 1, 1)
            ON CONFLICT (id) DO NOTHING;
        `);

        // 3. Tabla de Videos (Prácticas de estudiantes)
        // 4. Tabla de Medios Oficiales (Shorts y Tutoriales del Admin)
        await pool.query(`
            CREATE TABLE IF NOT EXISTS medios (
                id SERIAL PRIMARY KEY,
                title TEXT NOT NULL,
                tipo TEXT NOT NULL,
                tag TEXT,
                url TEXT NOT NULL,
                img TEXT
            );
        `);

        console.log("✅ Conectado a Supabase y tablas listas.");
    } catch (err) {
        console.error("❌ Error inicializando Supabase:", err.message);
    }
}
initDB();

// Variables en memoria solo para el chat en vivo
const chatMessages = [
    { sender: "Sistema Culinario", usuario: "sistema", text: "¡El servidor persistente está en línea!", time: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }) }
];
const onlineUsers = {};

// ==========================================
// RUTAS DE CONFIGURACIÓN GLOBAL (NUBE)
// ==========================================
app.get('/api/settings', async (req, res) => {
    try {
        const result = await pool.query('SELECT * FROM configuracion WHERE id = 1');
        res.json(result.rows[0] || { foro: 1, videos: 1, cursos: 1, registro: 1 });
    } catch (err) {
        res.json({ foro: 1, videos: 1, cursos: 1, registro: 1 });
    }
});

app.put('/api/settings', verifyAdmin, async (req, res) => {
    const { foro, videos, cursos, registro } = req.body;
    try {
        await pool.query(
            'UPDATE configuracion SET foro = $1, videos = $2, cursos = $3, registro = $4 WHERE id = 1',
            [foro ? 1 : 0, videos ? 1 : 0, cursos ? 1 : 0, registro ? 1 : 0]
        );
        res.json({ message: 'Módulos actualizados en toda la plataforma' });
    } catch (err) {
        res.status(500).json({ error: 'Error guardando configuraciones' });
    }
});

// ==========================================
// CAPA LÓGICA (BLL): RUTAS DE AUTENTICACIÓN
// ==========================================

// 1. Registro Seguro (Hashing)
app.post('/api/auth/register', async (req, res) => {
    const { name, email, usuario, password } = req.body;
    try {
        const hashedPassword = await bcrypt.hash(password, 10);
        await pool.query(
            'INSERT INTO usuarios (name, email, usuario, password) VALUES ($1, $2, $3, $4)',
            [name, email, usuario, hashedPassword]
        );
        res.status(201).json({ message: 'Usuario creado', user: { name, email, usuario } });
    } catch (err) {
        if (err.code === '23505') {
            return res.status(400).json({ error: 'El correo o usuario ya existe en la base de datos.' });
        }
        res.status(500).json({ error: 'Error interno del servidor.' });
    }
});

// 2. Login Seguro (Validación Hash)
app.post('/api/auth/login', async (req, res) => {
    const { identifier, password } = req.body;
    try {
        const result = await pool.query(
            'SELECT * FROM usuarios WHERE usuario = $1 OR email = $1',
            [identifier]
        );
        if (result.rows.length === 0) {
            return res.status(401).json({ error: 'Credenciales incorrectas.' });
        }

        const user = result.rows[0];
        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) {
            return res.status(401).json({ error: 'Credenciales incorrectas.' });
        }

        const token = jwt.sign({ id: user.id, usuario: user.usuario }, JWT_SECRET, { expiresIn: '8h' });
        const safeUser = { name: user.name, email: user.email, usuario: user.usuario };
        res.json({ message: 'Acceso concedido', token, user: safeUser });
    } catch (error) {
        res.status(500).json({ error: 'Error consultando la base de datos.' });
    }
});

// 3. Actualizar Perfil
app.put('/api/user/profile', async (req, res) => {
    const { usuario, newName } = req.body;
    try {
        await pool.query('UPDATE usuarios SET name = $1 WHERE usuario = $2', [newName, usuario]);
        res.json({ message: 'Perfil actualizado', user: { name: newName, usuario } });
    } catch (err) {
        res.status(500).json({ error: 'Error al actualizar perfil' });
    }
});

// 4. Cambiar Contraseña Segura (Hashing)
app.put('/api/user/password', async (req, res) => {
    const { usuario, currentPassword, newPassword } = req.body;
    try {
        const result = await pool.query('SELECT password FROM usuarios WHERE usuario = $1', [usuario]);
        if (result.rows.length === 0) return res.status(404).json({ error: 'Usuario no encontrado' });

        const isMatch = await bcrypt.compare(currentPassword, result.rows[0].password);
        if (!isMatch) return res.status(401).json({ error: 'Contraseña actual incorrecta' });

        const hashedNewPassword = await bcrypt.hash(newPassword, 10);
        await pool.query('UPDATE usuarios SET password = $1 WHERE usuario = $2', [hashedNewPassword, usuario]);
        res.json({ message: 'Contraseña actualizada' });
    } catch (error) {
        res.status(500).json({ error: 'Error al actualizar contraseña' });
    }
});

// ==========================================
// CAPA LÓGICA: RUTAS DE VIDEOTECA
// ==========================================
app.get('/api/videos', async (req, res) => {
    try {
        const result = await pool.query('SELECT * FROM videos ORDER BY id DESC');
        const formattedVideos = result.rows.map(r => ({
            id: 'local_' + r.id,
            title: r.title,
            desc: r.description,
            videoId: r.url.includes('v=') ? r.url.split('v=')[1].split('&')[0] : r.url.split('/').pop(),
            type: r.url.includes('tiktok') ? 'tiktok' : (r.url.includes('instagram') ? 'instagram' : 'youtube'),
            tag: 'Aporte de: ' + r.author,
            isLocal: false
        }));
        res.json(formattedVideos);
    } catch (err) {
        res.status(500).json({ error: 'Error consultando videos' });
    }
});

app.post('/api/videos/upload', async (req, res) => {
    const { title, desc, url, author } = req.body;
    try {
        await pool.query(
            'INSERT INTO videos (title, description, url, author) VALUES ($1, $2, $3, $4)',
            [title, desc, url, author]
        );
        res.status(200).json({ message: 'Video registrado exitosamente' });
    } catch (err) {
        res.status(500).json({ error: 'Error al guardar video en DB' });
    }
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
app.get('/api/admin/users', verifyAdmin, async (req, res) => {
    try {
        const result = await pool.query('SELECT name, email, usuario FROM usuarios ORDER BY id DESC');
        res.json(result.rows);
    } catch (err) {
        res.status(500).json({ error: 'Error al leer la base de datos' });
    }
});

app.delete('/api/admin/users/:usuario', verifyAdmin, async (req, res) => {
    try {
        await pool.query('DELETE FROM usuarios WHERE usuario = $1', [req.params.usuario]);
        res.json({ message: 'Estudiante eliminado exitosamente' });
    } catch (err) {
        res.status(500).json({ error: 'Error al eliminar' });
    }
});

// Inicializar Servidor
const PORT = process.env.PORT || 3000;
server.listen(PORT, () => {
    console.log(`✅ Servidor ITSC activo en puerto ${PORT}`);
    console.log('🔒 Sistema de seguridad Hashing Activado');
});
// ==========================================
// RUTAS DE MEDIOS (SHORTS Y TUTORIALES)
// ==========================================
app.get('/api/medios', async (req, res) => {
    try {
        const result = await pool.query('SELECT * FROM medios ORDER BY id DESC');
        res.json(result.rows);
    } catch (err) {
        res.status(500).json({ error: 'Error al leer medios' });
    }
});

app.post('/api/admin/medios', verifyAdmin, async (req, res) => {
    const { title, tipo, tag, url, img } = req.body;
    try {
        await pool.query(
            'INSERT INTO medios (title, tipo, tag, url, img) VALUES ($1, $2, $3, $4, $5)',
            [title, tipo, tag || 'ITSC', url, img || '']
        );
        res.status(201).json({ message: 'Contenido publicado exitosamente' });
    } catch (err) {
        res.status(500).json({ error: 'Error al guardar en Supabase' });
    }
});

app.delete('/api/admin/medios/:id', verifyAdmin, async (req, res) => {
    try {
        await pool.query('DELETE FROM medios WHERE id = $1', [req.params.id]);
        res.json({ message: 'Contenido eliminado' });
    } catch (err) {
        res.status(500).json({ error: 'Error al eliminar contenido' });
    }
});