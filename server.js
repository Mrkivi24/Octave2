const express = require('express');
const session = require('express-session');
const socketio = require('socket.io');
const sqlite3 = require('sqlite3').verbose();
const bodyParser = require('body-parser');
const svgCaptcha = require('svg-captcha');
const path = require('path');
const bcrypt = require('bcrypt');
const saltRounds = 10;

const app = express();
const port = process.env.PORT || 3000;

// Database setup
const db = new sqlite3.Database('chat.db');
db.serialize(() => {
    db.run(`CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE,
        password TEXT,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )`);

    db.run(`CREATE TABLE IF NOT EXISTS messages (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        content TEXT,
        username TEXT,
        is_logged_in BOOLEAN,
        parent_id INTEGER,
        is_edited BOOLEAN DEFAULT 0,
        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
    )`);
});

// Middleware
app.use(bodyParser.json());
app.use(express.static(path.join(__dirname, 'public')));
app.use(session({
    secret: 'your-secret-key-here',
    resave: false,
    saveUninitialized: true,
    cookie: { secure: false }
}));

// Authentication endpoints
app.post('/login', (req, res) => {
    const { username, password } = req.body;
    
    db.get('SELECT * FROM users WHERE username = ?', [username], (err, user) => {
        if (err) return res.status(500).json({ success: false, message: 'Database error' });
        if (!user) return res.json({ success: false, message: 'User not found' });

        bcrypt.compare(password, user.password, (err, result) => {
            if (err || !result) {
                return res.json({ success: false, message: 'Invalid password' });
            }
            
            req.session.user = { id: user.id, username: user.username };
            res.json({ success: true, username: user.username });
        });
    });
});

app.post('/signup', (req, res) => {
    const { username, password } = req.body;
    
    if (username.length < 3 || username.length > 20) {
        return res.json({ success: false, message: 'Username must be 3-20 characters' });
    }
    
    if (password.length < 6) {
        return res.json({ success: false, message: 'Password must be at least 6 characters' });
    }

    db.get('SELECT id FROM users WHERE username = ?', [username], (err, user) => {
        if (err) return res.status(500).json({ success: false, message: 'Database error' });
        if (user) return res.json({ success: false, message: 'Username already exists' });

        bcrypt.hash(password, saltRounds, (err, hash) => {
            if (err) return res.status(500).json({ success: false, message: 'Error creating account' });

            db.run('INSERT INTO users (username, password) VALUES (?, ?)', 
                [username, hash], 
                function(err) {
                    if (err) return res.status(500).json({ success: false, message: 'Error creating account' });
                    
                    req.session.user = { id: this.lastID, username };
                    res.json({ success: true, username });
                }
            );
        });
    });
});

app.post('/set-guestname', (req, res) => {
    const { username } = req.body;
    if (!username || username.length < 3) {
        return res.json({ success: false, message: 'Username must be at least 3 characters' });
    }
    req.session.guest = { username };
    res.json({ success: true, username });
});

// Chat endpoints
app.get('/chat-history', (req, res) => {
    db.all(
        `SELECT m.id, m.content, m.username, m.is_logged_in, 
        m.is_edited, m.parent_id, m.timestamp, 
        u.username as display_name
        FROM messages m
        LEFT JOIN users u ON m.username = u.username
        ORDER BY m.timestamp ASC
        LIMIT 100`,
        (err, messages) => {
            if (err) return res.status(500).json({ error: 'Database error' });
            res.json(messages);
        }
    );
});

// CAPTCHA endpoints
app.get('/captcha', (req, res) => {
    const captcha = svgCaptcha.create({
        size: 5,
        noise: 2,
        color: true,
        background: '#111',
        ignoreChars: '0o1iIlL',
        charPreset: 'ABCDEFGHJKLMNPQRSTUVWXYZabcdefghjkmnpqrstuvwxyz23456789'
    });
    req.session.captcha = captcha.text;
    res.type('svg');
    res.send(captcha.data);
});

app.post('/verify-captcha', (req, res) => {
    const { input } = req.body;
    const isValid = input && input.toLowerCase() === req.session.captcha.toLowerCase();
    res.json({ success: isValid });
});

// HTTP Server
const server = app.listen(port, () => {
    console.log(`Server running on port ${port}`);
});

// Socket.IO setup
const io = socketio(server);
const onlineUsers = new Map();

io.on('connection', (socket) => {
    console.log('New client connected');

    socket.on('user-connected', (userData) => {
        onlineUsers.set(socket.id, userData);
        updateUserList();
        
        // Send chat history to new connection
        db.all(
            `SELECT m.id, m.content, m.username, m.is_logged_in, 
            m.is_edited, m.parent_id, m.timestamp, 
            u.username as display_name
            FROM messages m
            LEFT JOIN users u ON m.username = u.username
            ORDER BY m.timestamp ASC
            LIMIT 100`,
            (err, messages) => {
                if (!err) {
                    socket.emit('chat-history', messages);
                }
            }
        );
    });

    socket.on('send-message', (msg) => {
        db.run(
            'INSERT INTO messages (content, username, is_logged_in, parent_id) VALUES (?, ?, ?, ?)',
            [msg.content, msg.username, msg.isLoggedIn, msg.parentId || null],
            function(err) {
                if (err) return console.error(err);
                
                const newMsg = {
                    id: this.lastID,
                    ...msg,
                    edited: false
                };
                
                io.emit('message', newMsg);
            }
        );
    });

    socket.on('edit-message', ({ id, newContent }) => {
        db.run(
            'UPDATE messages SET content = ?, is_edited = 1 WHERE id = ?',
            [newContent, id],
            (err) => {
                if (err) return console.error(err);
                
                db.get('SELECT * FROM messages WHERE id = ?', [id], (err, row) => {
                    if (err) return console.error(err);
                    
                    io.emit('message-edited', {
                        id: row.id,
                        content: row.content,
                        edited: true
                    });
                });
            }
        );
    });

    socket.on('disconnect', () => {
        onlineUsers.delete(socket.id);
        updateUserList();
    });

    function updateUserList() {
        const users = Array.from(onlineUsers.values());
        io.emit('user-list', users);
    }
});

// Routes
app.get('/main', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'main.html'));
});

app.get('/chat', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'chat.html'));
});

app.get('/login', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'login.html'));
});

app.get('/signup', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'sign.html'));
});

app.get('/user', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'user.html'));
});

app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'captcha.html'));
});