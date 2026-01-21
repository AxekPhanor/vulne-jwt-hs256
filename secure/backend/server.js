const express = require('express');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');

const app = express();
const PORT = 3001;

// SÉCURISÉ : Génération ou chargement des clés RSA
const keysDir = path.join(__dirname, 'keys');
let privateKey, publicKey;

try {
    if (!fs.existsSync(keysDir)) {
        fs.mkdirSync(keysDir, { recursive: true });
    }

    const privateKeyPath = path.join(keysDir, 'private.pem');
    const publicKeyPath = path.join(keysDir, 'public.pem');

    if (!fs.existsSync(privateKeyPath) || !fs.existsSync(publicKeyPath)) {
        console.log('Génération des clés RSA...');
        const keyPair = crypto.generateKeyPairSync('rsa', {
            modulusLength: 2048,
            publicKeyEncoding: { type: 'spki', format: 'pem' },
            privateKeyEncoding: { type: 'pkcs8', format: 'pem' }
        });
        fs.writeFileSync(privateKeyPath, keyPair.privateKey);
        fs.writeFileSync(publicKeyPath, keyPair.publicKey);
        privateKey = keyPair.privateKey;
        publicKey = keyPair.publicKey;
        console.log('Clés RSA générées avec succès.');
    } else {
        privateKey = fs.readFileSync(privateKeyPath, 'utf8');
        publicKey = fs.readFileSync(publicKeyPath, 'utf8');
        console.log('Clés RSA chargées.');
    }
} catch (err) {
    console.error('Erreur lors du chargement des clés:', err);
    process.exit(1);
}

// Base de données en mémoire
const db = {
    users: [
        { id: 1, username: 'admin', password: 'admin123', admin: true },
        { id: 2, username: 'user', password: 'user123', admin: false },
        { id: 3, username: 'collector', password: 'collect2024', admin: false }
    ],
    products: [
        { id: 1, name: 'Nike Air Jordan 1 OG (1985)', description: 'Paire originale en excellent état', price: 2500, category: 'Baskets' },
        { id: 2, name: 'Figurine Hasbro Darth Vader (1977)', description: 'First edition, boîte scellée', price: 890, category: 'Figurines' },
        { id: 3, name: 'Poster Star Wars dédicacé', description: 'Signé par Mark Hamill', price: 1200, category: 'Posters' },
        { id: 4, name: 'Cassette V2000 Blade Runner', description: 'Version originale 1982', price: 150, category: 'Cassettes' },
        { id: 5, name: 'Game Boy Color Pokemon Edition', description: 'Edition limitée Pikachu', price: 320, category: 'Consoles' }
    ]
};

// Middleware
app.use(cors({ origin: true, credentials: true }));
app.use(express.json());
app.use(express.static(path.join(__dirname, '../frontend')));

// Cookie parser
app.use((req, res, next) => {
    const cookies = {};
    const cookieHeader = req.headers.cookie;
    if (cookieHeader) {
        cookieHeader.split(';').forEach(cookie => {
            const [name, value] = cookie.trim().split('=');
            cookies[name] = value;
        });
    }
    req.cookies = cookies;
    next();
});

// Route Login - SÉCURISÉ avec RS256
app.post('/login', (req, res) => {
    const { username, password } = req.body;

    const user = db.users.find(u => u.username === username && u.password === password);

    if (!user) {
        return res.status(401).json({ error: 'Identifiants invalides' });
    }

    // SÉCURISÉ : JWT signé avec RS256 (asymétrique)
    const token = jwt.sign(
        {
            sub: user.id.toString(),
            name: user.username,
            admin: user.admin,
            iat: Math.floor(Date.now() / 1000),
            exp: Math.floor(Date.now() / 1000) + (2 * 60 * 60) // 2h
        },
        privateKey,
        { algorithm: 'RS256' }
    );

    // SÉCURISÉ : Cookie avec tous les flags de protection
    res.cookie('auth_token', token, {
        httpOnly: true,     // Non accessible par JavaScript (protection XSS)
        secure: false,      // En prod: true (HTTPS only) - false pour localhost
        sameSite: 'strict', // Protection CSRF
        maxAge: 2 * 60 * 60 * 1000 // 2h en ms
    });

    res.json({
        success: true,
        user: { id: user.id, username: user.username, admin: user.admin }
    });
});

// Middleware vérification JWT - SÉCURISÉ avec RS256
const verifyToken = (req, res, next) => {
    const token = req.cookies?.auth_token || req.headers.authorization?.split(' ')[1];

    if (!token) {
        return res.status(401).json({ error: 'Token manquant' });
    }

    try {
        // SÉCURISÉ : Vérification avec clé publique, algorithme spécifié explicitement
        const decoded = jwt.verify(token, publicKey, { algorithms: ['RS256'] });
        req.user = decoded;
        next();
    } catch (err) {
        console.log('JWT verification failed:', err.message);
        return res.status(401).json({ error: 'Token invalide ou signature incorrecte' });
    }
};

// Route produits (publique)
app.get('/api/products', (req, res) => {
    res.json(db.products);
});

// Route admin (protégée et sécurisée)
app.get('/api/admin', verifyToken, (req, res) => {
    if (!req.user.admin) {
        return res.status(403).json({ error: 'Accès refusé - Admin requis' });
    }

    const users = db.users.map(u => ({ id: u.id, username: u.username, admin: u.admin }));
    const stats = {
        totalUsers: users.length,
        totalProducts: db.products.length,
        totalAdmins: users.filter(u => u.admin).length
    };

    res.json({ users, stats });
});

// Route info utilisateur
app.get('/api/me', verifyToken, (req, res) => {
    res.json(req.user);
});

// Logout
app.post('/logout', (req, res) => {
    res.clearCookie('auth_token', {
        httpOnly: true,
        secure: false,
        sameSite: 'strict'
    });
    res.json({ success: true });
});

// Servir les pages frontend
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, '../frontend/index.html'));
});

app.get('/catalogue', (req, res) => {
    res.sendFile(path.join(__dirname, '../frontend/catalogue.html'));
});

app.get('/admin', (req, res) => {
    res.sendFile(path.join(__dirname, '../frontend/admin.html'));
});

app.listen(PORT, () => {
    console.log(`[SECURE] Collector.shop démarré sur http://localhost:${PORT}`);
    console.log('Algorithme JWT: RS256 (asymétrique)');
    console.log('Cookies: HttpOnly + SameSite=Strict');
});
