const express = require('express');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const path = require('path');

const app = express();
const PORT = 3000;

// VULNÉRABILITÉ CWE-321 & CWE-521 : Secret hardcodé et faible
const JWT_SECRET = 'd0i4xj7qwtv103a6';

// Base de données en mémoire (pour éviter les problèmes de compilation SQLite)
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

// Cookie parser simple
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

// Route Login
app.post('/login', (req, res) => {
  const { username, password } = req.body;

  const user = db.users.find(u => u.username === username && u.password === password);

  if (!user) {
    return res.status(401).json({ error: 'Identifiants invalides' });
  }

  // Génération JWT avec HS256 (vulnérable)
  const token = jwt.sign(
    {
      sub: user.id.toString(),
      name: user.username,
      admin: user.admin,
      iat: Math.floor(Date.now() / 1000),
      exp: Math.floor(Date.now() / 1000) + (2 * 60 * 60) // 2h
    },
    JWT_SECRET,
    { algorithm: 'HS256' }
  );

  // VULNÉRABILITÉ CWE-614 & CWE-1004 : Cookie sans flags de sécurité
  res.cookie('auth_token', token, {
    httpOnly: false,  // Vulnérable : accessible par JavaScript
    secure: false,    // Vulnérable : transmission en clair
    sameSite: 'lax'   // Vulnérable : pas strict
  });

  res.json({
    success: true,
    user: { id: user.id, username: user.username, admin: user.admin }
  });
});

// Middleware vérification JWT (vulnérable)
const verifyToken = (req, res, next) => {
  const token = req.cookies?.auth_token || req.headers.authorization?.split(' ')[1];

  if (!token) {
    return res.status(401).json({ error: 'Token manquant' });
  }

  try {
    // VULNÉRABILITÉ CWE-290 & CWE-502 : Confiance aveugle dans le payload
    const decoded = jwt.verify(token, JWT_SECRET);
    req.user = decoded;
    next();
  } catch (err) {
    return res.status(401).json({ error: 'Token invalide' });
  }
};

// Route produits (publique)
app.get('/api/products', (req, res) => {
  res.json(db.products);
});

// Route admin (protégée mais vulnérable)
app.get('/api/admin', verifyToken, (req, res) => {
  // VULNÉRABILITÉ CWE-285 & CWE-269 : Vérification basée sur le JWT uniquement
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
  res.clearCookie('auth_token');
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
  console.log(`[VULNERABLE] Collector.shop démarré sur http://localhost:${PORT}`);
  console.log('SECRET JWT: ' + JWT_SECRET + ' (VULNÉRABLE!)');
});
