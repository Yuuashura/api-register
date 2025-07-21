const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'your-secret-key-here';

// Middleware
app.use(cors());
app.use(express.json());
app.use(express.static('public'));


// Simple in-memory storage (dalam production gunakan database)
let users = [];

// Helper function untuk mencari user berdasarkan username atau email
const findUser = (identifier) => {
  return users.find(user => 
    user.username === identifier || user.email === identifier
  );
};


app.get('/', (req, res) => {
  res.sendFile(__dirname + '/public/register.html');
});


// POST /api/register
app.post('/api/register', async (req, res) => {
  try {
    const { username, email, password } = req.body;

    // Validasi input
    if (!username || !email || !password) {
      return res.status(400).json({
        success: false,
        message: 'Username, email, dan password harus diisi'
      });
    }

    // Cek apakah username sudah ada
    const existingUserByUsername = users.find(user => user.username === username);
    if (existingUserByUsername) {
      return res.status(400).json({
        success: false,
        message: 'Username sudah digunakan'
      });
    }

    // Cek apakah email sudah ada
    const existingUserByEmail = users.find(user => user.email === email);
    if (existingUserByEmail) {
      return res.status(400).json({
        success: false,
        message: 'Email sudah digunakan'
      });
    }

    // Hash password
    const hashedPassword = await bcrypt.hash(password, 10);

    // Buat user baru
    const newUser = {
      id: users.length + 1,
      username,
      email,
      password: hashedPassword,
      createdAt: new Date().toISOString()
    };

    users.push(newUser);

    // Return response tanpa password
    const { password: _, ...userResponse } = newUser;
    
    res.status(201).json({
      success: true,
      message: 'User berhasil didaftarkan',
      data: userResponse
    });

  } catch (error) {
    res.status(500).json({
      success: false,
      message: 'Terjadi kesalahan server',
      error: error.message
    });
  }
});

// POST /api/login
app.post('/api/login', async (req, res) => {
  try {
    const { identifier, password } = req.body; // identifier bisa username atau email

    // Validasi input
    if (!identifier || !password) {
      return res.status(400).json({
        success: false,
        message: 'Username/email dan password harus diisi'
      });
    }

    // Cari user berdasarkan username atau email
    const user = findUser(identifier);
    if (!user) {
      return res.status(401).json({
        success: false,
        message: 'Username/email atau password salah'
      });
    }

    // Verifikasi password
    const isPasswordValid = await bcrypt.compare(password, user.password);
    if (!isPasswordValid) {
      return res.status(401).json({
        success: false,
        message: 'Username/email atau password salah'
      });
    }

    // Generate JWT token
    const token = jwt.sign(
      { id: user.id, username: user.username, email: user.email },
      JWT_SECRET,
      { expiresIn: '24h' }
    );

    // Return response tanpa password
    const { password: _, ...userResponse } = user;

    res.status(200).json({
      success: true,
      message: 'Login berhasil',
      data: {
        user: userResponse,
        token
      }
    });

  } catch (error) {
    res.status(500).json({
      success: false,
      message: 'Terjadi kesalahan server',
      error: error.message
    });
  }
});

// GET /api/users - Menampilkan semua data user tanpa perlu token
app.get('/api/users', (req, res) => {
  try {
    // Return semua user tanpa password
    const usersWithoutPassword = users.map(({ password, ...user }) => user);
    
    res.status(200).json({
      success: true,
      message: 'Data users berhasil diambil',
      data: usersWithoutPassword
    });

  } catch (error) {
    res.status(500).json({
      success: false,
      message: 'Terjadi kesalahan server',
      error: error.message
    });
  }
});

// Health check endpoint
app.get('/api/health', (req, res) => {
  res.status(200).json({
    success: true,
    message: 'Server berjalan dengan baik',
    timestamp: new Date().toISOString()
  });
});

// Middleware autentikasi JWT
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).json({
      success: false,
      message: 'Token tidak ditemukan'
    });
  }

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) {
      return res.status(403).json({
        success: false,
        message: 'Token tidak valid'
      });
    }

    req.user = user; // simpan data user ke dalam req
    next();
  });
};


// DELETE /api/users/:id - Menghapus user berdasarkan ID
app.delete('/api/users/:id', (req, res) => {
  const userId = parseInt(req.params.id);

  const userIndex = users.findIndex(u => u.id === userId);
  if (userIndex === -1) {
    return res.status(404).json({
      success: false,
      message: 'User tidak ditemukan'
    });
  }

  users.splice(userIndex, 1);

  res.status(200).json({
    success: true,
    message: 'User berhasil dihapus'
  });
});


// Start server
app.listen(PORT, () => {
  console.log(`Server berjalan di port ${PORT}`);
  console.log(`http://localhost:${PORT}`);
});

module.exports = app;