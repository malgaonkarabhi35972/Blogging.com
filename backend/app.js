// ======================
// Required modules & setup
// ======================
const express = require('express');
const cors = require('cors');
const mysql = require('mysql2/promise');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const morgan = require('morgan');
const { body, validationResult } = require('express-validator');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 5000;

// Middleware setup
app.use(helmet());
app.use(cors({
  origin: process.env.NODE_ENV === 'production'
    ? ['https://yourproductiondomain.com']
    : ['http://localhost:3000'],
  credentials: true
}));
app.use(morgan(process.env.NODE_ENV === 'production' ? 'combined' : 'dev'));
app.use(rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100,
  message: 'Too many requests from this IP, please try again later',
  standardHeaders: true,
  legacyHeaders: false,
}));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// ======================
// MySQL connection pool
// ======================
const pool = mysql.createPool({
  host: process.env.DB_HOST,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME,
  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0
});

// ======================
// JWT Middleware
// ======================
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) return res.status(401).json({ error: 'Authorization token required' });

  jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
    if (err) return res.status(403).json({ error: 'Invalid or expired token' });
    req.user = user;
    next();
  });
};

// ======================
// Authentication Routes
// ======================

// Signup
app.post('/api/auth/signup', [
  body('username').trim().notEmpty().isLength({ min: 3 }),
  body('email').trim().isEmail(),
  body('password').isLength({ min: 6 }),
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) return res.status(400).json({ errors: errors.array() });

  const { username, email, password } = req.body;

  try {
    const [existing] = await pool.query('SELECT * FROM users WHERE email = ? OR username = ?', [email, username]);
    if (existing.length > 0) return res.status(400).json({ error: 'Email or username already exists' });

    const hashedPassword = await bcrypt.hash(password, 10);
    const [result] = await pool.query('INSERT INTO users (username, email, password) VALUES (?, ?, ?)', [username, email, hashedPassword]);

    res.status(201).json({ message: 'User created', userId: result.insertId });
  } catch (err) {
    console.error('Signup error:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Login
app.post('/api/auth/login', [
  body('email').trim().isEmail(),
  body('password').notEmpty(),
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) return res.status(400).json({ errors: errors.array() });

  const { email, password } = req.body;

  try {
    const [users] = await pool.query('SELECT * FROM users WHERE email = ?', [email]);
    if (users.length === 0) return res.status(401).json({ error: 'Invalid email or password' });

    const user = users[0];
    const validPass = await bcrypt.compare(password, user.password);
    if (!validPass) return res.status(401).json({ error: 'Invalid email or password' });

    const token = jwt.sign({ userId: user.id }, process.env.JWT_SECRET, { expiresIn: '1h' });

    res.json({ token, username: user.username, userId: user.id, expiresIn: 3600 });
  } catch (err) {
    console.error('Login error:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// ======================
// Blog Posts Routes
// ======================

// Create a new post
app.post('/api/posts', authenticateToken, [
  body('title').trim().notEmpty().isLength({ max: 200 }),
  body('content').trim().notEmpty(),
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) return res.status(400).json({ errors: errors.array() });

  const { title, content, image_url } = req.body;

  try {
    const [result] = await pool.query(
      'INSERT INTO posts (title, content, author_id, image_url) VALUES (?, ?, ?, ?)',
      [title, content, req.user.userId, image_url || null]
    );
    res.status(201).json({
      id: result.insertId,
      title,
      content,
      image_url,
      author_id: req.user.userId,
      createdAt: new Date().toISOString()
    });
  } catch (err) {
    console.error('Create post error:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Get all posts
app.get('/api/posts', async (req, res) => {
  const page = parseInt(req.query.page) || 1;
  const limit = parseInt(req.query.limit) || 10;
  const offset = (page - 1) * limit;

  try {
    const [posts] = await pool.query(`
      SELECT posts.*, users.username 
      FROM posts 
      JOIN users ON posts.author_id = users.id
      ORDER BY posts.created_at DESC
      LIMIT ? OFFSET ?
    `, [limit, offset]);

    const [countResult] = await pool.query('SELECT COUNT(*) as total FROM posts');
    const total = countResult[0].total;

    res.json({ posts, pagination: { page, limit, total, totalPages: Math.ceil(total / limit) } });
  } catch (err) {
    console.error('Get posts error:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Get single post
app.get('/api/posts/:id', async (req, res) => {
  const { id } = req.params;

  try {
    const [posts] = await pool.query(`
      SELECT posts.*, users.username 
      FROM posts 
      JOIN users ON posts.author_id = users.id
      WHERE posts.id = ?
    `, [id]);

    if (posts.length === 0) return res.status(404).json({ error: 'Post not found' });

    res.json(posts[0]);
  } catch (err) {
    console.error('Get post error:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Get posts by logged-in user
app.get('/api/posts/user/me', authenticateToken, async (req, res) => {
  try {
    const [posts] = await pool.query('SELECT * FROM posts WHERE author_id = ? ORDER BY created_at DESC', [req.user.userId]);
    res.json(posts);
  } catch (err) {
    console.error('Get user posts error:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Update a post
app.put('/api/posts/:id', authenticateToken, async (req, res) => {
  const { id } = req.params;
  const { title, content, image_url } = req.body;

  try {
    const [posts] = await pool.query('SELECT * FROM posts WHERE id = ? AND author_id = ?', [id, req.user.userId]);
    if (posts.length === 0) return res.status(404).json({ error: 'Post not found or not authorized' });

    await pool.query(
      'UPDATE posts SET title = ?, content = ?, image_url = ? WHERE id = ?',
      [title, content, image_url || null, id]
    );

    res.json({ message: 'Post updated successfully' });
  } catch (err) {
    console.error('Update post error:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Delete a post
app.delete('/api/posts/:id', authenticateToken, async (req, res) => {
  const { id } = req.params;

  try {
    const [posts] = await pool.query('SELECT * FROM posts WHERE id = ? AND author_id = ?', [id, req.user.userId]);
    if (posts.length === 0) return res.status(404).json({ error: 'Post not found or not authorized' });

    await pool.query('DELETE FROM posts WHERE id = ?', [id]);
    res.json({ message: 'Post deleted successfully' });
  } catch (err) {
    console.error('Delete post error:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// ======================
// Start Server
// ======================
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
