// server.js
require('dotenv').config();
const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const cors = require('cors');
const path = require('path');
const { Resend } = require('resend'); // ✅ Импорт Resend

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'dev_secret_key_change_in_production';

// 📧 RESEND — безопасная инициализация с fallback-ключом (обход бага Railway)
const resendKey = process.env.RESEND_API_KEY || 're_apwAdcvd_N2Fam3nisk2uPDrFo2G6Kbmc';

if (!resendKey || !resendKey.startsWith('re_')) {
  console.error('❌ FATAL: RESEND_API_KEY некорректен');
  process.exit(1);
}

const resend = new Resend(resendKey);
console.log('✅ Resend инициализирован');

app.use(cors({
  origin: process.env.FRONTEND_URL || '*',
  credentials: true
}));
app.use(express.json());
app.use(express.static(path.join(__dirname)));

// ✅ SQLite
const dbPath = process.env.DATABASE_PATH || path.join(__dirname, 'app.db');
const db = new sqlite3.Database(dbPath, (err) => {
  if (err) console.error('❌ Ошибка БД:', err);
  else console.log(`✅ SQLite: ${dbPath}`);
});

db.serialize(() => {
  db.run(`CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  )`);
  db.run(`CREATE TABLE IF NOT EXISTS verification_codes (
    email TEXT PRIMARY KEY,
    code TEXT NOT NULL,
    expires_at INTEGER NOT NULL
  )`);
  db.run(`CREATE TABLE IF NOT EXISTS user_progress (
    user_id INTEGER,
    section TEXT NOT NULL,
    progress TEXT NOT NULL,
    PRIMARY KEY(user_id, section),
    FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
  )`);
  db.run(`CREATE TABLE IF NOT EXISTS certificates (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    type TEXT NOT NULL,
    score INTEGER NOT NULL,
    date TEXT NOT NULL,
    number TEXT NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
  )`);
});

const authenticate = (req, res, next) => {
  const authHeader = req.headers.authorization;
  if (!authHeader) return res.status(401).json({ error: 'Требуется авторизация' });
  const token = authHeader.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'Токен не найден' });
  
  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) return res.status(401).json({ error: 'Токен истёк или неверный' });
    req.user = user;
    next();
  });
};

// 🔹 Отправка кода (РЕАЛЬНОЕ ПИСЬМО через Resend)
app.post('/api/auth/send-code', async (req, res) => {
  const { email } = req.body;
  
  console.log(`📩 Запрос кода для: ${email}`);
  
  if (!email || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
    return res.status(400).json({ error: 'Введите корректный email' });
  }

  const code = Math.floor(100000 + Math.random() * 900000).toString();
  const expiresAt = Date.now() + 600000; // 10 минут

  try {
    // 1. Сохраняем код в БД
    await new Promise((resolve, reject) => {
      db.run(
        'INSERT OR REPLACE INTO verification_codes (email, code, expires_at) VALUES (?, ?, ?)',
        [email, code, expiresAt],
        function(err) {
          if (err) reject(err);
          else resolve(this);
        }
      );
    });

    // 2. Отправляем письмо через Resend API
    const { data, error } = await resend.emails.send({
      from: 'Готов к РФ <onboarding@resend.dev>',
      to: email,
      subject: '🔐 Ваш код подтверждения — Готов к РФ',
      html: `
        <div style="font-family:Arial,sans-serif;max-width:500px;margin:0 auto;padding:20px;border:1px solid #e0e0e0;border-radius:8px;background:#fff">
          <h2 style="color:#2563eb;margin:0 0 20px 0">🇷 Готов к РФ</h2>
          <p style="margin:0 0 15px 0;font-size:16px">Ваш код подтверждения:</p>
          <div style="background:#f3f4f6;padding:15px;border-radius:6px;text-align:center;font-size:28px;font-weight:bold;letter-spacing:5px;margin:20px 0;color:#1f2937">${code}</div>
          <p style="color:#6b7280;font-size:14px;margin:20px 0 0 0">Код действителен <strong>10 минут</strong>.</p>
          <p style="color:#9ca3af;font-size:12px;margin:20px 0 0 0">Если вы не запрашивали код, просто проигнорируйте это письмо.</p>
        </div>
      `
    });
    
    if (error) {
      console.error('❌ Ошибка Resend:', error);
      throw new Error('Не удалось отправить письмо');
    }
    console.log(`✅ Письмо отправлено через Resend (ID: ${data?.id})`);

    console.log(`🔐 [DEV LOG] Код для ${email}: ${code}`);
    res.json({ message: 'Код отправлен на вашу почту' });
    
  } catch (err) {
    console.error('❌ Ошибка отправки кода:', err.message);
    db.run('DELETE FROM verification_codes WHERE email = ?', [email]);
    res.status(500).json({ 
      error: 'Не удалось отправить код',
      message: process.env.NODE_ENV === 'production' ? 'Попробуйте позже' : err.message
    });
  }
});

// 🔹 Проверка кода
app.post('/api/auth/verify-code', (req, res) => {
  const { email, code } = req.body;
  if (!email || !code) return res.status(400).json({ error: 'Email и код обязательны' });
  
  db.get(
    'SELECT * FROM verification_codes WHERE email = ? AND code = ?',
    [email, code],
    (err, row) => {
      if (err) return res.status(500).json({ error: 'Ошибка сервера' });
      if (!row) return res.status(400).json({ error: 'Неверный код' });
      if (row.expires_at < Date.now()) {
        db.run('DELETE FROM verification_codes WHERE email = ?', [email]);
        return res.status(400).json({ error: 'Код истёк' });
      }
      db.run('DELETE FROM verification_codes WHERE email = ?', [email]);
      res.json({ valid: true });
    }
  );
});

// 🔹 Регистрация
app.post('/api/auth/register', async (req, res) => {
  const { email, password, code } = req.body;
  
  console.log(`📝 Регистрация: ${email}`);
  
  if (!email || !password || !code) {
    return res.status(400).json({ error: 'Заполните все поля' });
  }
  if (password.length < 8) {
    return res.status(400).json({ error: 'Минимум 8 символов' });
  }

  db.get(
    'SELECT * FROM verification_codes WHERE email = ? AND code = ?',
    [email, code],
    async (err, row) => {
      if (err) return res.status(500).json({ error: 'Ошибка сервера' });
      if (!row) return res.status(400).json({ error: 'Неверный код' });
      if (row.expires_at < Date.now()) {
        db.run('DELETE FROM verification_codes WHERE email = ?', [email]);
        return res.status(400).json({ error: 'Код истёк' });
      }

      try {
        const hashed = await bcrypt.hash(password, 10);
        db.run(
          'INSERT INTO users (email, password) VALUES (?, ?)',
          [email, hashed],
          function(err) {
            if (err) {
              if (err.message.includes('UNIQUE')) {
                return res.status(409).json({ error: 'Email уже зарегистрирован' });
              }
              console.error('❌ Ошибка создания пользователя:', err);
              return res.status(500).json({ error: 'Ошибка регистрации' });
            }
            
            console.log(`✅ Пользователь создан: ${email} (ID: ${this.lastID})`);
            db.run('DELETE FROM verification_codes WHERE email = ?', [email]);
            
            const token = jwt.sign({ id: this.lastID, email }, JWT_SECRET, { expiresIn: '7d' });
            res.status(201).json({ 
              token, 
              user: { id: this.lastID, email },
              message: 'Регистрация успешна'
            });
          }
        );
      } catch (e) {
        console.error('❌ Ошибка хеширования:', e);
        res.status(500).json({ error: 'Внутренняя ошибка' });
      }
    }
  );
});

// 🔹 Вход
app.post('/api/auth/login', async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) return res.status(400).json({ error: 'Email и пароль обязательны' });

  db.get('SELECT * FROM users WHERE email = ?', [email], async (err, user) => {
    if (err) return res.status(500).json({ error: 'Ошибка сервера' });
    if (!user) return res.status(401).json({ error: 'Неверный email или пароль' });
    
    const valid = await bcrypt.compare(password, user.password);
    if (!valid) return res.status(401).json({ error: 'Неверный email или пароль' });
    
    const token = jwt.sign({ id: user.id, email: user.email }, JWT_SECRET, { expiresIn: '7d' });
    res.json({ token, user: { id: user.id, email: user.email } });
  });
});

// 🔹 Прогресс
app.get('/api/user/progress/:section', authenticate, (req, res) => {
  db.get('SELECT progress FROM user_progress WHERE user_id = ? AND section = ?', 
    [req.user.id, req.params.section], (err, row) => {
      if (err) return res.status(500).json({ error: 'Ошибка чтения' });
      try {
        res.json({ progress: row ? JSON.parse(row.progress) : [] });
      } catch (e) {
        res.json({ progress: [] });
      }
    });
});

app.put('/api/user/progress/:section', authenticate, (req, res) => {
  const { progress } = req.body;
  if (!Array.isArray(progress)) return res.status(400).json({ error: 'Прогресс должен быть массивом' });
  
  db.run('INSERT OR REPLACE INTO user_progress VALUES (?, ?, ?)',
    [req.user.id, req.params.section, JSON.stringify(progress)], (err) => {
      if (err) return res.status(500).json({ error: 'Ошибка сохранения' });
      res.json({ success: true });
    });
});

// 🔹 Сертификаты
app.get('/api/user/certificates', authenticate, (req, res) => {
  db.all('SELECT id, type, score, date, number, created_at FROM certificates WHERE user_id = ? ORDER BY created_at DESC', 
    [req.user.id], (err, certs) => {
      if (err) return res.status(500).json({ error: 'Ошибка чтения' });
      res.json(certs || []);
    });
});

app.post('/api/user/certificates', authenticate, (req, res) => {
  const { type, score, date, number } = req.body;
  if (!type || score === undefined || !date || !number) {
    return res.status(400).json({ error: 'Заполните все поля' });
  }
  
  db.run('INSERT INTO certificates (user_id, type, score, date, number) VALUES (?, ?, ?, ?, ?)',
    [req.user.id, type, score, date, number], function(err) {
      if (err) return res.status(500).json({ error: 'Ошибка сохранения' });
      res.status(201).json({ id: this.lastID });
    });
});

app.get('/api/health', (req, res) => {
  res.json({ status: 'ok', time: new Date().toISOString() });
});

app.use('/api/*', (req, res) => {
  res.status(404).json({ error: 'Not found' });
});

app.listen(PORT, '0.0.0.0', () => {
  console.log(`🚀 Сервер запущен: http://0.0.0.0:${PORT}`);
  console.log(`📧 Resend: ${resendKey ? '✅ Настроен' : '⚠️ Не задан'}`);
});

process.on('SIGTERM', () => {
  db.close(() => process.exit(0));
});
