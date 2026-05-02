// server.js
require('dotenv').config();
const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const cors = require('cors');
const nodemailer = require('nodemailer');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'dev_secret_key_change_in_production';

// ✅ CORS с явными настройками для Render
app.use(cors({
  origin: process.env.FRONTEND_URL || '*',
  credentials: true
}));
app.use(express.json());

// ✅ Явный путь для статики (работает и на localhost, и на Render)
app.use(express.static(path.join(__dirname)));

// 📧 NODemailer — с улучшенной диагностикой
let transporter = null;
if (process.env.SMTP_HOST && process.env.SMTP_USER && process.env.SMTP_PASS) {
  console.log('📧 Настройка SMTP...');
  console.log('   Host:', process.env.SMTP_HOST);
  console.log('   Port:', process.env.SMTP_PORT);
  console.log('   User:', process.env.SMTP_USER);
  console.log('   Secure:', process.env.SMTP_SECURE);
  
  transporter = nodemailer.createTransport({
    host: process.env.SMTP_HOST,
    port: parseInt(process.env.SMTP_PORT) || 465,
    secure: process.env.SMTP_SECURE === 'true', // true для 465, false для 587
    auth: {
      user: process.env.SMTP_USER,
      pass: process.env.SMTP_PASS
    },
    family: 4,              // Принудительно IPv4
    connectionTimeout: 15000,  // Увеличено до 15 сек
    socketTimeout: 15000,
    logger: true,  // Включить логирование
    debug: true    // Включить отладку
  });

  transporter.verify((error, success) => {
    if (error) {
      console.error('❌ SMTP ошибка:', error.message);
      console.error('   Код ошибки:', error.code);
      console.error('   Полный текст:', error);
    } else {
      console.log('✅ SMTP готов к отправке писем');
    }
  });
} else {
  console.warn('⚠️ SMTP не настроен');
}

async function sendVerificationEmail(email, code) {
  if (!transporter) {
    throw new Error('SMTP не настроен');
  }
  
  const mailOptions = {
    from: `"Готов к РФ" <${process.env.SMTP_FROM || process.env.SMTP_USER}>`,
    to: email,
    subject: '🔐 Ваш код подтверждения — Готов к РФ',
    text: `Ваш код подтверждения: ${code}\n\nКод действителен 10 минут.`,
    html: `
      <div style="font-family:Arial;max-width:500px;margin:0 auto;padding:20px;border:1px solid #e0e0e0;border-radius:8px">
        <h2 style="color:#2563eb">🇷 Готов к РФ</h2>
        <p>Ваш код подтверждения:</p>
        <div style="background:#f3f4f6;padding:15px;border-radius:6px;text-align:center;font-size:24px;font-weight:bold;letter-spacing:3px;margin:20px 0">${code}</div>
        <p style="color:#6b7280;font-size:14px">Код действителен <strong>10 минут</strong>.</p>
      </div>
    `
  };
  return await transporter.sendMail(mailOptions);
}

// ✅ SQLite — используем абсолютный путь для надёжности на Render
const dbPath = process.env.DATABASE_PATH || path.join(__dirname, 'app.db');
const db = new sqlite3.Database(dbPath, (err) => {
  if (err) console.error('❌ Ошибка подключения к БД:', err);
  else console.log(`✅ SQLite подключена: ${dbPath}`);
});

// Инициализация таблиц
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

// Middleware авторизации
const authenticate = (req, res, next) => {
  const authHeader = req.headers.authorization;
  if (!authHeader) return res.status(401).json({ error: 'Требуется авторизация' });
  const token = authHeader.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'Токен не найден' });
  
  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) {
      if (err.name === 'TokenExpiredError') {
        return res.status(401).json({ error: 'Токен истёк' });
      }
      return res.status(403).json({ error: 'Недействительный токен' });
    }
    req.user = user;
    next();
  });
};

// 🔹 Отправка кода
app.post('/api/auth/send-code', async (req, res) => {
  const { email } = req.body;
  
  if (!email || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
    return res.status(400).json({ error: 'Введите корректный email' });
  }

  if (!transporter) {
    return res.status(503).json({ 
      error: 'Сервис отправки писем не настроен',
      message: 'Администратор: добавьте SMTP_* переменные в Render'
    });
  }

  const code = Math.floor(100000 + Math.random() * 900000).toString();
  const expiresAt = Date.now() + 600000; // 10 минут

  try {
    await new Promise((resolve, reject) => {
      db.run('INSERT OR REPLACE INTO verification_codes VALUES (?, ?, ?)',
        [email, code, expiresAt], function(err) {
          if (err) reject(err);
          else resolve(this);
        });
    });

    await sendVerificationEmail(email, code);
    console.log(`✉️ Код отправлен на ${email}`);
    res.json({ message: 'Код подтверждения отправлен на вашу электронную почту' });
    
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
  
  db.get('SELECT * FROM verification_codes WHERE email = ? AND code = ?', [email, code], (err, row) => {
    if (err) {
      console.error('DB error:', err);
      return res.status(500).json({ error: 'Ошибка сервера' });
    }
    if (!row) return res.status(400).json({ error: 'Неверный код' });
    if (row.expires_at < Date.now()) {
      db.run('DELETE FROM verification_codes WHERE email = ?', [email]);
      return res.status(400).json({ error: 'Код истёк. Запросите новый' });
    }
    db.run('DELETE FROM verification_codes WHERE email = ?', [email]);
    res.json({ valid: true });
  });
});

// 🔹 Регистрация
app.post('/api/auth/register', async (req, res) => {
  const { email, password, code } = req.body;
  if (!email || !password || !code) return res.status(400).json({ error: 'Заполните все поля' });
  if (password.length < 8) return res.status(400).json({ error: 'Минимум 8 символов' });

  db.get('SELECT * FROM verification_codes WHERE email = ? AND code = ?', [email, code], async (err, row) => {
    if (err) {
      console.error('DB error:', err);
      return res.status(500).json({ error: 'Ошибка сервера' });
    }
    if (!row || row.expires_at < Date.now()) {
      if (row && row.expires_at < Date.now()) {
        db.run('DELETE FROM verification_codes WHERE email = ?', [email]);
      }
      return res.status(400).json({ error: 'Неверный или истёкший код' });
    }

    try {
      const hashed = await bcrypt.hash(password, 10);
      db.run('INSERT INTO users (email, password) VALUES (?, ?)', [email, hashed], function(err) {
        if (err) {
          if (err.message.includes('UNIQUE') || err.message.includes('duplicate')) {
            return res.status(409).json({ error: 'Email уже зарегистрирован' });
          }
          console.error('DB insert error:', err);
          return res.status(500).json({ error: 'Ошибка регистрации' });
        }
        db.run('DELETE FROM verification_codes WHERE email = ?', [email]);
        const token = jwt.sign({ id: this.lastID, email }, JWT_SECRET, { expiresIn: '7d' });
        res.status(201).json({ token, user: { id: this.lastID, email } });
      });
    } catch (e) {
      console.error('❌ Ошибка хеширования:', e);
      res.status(500).json({ error: 'Внутренняя ошибка' });
    }
  });
});

// 🔹 Вход
app.post('/api/auth/login', async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) return res.status(400).json({ error: 'Email и пароль обязательны' });

  db.get('SELECT * FROM users WHERE email = ?', [email], async (err, user) => {
    if (err) {
      console.error('DB error:', err);
      return res.status(500).json({ error: 'Ошибка сервера' });
    }
    if (!user) return res.status(401).json({ error: 'Неверный email или пароль' });
    
    const valid = await bcrypt.compare(password, user.password);
    if (!valid) return res.status(401).json({ error: 'Неверный email или пароль' });
    
    const token = jwt.sign({ id: user.id, email: user.email }, JWT_SECRET, { expiresIn: '7d' });
    res.json({ token, user: { id: user.id, email: user.email } });
  });
});

// 🔹 Прогресс обучения
app.get('/api/user/progress/:section', authenticate, (req, res) => {
  db.get('SELECT progress FROM user_progress WHERE user_id = ? AND section = ?', 
    [req.user.id, req.params.section], (err, row) => {
      if (err) {
        console.error('DB error:', err);
        return res.status(500).json({ error: 'Ошибка чтения' });
      }
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
      if (err) {
        console.error('DB error:', err);
        return res.status(500).json({ error: 'Ошибка сохранения' });
      }
      res.json({ success: true });
    });
});

// 🔹 Сертификаты
app.get('/api/user/certificates', authenticate, (req, res) => {
  db.all('SELECT id, type, score, date, number, created_at FROM certificates WHERE user_id = ? ORDER BY created_at DESC', 
    [req.user.id], (err, certs) => {
      if (err) {
        console.error('DB error:', err);
        return res.status(500).json({ error: 'Ошибка чтения' });
      }
      res.json(certs || []);
    });
});

app.post('/api/user/certificates', authenticate, (req, res) => {
  const { type, score, date, number } = req.body;
  if (!type || score === undefined || !date || !number) {
    return res.status(400).json({ error: 'Заполните все поля сертификата' });
  }
  
  db.run('INSERT INTO certificates (user_id, type, score, date, number) VALUES (?, ?, ?, ?, ?)',
    [req.user.id, type, score, date, number], function(err) {
      if (err) {
        console.error('DB error:', err);
        return res.status(500).json({ error: 'Ошибка сохранения' });
      }
      res.status(201).json({ id: this.lastID });
    });
});

// 🔹 Health check
app.get('/api/health', (req, res) => {
  res.json({ 
    status: 'ok', 
    time: new Date().toISOString(),
    env: process.env.NODE_ENV || 'development'
  });
});

// ✅ Обработка 404 для API
app.use('/api/*', (req, res) => {
  res.status(404).json({ error: 'API endpoint not found' });
});

// ✅ Запуск сервера
app.listen(PORT, '0.0.0.0', () => {
  console.log(`🚀 Сервер запущен: http://0.0.0.0:${PORT}`);
  console.log(`📧 SMTP: ${transporter ? '✅ настроен' : '⚠️ НЕ настроен'}`);
  console.log(`🗄️  SQLite: ${dbPath}`);
});

// ✅ Graceful shutdown для Render
process.on('SIGTERM', () => {
  console.log('🔄 Получен SIGTERM, закрываем БД...');
  db.close(() => {
    console.log('✅ БД закрыта');
    process.exit(0);
  });
});
