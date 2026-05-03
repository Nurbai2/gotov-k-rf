// server.js
require('dotenv').config();
const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const cors = require('cors');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'dev_secret_key_change_in_production';

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

// 🔹 Отправка кода — ТЕПЕРЬ ВСЕГДА ВОЗВРАЩАЕТ КОД
app.post('/api/auth/send-code', async (req, res) => {
  const { email } = req.body;
  
  console.log(`📩 Запрос кода для: ${email}`);
  
  if (!email || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
    return res.status(400).json({ error: 'Введите корректный email' });
  }

  const code = Math.floor(100000 + Math.random() * 900000).toString();
  const expiresAt = Date.now() + 600000; // 10 минут

  console.log(`🔐 Генерация кода: ${code}`);
  console.log(`⏰ Истекает через: 10 минут (${new Date(expiresAt).toISOString()})`);

  try {
    await new Promise((resolve, reject) => {
      db.run(
        'INSERT OR REPLACE INTO verification_codes (email, code, expires_at) VALUES (?, ?, ?)',
        [email, code, expiresAt],
        function(err) {
          if (err) {
            console.error('❌ Ошибка записи в БД:', err);
            reject(err);
          } else {
            console.log(`✅ Код сохранён в БД для ${email}`);
            resolve(this);
          }
        }
      );
    });

    // 📢 ВАЖНО: Всегда возвращаем код в ответе (для демонстрации)
    console.log(`\n🔐 КОД ПОДТВЕРЖДЕНИЯ для ${email}: ${code}\n`);
    
    res.json({ 
      message: 'Код отправлен',
      code: code,  // ← Всегда возвращаем код!
      debug: {
        email: email,
        expiresAt: expiresAt,
        expiresIn: '10 minutes'
      }
    });
    
  } catch (err) {
    console.error('❌ Ошибка отправки кода:', err.message);
    res.status(500).json({ 
      error: 'Не удалось отправить код',
      message: err.message
    });
  }
});

// 🔹 Проверка кода — С УЛУЧШЕННОЙ ОТЛАДКОЙ
app.post('/api/auth/verify-code', (req, res) => {
  const { email, code } = req.body;
  
  console.log(`🔍 Проверка кода для ${email}: введён ${code}`);
  
  if (!email || !code) {
    return res.status(400).json({ error: 'Email и код обязательны' });
  }
  
  db.get(
    'SELECT * FROM verification_codes WHERE email = ? AND code = ?',
    [email, code],
    (err, row) => {
      if (err) {
        console.error('❌ Ошибка БД:', err);
        return res.status(500).json({ error: 'Ошибка сервера' });
      }
      
      if (!row) {
        console.log(`❌ Код не найден в БД для ${email}`);
        // Попробуем найти код для этого email (возможно, введён неверный)
        db.get(
          'SELECT * FROM verification_codes WHERE email = ?',
          [email],
          (err, existingRow) => {
            if (existingRow) {
              console.log(`💡 В БД есть код: ${existingRow.code}`);
              console.log(`⏰ Истекает: ${new Date(existingRow.expires_at).toISOString()}`);
              console.log(`⏰ Сейчас: ${new Date(Date.now()).toISOString()}`);
              console.log(`⏰ Осталось секунд: ${Math.floor((existingRow.expires_at - Date.now()) / 1000)}`);
            } else {
              console.log(`💡 Для ${email} вообще нет кода в БД`);
            }
          }
        );
        return res.status(400).json({ error: 'Неверный код' });
      }
      
      console.log(`✅ Код найден! Истекает: ${new Date(row.expires_at).toISOString()}`);
      console.log(`⏰ Текущее время: ${new Date(Date.now()).toISOString()}`);
      console.log(`⏰ Истекает через: ${Math.floor((row.expires_at - Date.now()) / 1000)} сек`);
      
      if (row.expires_at < Date.now()) {
        console.log('❌ Код истёк!');
        db.run('DELETE FROM verification_codes WHERE email = ?', [email]);
        return res.status(400).json({ error: 'Код истёк' });
      }
      
      console.log('✅ Код действителен!');
      db.run('DELETE FROM verification_codes WHERE email = ?', [email]);
      res.json({ valid: true });
    }
  );
});

// 🔹 Регистрация
app.post('/api/auth/register', async (req, res) => {
  const { email, password, code } = req.body;
  
  console.log(`📝 Регистрация: ${email}, код: ${code}, пароль: ${'*'.repeat(password.length)}`);
  
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
      if (err) {
        console.error('❌ Ошибка БД:', err);
        return res.status(500).json({ error: 'Ошибка сервера' });
      }
      
      if (!row) {
        console.log(`❌ Код не найден или неверный для ${email}`);
        return res.status(400).json({ error: 'Неверный или истёкший код' });
      }
      
      if (row.expires_at < Date.now()) {
        console.log('❌ Код истёк!');
        db.run('DELETE FROM verification_codes WHERE email = ?', [email]);
        return res.status(400).json({ error: 'Код истёк' });
      }

      console.log('✅ Код подтверждён, создаём пользователя...');
      
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
    if (err) {
      console.error('❌ Ошибка БД:', err);
      return res.status(500).json({ error: 'Ошибка сервера' });
    }
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
  console.log(`🗄️  SQLite: ${dbPath}`);
  console.log(` Режим отладки: ВКЛЮЧЁН (код всегда в ответе)`);
});

process.on('SIGTERM', () => {
  db.close(() => process.exit(0));
});
