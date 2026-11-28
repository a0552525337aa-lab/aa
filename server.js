'use strict';

const express = require('express');
const session = require('express-session');
const multer = require('multer');
const bcrypt = require('bcryptjs');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

const app = express();
const PORT = Number(process.env.PORT) || 3000;
const ROOT = __dirname;
const PUBLIC_DIR = path.join(ROOT, 'public');
const DATA_DIR = path.join(ROOT, 'data');
const UPLOAD_DIR = path.join(PUBLIC_DIR, 'uploads');
const STATE_FILE = path.join(DATA_DIR, 'state.json');
const ADMINS_FILE = path.join(DATA_DIR, 'admins.json');

fs.mkdirSync(DATA_DIR, { recursive: true });
fs.mkdirSync(UPLOAD_DIR, { recursive: true });

app.disable('x-powered-by');
app.use(express.json({ limit: '2mb' }));

// عيّن SESSION_SECRET إلى قيمة عشوائية طويلة عند النشر.
app.use(session({
  name: 'almoghani.sid',
  secret: process.env.SESSION_SECRET || 'غيّر-هذا-السر-قبل-النشر-إلى-قيمة-عشوائية-طويلة',
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,
    sameSite: 'strict',
    secure: process.env.NODE_ENV === 'production',
    maxAge: 8 * 60 * 60 * 1000
  }
}));

const defaultState = {
  settings: {
    title: 'almoghani',
    subtitle: 'مساحتك الخاصة للبث والمحتوى',
    websiteUrl: 'https://example.com',
    contactUrl: 'https://wa.me/',
    aiUrl: 'https://example.com',
    liveUrl: '',
    liveActive: false,
    backgroundUrl: '',
    fallbackType: 'message',
    fallbackMessage: 'أهلاً بك في almoghani — سيظهر المحتوى هنا قريباً.',
    fallbackUrl: '',
    logoUrl: '',
    logoPosition: 'top-right',
    primary: '#d71920',
    secondary: '#a70f18',
    background: '#080808',
    surface: '#151515',
    text: '#f4f1f1',
    muted: '#aaa3a3',
    fontFamily: 'Tahoma, Arial, sans-serif',
    headingSize: 34,
    bodySize: 16,
    buttonSize: 15
  },
  buttons: [
    { id: 'website', label: 'رابط موقعي', action: 'website', target: '', enabled: true },
    { id: 'refresh', label: 'تحديث البث', action: 'refresh', target: '', enabled: true },
    { id: 'contact', label: 'راسلني', action: 'contact', target: '', enabled: true },
    { id: 'ai', label: 'شات الذكاء الاصطناعي', action: 'ai', target: '', enabled: true },
    { id: 'live', label: 'عرض البث المباشر', action: 'live', target: '', enabled: true }
  ],
  banners: [],
  groups: [],
  movies: []
};

function readJson(file, fallback) {
  try {
    return JSON.parse(fs.readFileSync(file, 'utf8'));
  } catch {
    return fallback;
  }
}

let state = readJson(STATE_FILE, defaultState);

function saveState() {
  const temporaryFile = `${STATE_FILE}.tmp`;
  fs.writeFileSync(temporaryFile, JSON.stringify(state, null, 2), 'utf8');
  fs.renameSync(temporaryFile, STATE_FILE);
}

if (!fs.existsSync(STATE_FILE)) {
  saveState();
}

// ينشئ أول حساب إدارة. غيّر بياناته من متغيرات البيئة قبل التشغيل.
let admins = readJson(ADMINS_FILE, null);

if (!admins) {
  const username = process.env.ADMIN_USER || 'admin';
  const password = process.env.ADMIN_PASSWORD || 'ChangeMe_123!';

  admins = [{
    id: crypto.randomUUID(),
    username,
    passwordHash: bcrypt.hashSync(password, 12)
  }];

  fs.writeFileSync(ADMINS_FILE, JSON.stringify(admins, null, 2), 'utf8');
  console.log(`حساب الإدارة الأولي: ${username}`);
  console.log('غيّر كلمة المرور الافتراضية قبل إتاحة الموقع للعموم.');
}

function requireAdmin(req, res, next) {
  if (!req.session.adminId) {
    return res.status(401).json({ error: 'سجّل الدخول إلى لوحة التحكم أولاً.' });
  }
  next();
}

// تحفظ الملفات المرفوعة بأسماء عشوائية وتقبل الصور والفيديو فقط.
const storage = multer.diskStorage({
  destination: (_req, _file, callback) => callback(null, UPLOAD_DIR),
  filename: (_req, file, callback) => {
    const extension = path.extname(file.originalname).toLowerCase().slice(0, 12);
    callback(null, `${Date.now()}-${crypto.randomUUID()}${extension}`);
  }
});

const upload = multer({
  storage,
  limits: { fileSize: 100 * 1024 * 1024 },
  fileFilter: (_req, file, callback) => {
    if (!file.mimetype.startsWith('image/') && !file.mimetype.startsWith('video/')) {
      return callback(new Error('نوع الملف غير مدعوم. ارفع صورة أو فيديو.'));
    }
    callback(null, true);
  }
});

// الحالة العامة للواجهة. لا تتضمن بيانات المشرفين.
app.get('/api/state', (_req, res) => {
  res.json(state);
});

app.post('/api/login', async (req, res) => {
  const username = String(req.body.username || '');
  const password = String(req.body.password || '');
  const admin = admins.find(item => item.username === username);

  if (!admin || !(await bcrypt.compare(password, admin.passwordHash))) {
    return res.status(401).json({ error: 'اسم المستخدم أو كلمة المرور غير صحيحة.' });
  }

  req.session.adminId = admin.id;
  req.session.username = admin.username;
  res.json({ ok: true, username: admin.username });
});

app.post('/api/logout', requireAdmin, (req, res) => {
  req.session.destroy(() => res.json({ ok: true }));
});

app.get('/api/me', (req, res) => {
  if (!req.session.adminId) {
    return res.json({ loggedIn: false });
  }
  res.json({ loggedIn: true, username: req.session.username });
});

// تحفظ الصفحة الإدارية الحالة كاملة، ثم تعرضها واجهة المستخدم عند التحديث الدوري.
app.put('/api/state', requireAdmin, (req, res) => {
  const incoming = req.body;

  if (
    !incoming ||
    typeof incoming !== 'object' ||
    !incoming.settings ||
    !Array.isArray(incoming.buttons) ||
    !Array.isArray(incoming.banners) ||
    !Array.isArray(incoming.groups) ||
    !Array.isArray(incoming.movies)
  ) {
    return res.status(400).json({ error: 'بيانات الموقع غير مكتملة.' });
  }

  state = {
    settings: { ...defaultState.settings, ...incoming.settings },
    buttons: incoming.buttons.slice(0, 50),
    banners: incoming.banners.slice(0, 100),
    groups: incoming.groups.slice(0, 100),
    movies: incoming.movies.slice(0, 500)
  };

  saveState();
  res.json({ ok: true });
});

app.post('/api/upload', requireAdmin, upload.single('file'), (req, res) => {
  if (!req.file) {
    return res.status(400).json({ error: 'اختر ملفاً للتحميل.' });
  }

  res.json({ url: `/uploads/${req.file.filename}` });
});

// إدارة المشرفين؛ كلمات المرور لا تُرسل إلى المتصفح.
app.get('/api/admins', requireAdmin, (req, res) => {
  res.json(admins.map(({ id, username }) => ({
    id,
    username,
    current: id === req.session.adminId
  })));
});

app.post('/api/admins', requireAdmin, async (req, res) => {
  const username = String(req.body.username || '').trim();
  const password = String(req.body.password || '');

  if (!/^[a-zA-Z0-9_.-]{3,32}$/.test(username)) {
    return res.status(400).json({
      error: 'اسم المستخدم يجب أن يتكون من 3 إلى 32 حرفاً أو رقماً.'
    });
  }

  if (password.length < 10) {
    return res.status(400).json({
      error: 'كلمة المرور يجب ألا تقل عن 10 أحرف.'
    });
  }

  if (admins.some(item => item.username === username)) {
    return res.status(409).json({ error: 'اسم المستخدم موجود مسبقاً.' });
  }

  admins.push({
    id: crypto.randomUUID(),
    username,
    passwordHash: await bcrypt.hash(password, 12)
  });

  fs.writeFileSync(ADMINS_FILE, JSON.stringify(admins, null, 2), 'utf8');
  res.json({ ok: true });
});

app.delete('/api/admins/:id', requireAdmin, (req, res) => {
  if (req.params.id === req.session.adminId) {
    return res.status(400).json({ error: 'لا يمكنك حذف حسابك الحالي.' });
  }

  if (admins.length <= 1) {
    return res.status(400).json({ error: 'يجب إبقاء مشرف واحد على الأقل.' });
  }

  const updatedAdmins = admins.filter(item => item.id !== req.params.id);

  if (updatedAdmins.length === admins.length) {
    return res.status(404).json({ error: 'حساب المشرف غير موجود.' });
  }

  admins = updatedAdmins;
  fs.writeFileSync(ADMINS_FILE, JSON.stringify(admins, null, 2), 'utf8');
  res.json({ ok: true });
});

app.use('/uploads', express.static(UPLOAD_DIR));
app.use(express.static(PUBLIC_DIR));

app.use((error, _req, res, _next) => {
  console.error(error.message);
  res.status(400).json({ error: error.message || 'حدث خطأ في الطلب.' });
});

app.listen(PORT, () => {
  console.log(`almoghani يعمل على http://localhost:${PORT}`);
  console.log(`لوحة التحكم: http://localhost:${PORT}/admin`);
});
