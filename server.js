const express = require('express');
const session = require('express-session');
const bcrypt = require('bcryptjs');
const Database = require('better-sqlite3');
const path = require('path');
const crypto = require('crypto');
const fs = require('fs');
const multer = require('multer');
require('dotenv').config();
const nodemailer = require('nodemailer');

const STATUS = ['Mới', 'Đã tiếp nhận', 'Đang xử lý', 'Hoàn thành'];
const CATEGORIES = ['Điện', 'Nước', 'Nội thất', 'Internet', 'Vệ sinh', 'Khác'];
const TEAMS = ['Tổ điện', 'Tổ nước', 'Tổ nội thất', 'Tổ IT'];
const BUILDINGS = ['A', 'B', 'C', 'D'];

// ---------- Upload ảnh / video ----------
const UPLOAD_DIR = process.env.UPLOAD_DIR || path.join(__dirname, 'uploads');
fs.mkdirSync(UPLOAD_DIR, { recursive: true });
const MEDIA_TYPES = {
  'image/jpeg': '.jpg', 'image/png': '.png', 'image/gif': '.gif', 'image/webp': '.webp',
  'video/mp4': '.mp4', 'video/webm': '.webm', 'video/quicktime': '.mov',
};
const MAX_FILES = 5, MAX_IMAGE = 8 * 1024 * 1024, MAX_VIDEO = 50 * 1024 * 1024;
const upload = multer({
  storage: multer.diskStorage({
    destination: UPLOAD_DIR,
    filename: (req, file, cb) => cb(null, crypto.randomUUID() + (MEDIA_TYPES[file.mimetype] || '')),
  }),
  limits: { fileSize: MAX_VIDEO, files: MAX_FILES },
  fileFilter: (req, file, cb) => MEDIA_TYPES[file.mimetype]
    ? cb(null, true)
    : cb(new Error('Chỉ chấp nhận ảnh (JPG, PNG, GIF, WebP) và video (MP4, WebM, MOV)')),
});
// Kiểm tra "chữ ký" đầu file để chắc chắn đúng là ảnh/video (không tin mimetype do client gửi)
function sniff(file) {
  const b = Buffer.alloc(12);
  const fd = fs.openSync(file.path, 'r');
  fs.readSync(fd, b, 0, 12, 0);
  fs.closeSync(fd);
  const hex = b.toString('hex'), a = (i, j) => b.toString('latin1', i, j);
  switch (file.mimetype) {
    case 'image/jpeg': return hex.startsWith('ffd8ff');
    case 'image/png': return hex.startsWith('89504e47');
    case 'image/gif': return a(0, 4) === 'GIF8';
    case 'image/webp': return a(0, 4) === 'RIFF' && a(8, 12) === 'WEBP';
    case 'video/mp4': return a(4, 8) === 'ftyp';
    case 'video/quicktime': return ['ftyp', 'moov', 'wide', 'mdat', 'free'].includes(a(4, 8));
    case 'video/webm': return hex.startsWith('1a45dfa3');
  }
  return false;
}
const removeFiles = (files = []) => files.forEach((f) => fs.unlink(f.path, () => {}));

// ---------- Database ----------
const db = new Database(path.join(__dirname, 'ktx.db'));
db.pragma('journal_mode = WAL');
db.pragma('foreign_keys = ON');
db.exec(`
CREATE TABLE IF NOT EXISTS rooms (
  id INTEGER PRIMARY KEY, building TEXT NOT NULL, number TEXT NOT NULL,
  UNIQUE (building, number));
CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY,
  mssv TEXT UNIQUE NOT NULL,
  name TEXT NOT NULL,
  email TEXT,
  password_hash TEXT NOT NULL,
  role TEXT NOT NULL DEFAULT 'student',
  room_id INTEGER REFERENCES rooms(id)
);
CREATE TABLE IF NOT EXISTS requests (
  id INTEGER PRIMARY KEY, user_id INTEGER NOT NULL REFERENCES users(id),
  room_id INTEGER NOT NULL REFERENCES rooms(id),
  category TEXT NOT NULL, priority TEXT NOT NULL DEFAULT 'thuong',
  description TEXT NOT NULL, status INTEGER NOT NULL DEFAULT 0,
  assignee TEXT, created_at TEXT NOT NULL DEFAULT (datetime('now')),
  updated_at TEXT NOT NULL DEFAULT (datetime('now')));
CREATE TABLE IF NOT EXISTS request_media (
  id INTEGER PRIMARY KEY, request_id INTEGER NOT NULL REFERENCES requests(id),
  filename TEXT NOT NULL, original_name TEXT, mime TEXT NOT NULL, size INTEGER NOT NULL,
  created_at TEXT NOT NULL DEFAULT (datetime('now')));
CREATE TABLE IF NOT EXISTS request_history (
  id INTEGER PRIMARY KEY, request_id INTEGER NOT NULL REFERENCES requests(id),
  status INTEGER NOT NULL, assignee TEXT, changed_by TEXT NOT NULL,
  changed_at TEXT NOT NULL DEFAULT (datetime('now')));
  CREATE TABLE IF NOT EXISTS password_resets (
  id INTEGER PRIMARY KEY,
  user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  token_hash TEXT NOT NULL UNIQUE,
  expires_at INTEGER NOT NULL,
  used INTEGER NOT NULL DEFAULT 0,
  created_at INTEGER NOT NULL);
`);
const userColumns = db.prepare('PRAGMA table_info(users)').all();

if (!userColumns.some(col => col.name === 'email')) {
  db.exec('ALTER TABLE users ADD COLUMN email TEXT');
}
// Cột trường học (tài khoản cũ chưa có thì để NULL, tài khoản mới bắt buộc nhập)
if (!userColumns.some(col => col.name === 'school')) {
  db.exec('ALTER TABLE users ADD COLUMN school TEXT');
}
// Email là duy nhất (không phân biệt hoa/thường). Bỏ qua nếu dữ liệu cũ đang bị trùng.
try {
  db.exec('CREATE UNIQUE INDEX IF NOT EXISTS idx_users_email ON users (lower(email)) WHERE email IS NOT NULL');
} catch (e) {
  console.warn('Không tạo được chỉ mục email duy nhất (dữ liệu cũ bị trùng?):', e.message);
}
db.exec('CREATE INDEX IF NOT EXISTS idx_password_resets_user ON password_resets (user_id)');

if (!db.prepare("SELECT 1 FROM users WHERE role='admin'").get()) {
  const pw = process.env.ADMIN_PASSWORD || 'admin123';
  db.prepare("INSERT INTO users (mssv,name,password_hash,role) VALUES ('admin','Ban quản lý KTX',?, 'admin')")
    .run(bcrypt.hashSync(pw, 10));
  console.log('Đã tạo tài khoản admin (mssv: admin). Hãy đổi mật khẩu bằng biến ADMIN_PASSWORD.');
}

// ---------- App ----------
const app = express();
const mailer = nodemailer.createTransport({
service: 'gmail',
auth: {
user: process.env.MAIL_USER,
pass: process.env.MAIL_APP_PASSWORD
}
});
app.use((req, res, next) => { res.setHeader('Referrer-Policy', 'no-referrer'); next(); }); // không lộ token reset qua Referer
app.use(express.json({ limit: '50kb' }));
app.use(session({
  secret: process.env.SESSION_SECRET || crypto.randomBytes(32).toString('hex'),
  resave: false, saveUninitialized: false,
  cookie: { httpOnly: true, sameSite: 'lax', maxAge: 1000 * 60 * 60 * 8 },
}));
app.use(express.static(path.join(__dirname, 'public')));

const need = (role) => (req, res, next) => {
  if (!req.session.user) return res.status(401).json({ error: 'Chưa đăng nhập' });
  if (role && req.session.user.role !== role) return res.status(403).json({ error: 'Không có quyền' });
  next();
};
const str = (v, max) => (typeof v === 'string' ? v.trim().slice(0, max) : '');
// Lấy chuỗi đã trim nhưng KHÔNG cắt bớt — để kiểm tra độ dài thật của dữ liệu người dùng nhập
const raw = (v) => (typeof v === 'string' ? v.trim() : '');

const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
const MSSV_RE = /^\w{4,20}$/;
const NAME_RE = /^[\p{L}][\p{L}\s.'-]*$/u;
const ROOM_RE = /^[A-Za-z0-9]{1,10}$/;
const RESET_TOKEN_RE = /^[a-f0-9]{64}$/;
const MIN_PASSWORD = 6;
const sha256 = (v) => crypto.createHash('sha256').update(v).digest('hex');

// Trả về chuỗi lỗi (tiếng Việt) hoặc null nếu hợp lệ
function checkPassword(pw) {
  if (typeof pw !== 'string' || pw.length < MIN_PASSWORD) return `Mật khẩu phải có ít nhất ${MIN_PASSWORD} ký tự.`;
  if (Buffer.byteLength(pw, 'utf8') > 72) return 'Mật khẩu quá dài (tối đa 72 ký tự).'; // giới hạn của bcrypt
  return null;
}

// Giới hạn số lần gọi theo khóa (IP/email) để tránh spam mail / dò mật khẩu
const hits = new Map();
function tooMany(key, limit, windowMs) {
  const now = Date.now();
  const arr = (hits.get(key) || []).filter((t) => now - t < windowMs);
  arr.push(now);
  hits.set(key, arr);
  return arr.length > limit;
}
setInterval(() => { const now = Date.now(); for (const [k, v] of hits) if (!v.some((t) => now - t < 3600e3)) hits.delete(k); }, 600e3).unref();

app.get('/api/meta', (_, res) => res.json({ STATUS, CATEGORIES, TEAMS, BUILDINGS }));

app.post('/api/register', (req, res) => {
  const b = req.body || {};
  const mssv = raw(b.mssv), name = raw(b.name).replace(/\s+/g, ' ');
  const email = raw(b.email).toLowerCase();
  const school = raw(b.school).replace(/\s+/g, ' ');
  const building = raw(b.building).toUpperCase(), number = raw(b.number).toUpperCase();
  const password = typeof b.password === 'string' ? b.password : '';
  const bad = (error, status = 400) => res.status(status).json({ error });

  if (!MSSV_RE.test(mssv))
    return bad('MSSV phải có từ 4 đến 20 ký tự, chỉ gồm chữ cái, số hoặc dấu gạch dưới.');
  if (name.length < 2 || name.length > 80 || !NAME_RE.test(name))
    return bad('Họ tên phải có từ 2 đến 80 ký tự và chỉ gồm chữ cái, khoảng trắng, dấu chấm, gạch nối.');
  if (email.length > 254 || !EMAIL_RE.test(email))
    return bad('Email không hợp lệ. Ví dụ: example@gmail.com');
  if (!school) return bad('Vui lòng nhập trường học.');
  if (school.length < 2 || school.length > 100)
    return bad('Tên trường phải có từ 2 đến 100 ký tự.');
  if (!BUILDINGS.includes(building)) return bad('Tòa nhà không hợp lệ.');
  if (!number) return bad('Vui lòng nhập số phòng.');
  if (!ROOM_RE.test(number)) return bad('Số phòng chỉ gồm chữ cái và số (tối đa 10 ký tự), ví dụ: 305.');
  const pwErr = checkPassword(password);
  if (pwErr) return bad(pwErr);

  if (db.prepare('SELECT 1 FROM users WHERE mssv = ?').get(mssv))
    return bad('MSSV này đã được đăng ký. Vui lòng sử dụng MSSV khác.', 409);
  if (db.prepare('SELECT 1 FROM users WHERE lower(email) = ?').get(email))
    return bad('Email này đã được sử dụng. Vui lòng sử dụng email khác.', 409);

  try {
    db.transaction(() => {
      db.prepare('INSERT OR IGNORE INTO rooms (building,number) VALUES (?,?)').run(building, number);
      const room = db.prepare('SELECT id FROM rooms WHERE building=? AND number=?').get(building, number);
      db.prepare('INSERT INTO users (mssv,name,email,school,password_hash,room_id) VALUES (?,?,?,?,?,?)')
        .run(mssv, name, email, school, bcrypt.hashSync(password, 10), room.id);
    })();
  } catch (e) {
    if (e && e.code === 'SQLITE_CONSTRAINT_UNIQUE')
      return bad('MSSV hoặc email này đã được đăng ký.', 409);
    console.error('Lỗi đăng ký:', e);
    return bad('Không đăng ký được. Vui lòng thử lại.', 500);
  }
  res.json({ ok: true });
});

app.post('/api/login', (req, res) => {
  const mssv = raw(req.body.mssv);
  const password = typeof req.body.password === 'string'
    ? req.body.password
    : '';
  if (!mssv) return res.status(400).json({ error: 'Vui lòng nhập MSSV.' });
  if (!password) return res.status(400).json({ error: 'Vui lòng nhập mật khẩu.' });
  if (mssv.length > 20 || password.length > 200)
    return res.status(401).json({ error: 'MSSV không tồn tại' });
  if (tooMany('login:' + req.ip, 100, 15 * 60 * 1000))
    return res.status(429).json({ error: 'Bạn thử đăng nhập quá nhiều lần. Vui lòng đợi vài phút rồi thử lại.' });

  // Kiểm tra MSSV
  const u = db.prepare(
    'SELECT * FROM users WHERE mssv = ?'
  ).get(mssv);

  if (!u) {
    return res.status(401).json({
      error: 'MSSV không tồn tại'
    });
  }

  // Kiểm tra mật khẩu
  if (!bcrypt.compareSync(password, u.password_hash)) {
    return res.status(401).json({
      error: 'Mật khẩu không chính xác'
    });
  }

  req.session.user = {
    id: u.id,
    mssv: u.mssv,
    name: u.name,
    role: u.role,
    room_id: u.room_id
  };

  res.json({ user: req.session.user });
});
app.post('/api/logout', (req, res) => req.session.destroy(() => res.json({ ok: true })));
app.get('/api/me', (req, res) => res.json({ user: req.session.user || null }));

const LIST_SQL = `
SELECT r.id, r.category, r.priority, r.description, r.status, r.assignee, r.created_at, r.updated_at,
       u.name, u.mssv, u.school, rm.building, rm.number
FROM requests r JOIN users u ON u.id=r.user_id JOIN rooms rm ON rm.id=r.room_id
WHERE (@uid IS NULL OR r.user_id=@uid) AND (@status IS NULL OR r.status=@status)
  AND (@cat IS NULL OR r.category=@cat)
ORDER BY r.id DESC`;

app.get('/api/requests', need(), (req, res) => {
  const isAdmin = req.session.user.role === 'admin';
  const status = req.query.status !== undefined && req.query.status !== '' ? Number(req.query.status) : null;
  if (status !== null && (!Number.isInteger(status) || status < 0 || status >= STATUS.length))
    return res.status(400).json({ error: 'Trạng thái không hợp lệ' });
  const cat = CATEGORIES.includes(req.query.category) ? req.query.category : null;
  const rows = db.prepare(LIST_SQL).all({ uid: isAdmin ? null : req.session.user.id, status, cat });
  if (rows.length) {
    const ids = rows.map((r) => r.id);
    const media = db.prepare(`SELECT id, request_id, mime FROM request_media
      WHERE request_id IN (${ids.map(() => '?').join(',')}) ORDER BY id`).all(...ids);
    const by = {};
    media.forEach((m) => (by[m.request_id] = by[m.request_id] || []).push({ id: m.id, mime: m.mime }));
    rows.forEach((r) => (r.media = by[r.id] || []));
  }
  res.json(rows);
});

app.post('/api/requests', need('student'), (req, res) => {
  upload.array('media', MAX_FILES)(req, res, (err) => {
    const files = req.files || [];
    const fail = (msg) => { removeFiles(files); return res.status(400).json({ error: msg }); };
    if (err) {
      if (err.code === 'LIMIT_FILE_SIZE') return fail('Tệp quá lớn (video tối đa 50MB, ảnh tối đa 8MB)');
      if (err.code === 'LIMIT_FILE_COUNT' || err.code === 'LIMIT_UNEXPECTED_FILE') return fail(`Tối đa ${MAX_FILES} tệp`);
      return fail(err.message);
    }
    const category = raw(req.body.category), description = raw(req.body.description);
    const priority = raw(req.body.priority) || 'thuong';
    if (!CATEGORIES.includes(category)) return fail('Vui lòng chọn loại sự cố hợp lệ');
    if (!['thuong', 'cao'].includes(priority)) return fail('Mức độ không hợp lệ');
    if (!description) return fail('Vui lòng nhập mô tả sự cố');
    if (description.length < 5) return fail('Mô tả quá ngắn (tối thiểu 5 ký tự)');
    if (description.length > 1000) return fail('Mô tả tối đa 1000 ký tự');
    for (const f of files) {
      if (!sniff(f)) return fail('Nội dung tệp không đúng định dạng ảnh/video: ' + f.originalname);
      if (f.mimetype.startsWith('image/') && f.size > MAX_IMAGE) return fail('Ảnh tối đa 8MB: ' + f.originalname);
    }
    const u = req.session.user;
    try {
      const id = db.transaction(() => {
        const rid = db.prepare('INSERT INTO requests (user_id,room_id,category,priority,description) VALUES (?,?,?,?,?)')
          .run(u.id, u.room_id, category, priority, description).lastInsertRowid;
        db.prepare('INSERT INTO request_history (request_id,status,changed_by) VALUES (?,0,?)').run(rid, u.mssv);
        const ins = db.prepare('INSERT INTO request_media (request_id,filename,original_name,mime,size) VALUES (?,?,?,?,?)');
        files.forEach((f) => ins.run(rid, f.filename, f.originalname.slice(0, 120), f.mimetype, f.size));
        return rid;
      })();
      res.json({ id });
    } catch (e) {
      removeFiles(files);
      res.status(500).json({ error: 'Không lưu được yêu cầu' });
    }
  });
});

// Chỉ chủ yêu cầu hoặc admin mới xem được ảnh/video (không phục vụ tĩnh công khai)
app.get('/api/media/:id', need(), (req, res) => {
  const m = db.prepare(`SELECT m.filename, m.mime, r.user_id FROM request_media m
    JOIN requests r ON r.id=m.request_id WHERE m.id=?`).get(Number(req.params.id));
  if (!m || (req.session.user.role !== 'admin' && m.user_id !== req.session.user.id))
    return res.status(404).json({ error: 'Không tìm thấy' });
  res.setHeader('Content-Type', m.mime);
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('Cache-Control', 'private, max-age=3600');
  res.sendFile(m.filename, { root: UPLOAD_DIR }); // hỗ trợ tua video (Range)
});

app.patch('/api/requests/:id', need('admin'), (req, res) => {
  const id = Number(req.params.id);
  const r = db.prepare('SELECT * FROM requests WHERE id=?').get(id);
  if (!r) return res.status(404).json({ error: 'Không tìm thấy yêu cầu' });
  let status = req.body.status !== undefined && req.body.status !== null && req.body.status !== '' ? Number(req.body.status) : r.status;
  let assignee = req.body.assignee !== undefined ? (typeof req.body.assignee === 'string' && req.body.assignee ? req.body.assignee : null) : r.assignee;
  if (!Number.isInteger(status) || status < 0 || status >= STATUS.length)
    return res.status(400).json({ error: 'Trạng thái không hợp lệ' });
  if (assignee && !TEAMS.includes(assignee)) return res.status(400).json({ error: 'Tổ xử lý không hợp lệ' });
  if (assignee && r.assignee !== assignee && status === 0) status = 1; // được phân công => đã tiếp nhận
  db.transaction(() => {
    db.prepare("UPDATE requests SET status=?, assignee=?, updated_at=datetime('now') WHERE id=?").run(status, assignee, id);
    db.prepare('INSERT INTO request_history (request_id,status,assignee,changed_by) VALUES (?,?,?,?)')
      .run(id, status, assignee, req.session.user.mssv);
  })();
  res.json({ ok: true });
});

app.get('/api/requests/:id/history', need(), (req, res) => {
  const r = db.prepare('SELECT user_id FROM requests WHERE id=?').get(Number(req.params.id));
  if (!r || (req.session.user.role !== 'admin' && r.user_id !== req.session.user.id))
    return res.status(404).json({ error: 'Không tìm thấy' });
  res.json(db.prepare('SELECT status,assignee,changed_by,changed_at FROM request_history WHERE request_id=? ORDER BY id')
    .all(Number(req.params.id)));
});

app.get('/api/stats', need('admin'), (_, res) => {
  res.json({
    byStatus: db.prepare('SELECT status, COUNT(*) n FROM requests GROUP BY status').all(),
    byBuilding: db.prepare('SELECT rm.building b, COUNT(*) n FROM requests r JOIN rooms rm ON rm.id=r.room_id GROUP BY rm.building').all(),
  });
});
const RESET_TTL_MS = 15 * 60 * 1000;
const FORGOT_MSG = 'Nếu email đã đăng ký, bạn sẽ nhận được liên kết đặt lại mật khẩu. Vui lòng kiểm tra cả mục thư rác (Spam) nếu không thấy.';

app.post('/api/forgot-password', (req, res) => {
  const email = raw(req.body && req.body.email).toLowerCase();
  if (!email) return res.status(400).json({ error: 'Vui lòng nhập email đã đăng ký.' });
  if (email.length > 254 || !EMAIL_RE.test(email))
    return res.status(400).json({ error: 'Vui lòng nhập email hợp lệ.' });
  if (tooMany('forgot-ip:' + req.ip, 10, 15 * 60 * 1000) || tooMany('forgot:' + email, 3, 15 * 60 * 1000))
    return res.status(429).json({ error: 'Bạn yêu cầu quá nhiều lần. Vui lòng đợi vài phút rồi thử lại.' });

  const user = db.prepare('SELECT id, email FROM users WHERE lower(email) = ?').get(email);
  // Luôn trả cùng một phản hồi để không lộ email nào đã đăng ký
  if (!user) return res.json({ message: FORGOT_MSG });

  const token = crypto.randomBytes(32).toString('hex');
  const now = Date.now();
  db.transaction(() => {
    db.prepare('UPDATE password_resets SET used = 1 WHERE user_id = ? AND used = 0').run(user.id);
    db.prepare('INSERT INTO password_resets (user_id, token_hash, expires_at, used, created_at) VALUES (?, ?, ?, 0, ?)')
      .run(user.id, sha256(token), now + RESET_TTL_MS, now);
    db.prepare('DELETE FROM password_resets WHERE expires_at < ?').run(now - 24 * 3600e3); // dọn token cũ
  })();

  const baseUrl = (process.env.APP_URL || 'http://localhost:3000').replace(/\/+$/, '');
  const resetUrl = `${baseUrl}/?resetToken=${encodeURIComponent(token)}`;

  // Gửi mail nền, lỗi chỉ ghi log (không trả 500 vì sẽ lộ email có tồn tại hay không)
  mailer.sendMail({
    from: `"KTX Incident" <${process.env.MAIL_USER}>`,
    to: user.email,
    subject: 'Đặt lại mật khẩu KTX Incident',
    text:
      `Bạn đã yêu cầu đặt lại mật khẩu.\n\n` +
      `Mở liên kết sau để đặt mật khẩu mới:\n${resetUrl}\n\n` +
      `Liên kết hết hạn sau 15 phút và chỉ dùng được một lần. Nếu không phải bạn yêu cầu, hãy bỏ qua email này.`,
    html: `
      <h2>Đặt lại mật khẩu</h2>
      <p>Bạn đã yêu cầu đặt lại mật khẩu tài khoản KTX Incident.</p>
      <p><a href="${resetUrl}" style="background:#2563eb;color:white;padding:12px 20px;text-decoration:none;border-radius:6px">Đặt lại mật khẩu</a></p>
      <p>Liên kết hết hạn sau 15 phút và chỉ sử dụng được một lần.</p>
      <p>Nếu không phải bạn yêu cầu, hãy bỏ qua email này.</p>`,
  }).catch((err) => console.error('Lỗi gửi email đặt lại mật khẩu:', err.message));

  res.json({ message: FORGOT_MSG });
});

// Bước 2: đặt mật khẩu mới bằng token trong email (endpoint này trước đây bị thiếu)
app.post('/api/reset-password', (req, res) => {
  const token = raw(req.body && req.body.token);
  const password = req.body && typeof req.body.password === 'string' ? req.body.password : '';
  const INVALID = 'Liên kết đặt lại mật khẩu không hợp lệ hoặc đã hết hạn. Vui lòng yêu cầu liên kết mới.';
  if (tooMany('reset-ip:' + req.ip, 20, 15 * 60 * 1000))
    return res.status(429).json({ error: 'Bạn thử quá nhiều lần. Vui lòng đợi vài phút rồi thử lại.' });
  if (!RESET_TOKEN_RE.test(token)) return res.status(400).json({ error: INVALID });
  const pwErr = checkPassword(password);
  if (pwErr) return res.status(400).json({ error: pwErr });

  const row = db.prepare('SELECT id, user_id, expires_at, used FROM password_resets WHERE token_hash = ?').get(sha256(token));
  if (!row || row.used || row.expires_at < Date.now()) return res.status(400).json({ error: INVALID });

  const ok = db.transaction(() => {
    // Đánh dấu đã dùng trước (điều kiện used=0) để một token không thể dùng hai lần dù gửi song song
    if (db.prepare('UPDATE password_resets SET used = 1 WHERE id = ? AND used = 0').run(row.id).changes !== 1) return false;
    db.prepare('UPDATE password_resets SET used = 1 WHERE user_id = ?').run(row.user_id);
    db.prepare('UPDATE users SET password_hash = ? WHERE id = ?').run(bcrypt.hashSync(password, 10), row.user_id);
    return true;
  })();
  if (!ok) return res.status(400).json({ error: INVALID });
  res.json({ message: 'Đặt lại mật khẩu thành công. Bạn có thể đăng nhập bằng mật khẩu mới.' });
});

// JSON sai định dạng / body quá lớn => trả JSON thay vì trang lỗi HTML
app.use((err, req, res, next) => {
  if (err && err.type === 'entity.parse.failed') return res.status(400).json({ error: 'Dữ liệu gửi lên không hợp lệ.' });
  if (err && err.type === 'entity.too.large') return res.status(413).json({ error: 'Dữ liệu gửi lên quá lớn.' });
  console.error(err);
  res.status(500).json({ error: 'Lỗi máy chủ' });
});

const PORT = process.env.PORT || 3000;
const server = app.listen(PORT, () => console.log(`Server chạy tại http://localhost:${PORT}`));
server.on('error', (e) => { console.error('LỖI SERVER:', e.code, e.message); process.exit(1); });
process.on('uncaughtException', (e) => { console.error('LỖI KHÔNG BẮT ĐƯỢC:', e); process.exit(1); });
process.on('unhandledRejection', (e) => { console.error('LỖI PROMISE:', e); });
process.on('exit', (c) => console.log('Server đã dừng, mã thoát:', c, '| Node', process.version));
