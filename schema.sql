-- ตารางทั้งหมดของเว็บ 3rd Miss Moohong (รันครั้งเดียวตอนติดตั้ง)
CREATE TABLE IF NOT EXISTS countries (
  slug       TEXT PRIMARY KEY,          -- ประเทศ 1 ประเทศมีได้ 1 แถว จึงจองซ้ำไม่ได้
  owner      TEXT NOT NULL,             -- รหัสเบราว์เซอร์ของผู้สมัคร
  country    TEXT NOT NULL,
  continent  TEXT NOT NULL,
  username   TEXT NOT NULL,
  full_name  TEXT NOT NULL,
  photo_id   TEXT,
  claimed_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL,          -- ครบ 5 นาที
  slip_at    INTEGER,                   -- เวลาที่แนบสลิป (ถ้ามี ประเทศจะไม่หลุด)
  ip         TEXT
);
CREATE INDEX IF NOT EXISTS idx_countries_owner ON countries(owner);
CREATE INDEX IF NOT EXISTS idx_countries_ip ON countries(ip);

CREATE TABLE IF NOT EXISTS slips (
  slug        TEXT PRIMARY KEY,
  image_id    TEXT NOT NULL,
  amount      REAL,
  uploaded_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS reviews (
  slug   TEXT PRIMARY KEY,
  status TEXT NOT NULL,                 -- approved | rejected
  note   TEXT,
  at     INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS kv (
  key   TEXT PRIMARY KEY,               -- settings | content
  value TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS images (
  id         TEXT PRIMARY KEY,
  kind       TEXT NOT NULL,             -- site | profile | slip
  mime       TEXT NOT NULL,
  size       INTEGER NOT NULL,
  created_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS image_chunks (
  image_id TEXT NOT NULL,
  idx      INTEGER NOT NULL,
  data     BLOB NOT NULL,
  PRIMARY KEY (image_id, idx)
);

CREATE TABLE IF NOT EXISTS coadmins (
  id         TEXT PRIMARY KEY,
  name       TEXT NOT NULL,
  salt       TEXT NOT NULL,
  hash       TEXT NOT NULL,
  created_at INTEGER NOT NULL,
  perms      TEXT NOT NULL DEFAULT ''   -- สิทธิ์ที่ติ๊กให้ คั่นด้วย , (list,media,review,release,settings,content) ว่าง = เข้าหน้าแอดมินไม่ได้
);
