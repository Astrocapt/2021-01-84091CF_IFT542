-- IFT 542 Practical Assignment - Student Registration Web Application
-- Migration 001: base schema
-- Target engine: SQLite 3 (portable equivalent DDL for MySQL noted in README)

PRAGMA foreign_keys = ON;

-- ---------------------------------------------------------------------------
-- users: authentication principals. Passwords are NEVER stored in plaintext;
-- password_hash holds an Argon2id encoded hash string ($argon2id$v=19$...).
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS users (
    id                INTEGER PRIMARY KEY AUTOINCREMENT,
    email             TEXT    NOT NULL UNIQUE,
    matric_no         TEXT    UNIQUE,
    full_name         TEXT    NOT NULL,
    password_hash     TEXT    NOT NULL,
    role              TEXT    NOT NULL DEFAULT 'student'
                              CHECK (role IN ('student', 'admin')),
    mfa_secret        TEXT,             -- base32 TOTP secret, admin accounts only
    mfa_enabled       INTEGER NOT NULL DEFAULT 0,
    failed_attempts   INTEGER NOT NULL DEFAULT 0,
    locked_until      TEXT,             -- ISO-8601 UTC; NULL when not locked
    password_changed_at TEXT,
    created_at        TEXT    NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);

-- ---------------------------------------------------------------------------
-- profiles: student-editable data, separated from credential data so that a
-- profile-update flow never touches the users table's security columns.
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS profiles (
    user_id     INTEGER PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
    department  TEXT,
    level       TEXT,
    phone       TEXT,
    bio         TEXT,
    updated_at  TEXT
);

-- ---------------------------------------------------------------------------
-- courses / enrolments
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS courses (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    code        TEXT    NOT NULL UNIQUE,
    title       TEXT    NOT NULL,
    units       INTEGER NOT NULL DEFAULT 3,
    semester    TEXT    NOT NULL DEFAULT 'First',
    capacity    INTEGER NOT NULL DEFAULT 60
);

CREATE TABLE IF NOT EXISTS enrolments (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id     INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    course_id   INTEGER NOT NULL REFERENCES courses(id) ON DELETE CASCADE,
    created_at  TEXT    NOT NULL DEFAULT (datetime('now')),
    UNIQUE (user_id, course_id)
);

-- ---------------------------------------------------------------------------
-- documents: upload metadata only. The stored file itself is written outside
-- the served static path under a server-generated random name.
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS documents (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id        INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    original_name  TEXT    NOT NULL,
    stored_name    TEXT    NOT NULL UNIQUE,
    content_type   TEXT    NOT NULL,
    size_bytes     INTEGER NOT NULL,
    sha256         TEXT    NOT NULL,
    uploaded_at    TEXT    NOT NULL DEFAULT (datetime('now'))
);

-- ---------------------------------------------------------------------------
-- login_attempts: feeds rate limiting and the security audit trail.
-- Stores an identifier hash, not the submitted password, and never the value
-- of any credential field.
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS login_attempts (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    email         TEXT    NOT NULL,
    source_ip     TEXT    NOT NULL,
    successful    INTEGER NOT NULL DEFAULT 0,
    attempted_at  TEXT    NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_attempts_email_time
    ON login_attempts(email, attempted_at);
CREATE INDEX IF NOT EXISTS idx_attempts_ip_time
    ON login_attempts(source_ip, attempted_at);

-- ---------------------------------------------------------------------------
-- audit_log: non-repudiation control (STRIDE 'R'). Append-only in practice;
-- the application holds no DELETE or UPDATE statement against this table.
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS audit_log (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    event       TEXT    NOT NULL,
    actor       TEXT,             -- user id or 'anonymous'
    subject     TEXT,             -- object acted upon
    outcome     TEXT    NOT NULL, -- success | failure | denied
    source_ip   TEXT,
    detail      TEXT,             -- redacted, no secrets
    occurred_at TEXT    NOT NULL DEFAULT (datetime('now'))
);
