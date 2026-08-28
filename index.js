const express = require('express');
const { createServer } = require('node:http');
const { Server } = require('socket.io');
const sqlite3 = require('sqlite3');
const { open } = require('sqlite');
const { randomBytes, scrypt, timingSafeEqual } = require('node:crypto');
const { promisify } = require('node:util');

const scryptAsync = promisify(scrypt);
const TOKEN_TTL_DAYS = 30;

function generateSessionId() {
  return randomBytes(3).toString('hex').toUpperCase();
}

function toSessionResponse(session, extra = {}) {
  return {
    sessionId: session.id,
    name: session.name,
    createdAt: session.created_at,
    endedAt: session.ended_at ?? null,
    ...extra,
  };
}

async function hashPassword(password) {
  const salt = randomBytes(16).toString('hex');
  const hash = (await scryptAsync(password, salt, 64)).toString('hex');
  return { salt, hash };
}

async function verifyPassword(password, salt, storedHash) {
  const hash = (await scryptAsync(password, salt, 64)).toString('hex');
  return timingSafeEqual(Buffer.from(hash, 'hex'), Buffer.from(storedHash, 'hex'));
}

async function createAuthToken(db, userId) {
  const token = randomBytes(32).toString('hex');
  await db.run(
    `INSERT INTO auth_tokens (token, user_id, expires_at)
     VALUES (?, ?, datetime('now', '+${TOKEN_TTL_DAYS} days'))`,
    token,
    userId
  );
  return token;
}

async function getUserFromToken(db, token) {
  if (!token) {
    return null;
  }

  return db.get(
    `SELECT u.id, u.username
     FROM auth_tokens t
     JOIN users u ON u.id = t.user_id
     WHERE t.token = ?
       AND (t.expires_at IS NULL OR t.expires_at > datetime('now'))`,
    token
  );
}

async function linkUserSession(db, userId, sessionId) {
  if (!userId || !sessionId) {
    return;
  }

  await db.run(
    'INSERT OR IGNORE INTO user_sessions (user_id, session_id) VALUES (?, ?)',
    userId,
    sessionId
  );
}

function getBearerToken(req) {
  const header = req.headers.authorization || '';
  if (!header.startsWith('Bearer ')) {
    return null;
  }

  return header.slice(7).trim();
}

async function main() {
  const db = await open({
    filename: 'chat.db',
    driver: sqlite3.Database,
  });

  await db.exec(`
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT NOT NULL UNIQUE,
      password_hash TEXT NOT NULL,
      password_salt TEXT NOT NULL,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    );
  `);

  await db.exec(`
    CREATE TABLE IF NOT EXISTS auth_tokens (
      token TEXT PRIMARY KEY,
      user_id INTEGER NOT NULL,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      expires_at DATETIME,
      FOREIGN KEY (user_id) REFERENCES users(id)
    );
  `);

  await db.exec(`
    CREATE TABLE IF NOT EXISTS user_sessions (
      user_id INTEGER NOT NULL,
      session_id TEXT NOT NULL,
      linked_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      PRIMARY KEY (user_id, session_id),
      FOREIGN KEY (user_id) REFERENCES users(id),
      FOREIGN KEY (session_id) REFERENCES sessions(id)
    );
  `);

  await db.exec(`
    CREATE TABLE IF NOT EXISTS sessions (
      id TEXT PRIMARY KEY,
      name TEXT NOT NULL,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      ended_at DATETIME
    );
  `);

  const sessionColumns = await db.all('PRAGMA table_info(sessions)');
  const hasEndedAt = sessionColumns.some((col) => col.name === 'ended_at');
  if (!hasEndedAt) {
    await db.exec('ALTER TABLE sessions ADD COLUMN ended_at DATETIME');
  }

  await db.exec(`
    CREATE TABLE IF NOT EXISTS messages (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      client_offset TEXT UNIQUE,
      content TEXT,
      session_id TEXT
    );
  `);

  const messageColumns = await db.all('PRAGMA table_info(messages)');
  const hasSessionId = messageColumns.some((col) => col.name === 'session_id');
  if (!hasSessionId) {
    await db.exec('ALTER TABLE messages ADD COLUMN session_id TEXT');
  }

  await db.exec(`
    CREATE TABLE IF NOT EXISTS comments (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      content TEXT,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      deleted_at DATETIME,
      FOREIGN KEY (user_id) REFERENCES users(id),
      FOREIGN KEY (session_id) REFERENCES sessions(id)
    );
  `);

  const commentColumns = await db.all('PRAGMA table_info(comments)');
  const hasCommentSessionId = commentColumns.some((col) => col.name === 'session_id');
  if (!hasCommentSessionId) {
    await db.exec('ALTER TABLE comments ADD COLUMN session_id TEXT');
  }

  const app = express();
  app.use(express.json());
  app.use((req, res, next) => {
    const origin = req.headers.origin;
    const allowedOrigins = ['http://localhost:4200', 'http://127.0.0.1:4200'];

    if (origin && allowedOrigins.includes(origin)) {
      res.header('Access-Control-Allow-Origin', origin);
    }

    res.header('Access-Control-Allow-Headers', 'Content-Type, Authorization');
    res.header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');

    if (req.method === 'OPTIONS') {
      res.sendStatus(204);
      return;
    }

    next();
  });

  app.post('/auth/register', async (req, res) => {
    const username = (req.body.username || '').trim();
    const password = req.body.password || '';

    if (username.length < 3) {
      res.status(400).json({ error: 'Username must be at least 3 characters.' });
      return;
    }

    if (password.length < 6) {
      res.status(400).json({ error: 'Password must be at least 6 characters.' });
      return;
    }

    const existing = await db.get('SELECT id FROM users WHERE username = ?', username);
    if (existing) {
      res.status(409).json({ error: 'Username is already taken.' });
      return;
    }

    const { salt, hash } = await hashPassword(password);
    const result = await db.run(
      'INSERT INTO users (username, password_hash, password_salt) VALUES (?, ?, ?)',
      username,
      hash,
      salt
    );

    const token = await createAuthToken(db, result.lastID);
    res.json({ token, username });
  });

  app.post('/auth/login', async (req, res) => {
    const username = (req.body.username || '').trim();
    const password = req.body.password || '';

    const user = await db.get(
      'SELECT id, username, password_hash, password_salt FROM users WHERE username = ?',
      username
    );

    if (!user) {
      res.status(401).json({ error: 'Invalid username or password.' });
      return;
    }

    const valid = await verifyPassword(password, user.password_salt, user.password_hash);
    if (!valid) {
      res.status(401).json({ error: 'Invalid username or password.' });
      return;
    }

    const token = await createAuthToken(db, user.id);
    res.json({ token, username: user.username });
  });

  app.post('/auth/login-without-account', async (req, res) => {
    try {
      const username = `guest-${randomBytes(4).toString('hex')}`;
      const randomPassword = randomBytes(16).toString('hex');
      const { salt, hash } = await hashPassword(randomPassword);

      const result = await db.run(
        'INSERT INTO users (username, password_hash, password_salt) VALUES (?, ?, ?)',
        username,
        hash,
        salt
      );

      const token = await createAuthToken(db, result.lastID);
      res.json({ token, username });
    } catch (error) {
      console.error('guest login failed:', error);
      res.status(500).json({ error: 'Guest login failed.' });
    }
  });

  app.get('/auth/me', async (req, res) => {
    const user = await getUserFromToken(db, getBearerToken(req));
    if (!user) {
      res.status(401).json({ error: 'Unauthorized' });
      return;
    }

    res.json({ username: user.username });
  });

  app.get('/auth/sessions', async (req, res) => {
    const user = await getUserFromToken(db, getBearerToken(req));
    if (!user) {
      res.status(401).json({ error: 'Unauthorized' });
      return;
    }

    const rows = await db.all(
      `SELECT s.id AS sessionId, s.name, s.created_at AS createdAt, s.ended_at AS endedAt
       FROM user_sessions us
       JOIN sessions s ON s.id = us.session_id
       WHERE us.user_id = ? AND s.ended_at IS NOT NULL
       ORDER BY s.created_at DESC`,
      user.id
    );

    res.json(rows);
  });

  app.post('/auth/logout', async (req, res) => {
    const token = getBearerToken(req);
    if (token) {
      await db.run('DELETE FROM auth_tokens WHERE token = ?', token);
    }

    res.json({ ok: true });
  });

  const server = createServer(app);
  const io = new Server(server, {
    connectionStateRecovery: {},
    cors: {
      origin: ['http://localhost:4200', 'http://127.0.0.1:4200'],
      methods: ['GET', 'POST'],
    },
  });

  io.use(async (socket, next) => {
    try {
      const user = await getUserFromToken(db, socket.handshake.auth?.token);
      if (user) {
        socket.userId = user.id;
        socket.username = user.username;
      }
      next();
    } catch (error) {
      next(error);
    }
  });

  io.on('connection', (socket) => {
    socket.on('create session', async (name, callback) => {
      try {
        const sessionName = (name || '').trim() || 'Untitled Session';
        const sessionId = generateSessionId();

        await db.run(
          'INSERT INTO sessions (id, name) VALUES (?, ?)',
          sessionId,
          sessionName
        );

        socket.sessionId = sessionId;
        socket.join(sessionId);
        await linkUserSession(db, socket.userId, sessionId);

        const row = await db.get(
          'SELECT id, name, created_at, ended_at FROM sessions WHERE id = ?',
          sessionId
        );

        callback(toSessionResponse(row));
      } catch (error) {
        console.error('create session failed:', error);
        callback({ error: 'Failed to create session' });
      }
    });

    socket.on('join session', async (sessionId, callback) => {
      const normalizedId = (sessionId || '').trim().toUpperCase();
      const session = await db.get(
        'SELECT id, name, created_at, ended_at FROM sessions WHERE id = ?',
        normalizedId
      );

      if (!session) {
        callback({ error: 'Session not found' });
        return;
      }

      if (session.ended_at) {
        callback({ error: 'Session has ended' });
        return;
      }

      socket.sessionId = session.id;
      socket.join(session.id);
      await linkUserSession(db, socket.userId, session.id);

      const rows = await db.all(
        'SELECT content FROM messages WHERE session_id = ? ORDER BY id',
        session.id
      );

      callback(toSessionResponse(session, {
        messages: rows.map((row) => row.content),
      }));
    });

    socket.on('watch session', async (sessionId, callback) => {
      const normalizedId = (sessionId || '').trim().toUpperCase();
      const session = await db.get(
        'SELECT id, name, created_at, ended_at FROM sessions WHERE id = ?',
        normalizedId
      );

      if (!session) {
        callback?.({ error: 'Session not found' });
        return;
      }

      if (session.ended_at) {
        callback?.({ error: 'Session has ended' });
        return;
      }

      socket.sessionId = session.id;
      socket.join(session.id);
      await linkUserSession(db, socket.userId, session.id);

      const rows = await db.all(
        'SELECT content FROM messages WHERE session_id = ? ORDER BY id',
        session.id
      );

      callback?.(toSessionResponse(session, {
        messages: rows.map((row) => row.content),
      }));
    });

    socket.on('view old sessions', async (sessionId, callback) => {
      const normalizedId = (sessionId || '').trim().toUpperCase();
      const session = await db.get(
        'SELECT id, name, created_at, ended_at FROM sessions WHERE id = ?',
        normalizedId
      );

      if (!session) {
        callback?.({ error: 'Session not found' });
        return;
      }

      if (!session.ended_at) {
        callback?.({ error: 'Session is still active' });
        return;
      }

      await linkUserSession(db, socket.userId, session.id);

      const rows = await db.all(
        'SELECT content FROM messages WHERE session_id = ? ORDER BY id',
        session.id
      );

      callback?.(toSessionResponse(session, {
        messages: rows.map((row) => row.content),
      }));
    });

    socket.on('end session', async (sessionId, callback) => {
      const normalizedId = (sessionId || '').trim().toUpperCase();
      const session = await db.get(
        'SELECT id, ended_at FROM sessions WHERE id = ?',
        normalizedId
      );

      if (!session) {
        callback?.({ error: 'Session not found' });
        return;
      }

      if (session.ended_at) {
        callback?.({ error: 'Session already ended' });
        return;
      }

      await db.run(
        'UPDATE sessions SET ended_at = CURRENT_TIMESTAMP WHERE id = ?',
        normalizedId
      );

      await linkUserSession(db, socket.userId, normalizedId);

      const row = await db.get(
        'SELECT id, name, created_at, ended_at FROM sessions WHERE id = ?',
        normalizedId
      );

      io.to(normalizedId).emit('session ended');
      callback?.(toSessionResponse(row));
    });

    socket.on('chat message', async (msg, clientOffset, callback) => {
      if (!socket.sessionId) {
        callback?.({ error: 'Not in a session' });
        return;
      }

      const session = await db.get(
        'SELECT ended_at FROM sessions WHERE id = ?',
        socket.sessionId
      );

      if (session?.ended_at) {
        callback?.({ error: 'Session has ended' });
        return;
      }

      let messageId;

      try {
        const result = await db.run(
          'INSERT INTO messages (content, client_offset, session_id) VALUES (?, ?, ?)',
          msg,
          clientOffset,
          socket.sessionId
        );
        messageId = result.lastID;
      } catch (e) {
        if (e.errno !== 19) {
          callback?.({ error: 'Failed to save message' });
          return;
        }

        const existing = await db.get(
          'SELECT id FROM messages WHERE client_offset = ?',
          clientOffset
        );
        messageId = existing?.id;
      }

      if (messageId) {
        socket.to(socket.sessionId).emit('chat message', msg, messageId);
      }

      callback?.();
    });
  });

  server.listen(3000, () => {
    console.log('server running at http://localhost:3000');
  });
}

main();