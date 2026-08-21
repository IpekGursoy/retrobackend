const express = require('express');
const { createServer } = require('node:http');
const { Server } = require('socket.io');
const sqlite3 = require('sqlite3');
const { open } = require('sqlite');
const { randomBytes } = require('node:crypto');

function generateSessionId() {
  return randomBytes(3).toString('hex').toUpperCase();
}

async function main() {
  const db = await open({
    filename: 'chat.db',
    driver: sqlite3.Database
  });

  await db.exec(`
    CREATE TABLE IF NOT EXISTS sessions (
      id TEXT PRIMARY KEY,
      name TEXT NOT NULL,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    );
  `);

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

  const app = express();
  const server = createServer(app);
  const io = new Server(server, {
    connectionStateRecovery: {},
    cors: {
      origin: ['http://localhost:4200', 'http://127.0.0.1:4200'],
      methods: ['GET', 'POST'],
    },
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

        callback({ sessionId, name: sessionName });
      } catch (error) {
        console.error('create session failed:', error);
        callback({ error: 'Failed to create session' });
      }
    });

    socket.on('join session', async (sessionId, callback) => {
      const normalizedId = (sessionId || '').trim().toUpperCase();
      const session = await db.get(
        'SELECT id, name FROM sessions WHERE id = ?',
        normalizedId
      );

      if (!session) {
        callback({ error: 'Session not found' });
        return;
      }

      socket.sessionId = session.id;
      socket.join(session.id);

      const rows = await db.all(
        'SELECT content FROM messages WHERE session_id = ? ORDER BY id',
        session.id
      );

      callback({
        sessionId: session.id,
        name: session.name,
        messages: rows.map((row) => row.content),
      });
    });

    socket.on('watch session', async (sessionId, callback) => {
      const normalizedId = (sessionId || '').trim().toUpperCase();
      const session = await db.get(
        'SELECT id, name FROM sessions WHERE id = ?',
        normalizedId
      );

      if (!session) {
        callback?.({ error: 'Session not found' });
        return;
      }

      socket.sessionId = session.id;
      socket.join(session.id);

      const rows = await db.all(
        'SELECT content FROM messages WHERE session_id = ? ORDER BY id',
        session.id
      );

      callback?.({
        sessionId: session.id,
        name: session.name,
        messages: rows.map((row) => row.content),
      });
    });

    socket.on('chat message', async (msg, clientOffset, callback) => {
      if (!socket.sessionId) {
        callback?.({ error: 'Not in a session' });
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
