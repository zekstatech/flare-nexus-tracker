/**
 * Crash-safe session marker and minute ledger (SQLite, main process).
 * Session credentials, the per-session signing key, and minute payloads
 * are AES-256-GCM sealed.
 * minute_ts stays readable so uploads can run in chronological order.
 * A minute row stays until the cloud API returns 200 for that upload.
 */
const crypto = require('crypto');
const Database = require('better-sqlite3');

function sealJson(key, value) {
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
  const body = Buffer.concat([
    cipher.update(JSON.stringify(value), 'utf8'),
    cipher.final(),
  ]);
  const tag = cipher.getAuthTag();
  return Buffer.concat([iv, tag, body]).toString('base64');
}

function openJson(key, sealed) {
  const buf = Buffer.from(String(sealed || ''), 'base64');
  if (buf.length < 29) throw new Error('sealed payload is too short');
  const decipher = crypto.createDecipheriv('aes-256-gcm', key, buf.subarray(0, 12));
  decipher.setAuthTag(buf.subarray(12, 28));
  const json = Buffer.concat([
    decipher.update(buf.subarray(28)),
    decipher.final(),
  ]).toString('utf8');
  return JSON.parse(json);
}

function columnNames(db, table) {
  const exists = db
    .prepare("SELECT name FROM sqlite_master WHERE type = 'table' AND name = ?")
    .get(table);
  if (!exists) return [];
  return db.prepare(`PRAGMA table_info(${table})`).all().map((row) => row.name);
}

function migrateLegacy(db, key) {
  const sessionCols = columnNames(db, 'session');
  const minuteCols = columnNames(db, 'minutes');
  const legacySessions = sessionCols.includes('token')
    ? db.prepare(
        'SELECT session_id, token, api_base_url, idle_threshold_sec FROM session'
      ).all()
    : [];
  const legacyMinutes = minuteCols.includes('is_active')
    ? db.prepare(
        `SELECT session_id, minute_ts, is_active, mouse_events, key_events,
                interval_cv, loop_score, editor_active, signature
         FROM minutes ORDER BY minute_ts`
      ).all()
    : [];
  if (sessionCols.includes('token')) db.exec('DROP TABLE session');
  if (minuteCols.includes('is_active')) db.exec('DROP TABLE minutes');

  db.exec(`
    CREATE TABLE IF NOT EXISTS session (
      id INTEGER PRIMARY KEY CHECK (id = 1),
      session_id TEXT NOT NULL,
      sealed TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS minutes (
      session_id TEXT NOT NULL,
      minute_ts TEXT NOT NULL,
      sealed TEXT NOT NULL,
      PRIMARY KEY (session_id, minute_ts)
    );
  `);

  const insertSession = db.prepare(`
    INSERT INTO session (id, session_id, sealed)
    VALUES (1, @sessionId, @sealed)
  `);
  const insertMinute = db.prepare(`
    INSERT INTO minutes (session_id, minute_ts, sealed)
    VALUES (@sessionId, @minute_ts, @sealed)
  `);
  const writeLegacy = db.transaction(() => {
    for (const row of legacySessions) {
      insertSession.run({
        sessionId: String(row.session_id),
        sealed: sealJson(key, {
          token: String(row.token),
          apiBaseUrl: String(row.api_base_url),
          idleThresholdSec: Number(row.idle_threshold_sec) || 300,
          signingKey: row.signing_key ? String(row.signing_key) : '',
        }),
      });
    }
    for (const row of legacyMinutes) {
      const tick = {
        minute_ts: String(row.minute_ts),
        is_active: row.is_active === 1,
        mouse_events: row.mouse_events,
        key_events: row.key_events,
        interval_cv: row.interval_cv,
        loop_score: row.loop_score,
        editor_active: row.editor_active === 1,
      };
      insertMinute.run({
        sessionId: String(row.session_id),
        minute_ts: tick.minute_ts,
        sealed: sealJson(key, { tick, signature: String(row.signature || '') }),
      });
    }
  });
  if (legacySessions.length || legacyMinutes.length) writeLegacy();
}

function openLedger(file, key) {
  if (!Buffer.isBuffer(key) || key.length !== 32) {
    throw new Error('ledger key must be 32 bytes');
  }
  const db = new Database(file);
  // WAL lets a chunk read and the next delete overlap. NORMAL syncs at
  // checkpoint instead of on every 120-row delete during a reconnect.
  db.pragma('journal_mode = WAL');
  db.pragma('synchronous = NORMAL');
  db.pragma('busy_timeout = 5000');
  db.pragma('cache_size = -8000');
  db.pragma('temp_store = MEMORY');
  db.pragma('mmap_size = 268435456');
  migrateLegacy(db, key);

  const saveSessionStmt = db.prepare(`
    INSERT INTO session (id, session_id, sealed)
    VALUES (1, @sessionId, @sealed)
    ON CONFLICT(id) DO UPDATE SET
      session_id = excluded.session_id,
      sealed = excluded.sealed
  `);
  const loadSessionStmt = db.prepare(
    'SELECT session_id, sealed FROM session WHERE id = 1'
  );
  const clearSessionStmt = db.prepare('DELETE FROM session WHERE id = 1');
  const saveMinuteStmt = db.prepare(`
    INSERT INTO minutes (session_id, minute_ts, sealed)
    VALUES (@sessionId, @minute_ts, @sealed)
    ON CONFLICT(session_id, minute_ts) DO UPDATE SET
      sealed = excluded.sealed
  `);
  const listMinutesStmt = db.prepare(`
    SELECT minute_ts, sealed
    FROM minutes
    WHERE session_id = ?
    ORDER BY minute_ts
  `);
  const deleteOneStmt = db.prepare(
    'DELETE FROM minutes WHERE session_id = ? AND minute_ts = ?'
  );
  const deleteSessionMinutesStmt = db.prepare(
    'DELETE FROM minutes WHERE session_id = ?'
  );
  const deleteSome = db.transaction((sessionId, minuteTsList) => {
    for (const minuteTs of minuteTsList) deleteOneStmt.run(sessionId, minuteTs);
  });

  return {
    saveSession(session) {
      saveSessionStmt.run({
        sessionId: String(session.sessionId),
        sealed: sealJson(key, {
          token: String(session.token),
          apiBaseUrl: String(session.apiBaseUrl),
          idleThresholdSec: Number(session.idleThresholdSec) || 300,
          signingKey: String(session.signingKey || ''),
        }),
      });
    },
    loadSession() {
      const row = loadSessionStmt.get();
      if (!row) return null;
      try {
        const body = openJson(key, row.sealed);
        return {
          sessionId: row.session_id,
          token: body.token,
          apiBaseUrl: body.apiBaseUrl,
          idleThresholdSec: body.idleThresholdSec,
          signingKey: body.signingKey || '',
        };
      } catch (err) {
        console.warn('[ledger] session seal failed:', err.message);
        return null;
      }
    },
    clearSession() {
      clearSessionStmt.run();
    },
    saveMinute(sessionId, tick, signature) {
      const minuteTs = String(tick.minute_ts);
      saveMinuteStmt.run({
        sessionId: String(sessionId),
        minute_ts: minuteTs,
        sealed: sealJson(key, {
          tick: {
            minute_ts: minuteTs,
            is_active: tick.is_active === true,
            mouse_events: Number(tick.mouse_events) || 0,
            key_events: Number(tick.key_events) || 0,
            interval_cv: tick.interval_cv == null ? null : Number(tick.interval_cv),
            loop_score: tick.loop_score == null ? null : Number(tick.loop_score),
            editor_active: tick.editor_active === true,
          },
          signature: String(signature || ''),
        }),
      });
    },
    listMinutes(sessionId) {
      return listMinutesStmt.all(String(sessionId)).map((row) => {
        try {
          const body = openJson(key, row.sealed);
          return { tick: body.tick, signature: body.signature };
        } catch {
          return { minute_ts: row.minute_ts, unreadable: true };
        }
      });
    },
    deleteMinutes(sessionId, minuteTsList) {
      if (!minuteTsList || minuteTsList.length === 0) return;
      deleteSome(String(sessionId), minuteTsList);
    },
    clearMinutes(sessionId) {
      deleteSessionMinutesStmt.run(String(sessionId));
    },
    close() {
      db.close();
    },
  };
}

module.exports = { openLedger };
