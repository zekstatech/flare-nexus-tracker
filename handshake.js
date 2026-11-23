/**
 * Local agent handshake tokens (Ed25519), minted by the HRMS API.
 * Same payload shape as backend/src/utils/agentHandshake.js.
 */
const crypto = require('crypto');

const HANDSHAKE_TTL_SEC = 60;
/** Tolerate laptop clock drift (the old 30s window blocked ~1–5 min skew). */
const HANDSHAKE_SKEW_SEC = 5 * 60;
/** How long a used nonce is remembered (wall clock). */
const HANDSHAKE_NONCE_RETENTION_SEC = 60 * 60;
/** Do not rewind the trusted clock from a handshake older than this. */
const HANDSHAKE_ANCHOR_MAX_DELTA_MS = 2 * 60 * 1000;

/**
 * @param {string} action
 * @param {string} token
 * @param {string} publicKey PEM
 * @param {number} nowMs local wall clock
 * @param {number|null} trustedMs server-anchored clock when available
 * @returns {{ n: string, exp: number, t: number|null } | null}
 */
function verifyHandshake(
  action,
  token,
  publicKey,
  nowMs = Date.now(),
  trustedMs = null
) {
  const tokenStr = String(token || '');
  const dot = tokenStr.lastIndexOf('.');
  if (dot <= 0 || !publicKey) return null;
  const payload = tokenStr.slice(0, dot);
  const sig = tokenStr.slice(dot + 1);
  if (!sig) return null;

  let authentic = false;
  try {
    authentic = crypto.verify(
      null,
      Buffer.from(`agent-handshake.${payload}`),
      publicKey,
      Buffer.from(sig, 'base64url')
    );
  } catch {
    return null;
  }
  if (!authentic) return null;

  let body;
  try {
    body = JSON.parse(Buffer.from(payload, 'base64url').toString('utf8'));
  } catch {
    return null;
  }
  if (!body || body.act !== action) return null;
  if (typeof body.n !== 'string' || !/^[0-9a-f]{32}$/.test(body.n)) return null;

  const exp = Number(body.exp);
  if (!Number.isFinite(exp)) return null;

  const serverMs = Number(body.t);
  const serverSec = Number.isFinite(serverMs) ? Math.floor(serverMs / 1000) : null;
  if (serverSec != null) {
    const expectedExp = serverSec + HANDSHAKE_TTL_SEC;
    if (Math.abs(exp - expectedExp) > 30) return null;
  }

  // Prefer server-anchored time after the first successful sync; otherwise
  // local wall clock with a wide skew so ~1–5 min laptop drift still works.
  const trustedSec =
    trustedMs != null && Number.isFinite(trustedMs)
      ? Math.floor(trustedMs / 1000)
      : null;
  const nowSec = trustedSec != null ? trustedSec : Math.floor(nowMs / 1000);

  if (nowSec > exp + HANDSHAKE_SKEW_SEC) return null;
  if (exp - nowSec > HANDSHAKE_TTL_SEC + HANDSHAKE_SKEW_SEC) return null;

  return {
    n: body.n,
    exp,
    t: Number.isFinite(serverMs) ? serverMs : null,
  };
}

/**
 * Single-use consumer with nonce retention and safe clock anchoring.
 * @param {{
 *   publicKey: string,
 *   getTrustedMs: () => number|null,
 *   onAnchor: (serverNowMs: number) => void,
 * }} opts
 */
function createHandshakeConsumer({ publicKey, getTrustedMs, onAnchor }) {
  /** @type {Map<string, number>} nonce -> retain-until unix seconds */
  const usedHandshakes = new Map();

  return function consumeHandshake(action, token) {
    const trustedMs =
      typeof getTrustedMs === 'function' ? getTrustedMs() : null;
    const parsed = verifyHandshake(
      action,
      token,
      publicKey,
      Date.now(),
      trustedMs
    );
    if (!parsed) return null;

    const now = Math.floor(Date.now() / 1000);
    for (const [nonce, until] of usedHandshakes) {
      if (until < now) usedHandshakes.delete(nonce);
    }
    if (usedHandshakes.has(parsed.n)) return false;
    usedHandshakes.set(parsed.n, now + HANDSHAKE_NONCE_RETENTION_SEC);

    if (parsed.t && typeof onAnchor === 'function') {
      const current = trustedMs;
      if (
        current == null ||
        Math.abs(parsed.t - current) <= HANDSHAKE_ANCHOR_MAX_DELTA_MS
      ) {
        onAnchor(parsed.t);
      }
    }
    return true;
  };
}

module.exports = {
  HANDSHAKE_TTL_SEC,
  HANDSHAKE_SKEW_SEC,
  HANDSHAKE_NONCE_RETENTION_SEC,
  HANDSHAKE_ANCHOR_MAX_DELTA_MS,
  verifyHandshake,
  createHandshakeConsumer,
};
