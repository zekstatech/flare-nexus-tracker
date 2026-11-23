const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('crypto');
const {
  HANDSHAKE_TTL_SEC,
  verifyHandshake,
  createHandshakeConsumer,
} = require('./handshake');

const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');

function issue(action, nowMs = Date.now()) {
  const nonce = crypto.randomBytes(16).toString('hex');
  const exp = Math.floor(nowMs / 1000) + HANDSHAKE_TTL_SEC;
  const payload = Buffer.from(
    JSON.stringify({ act: action, exp, n: nonce, t: nowMs }),
    'utf8'
  ).toString('base64url');
  const sig = crypto
    .sign(null, Buffer.from(`agent-handshake.${payload}`), privateKey)
    .toString('base64url');
  return `${payload}.${sig}`;
}

describe('verifyHandshake', () => {
  it('accepts a fresh token', () => {
    const token = issue('preflight');
    const parsed = verifyHandshake('preflight', token, publicKey);
    assert.ok(parsed);
    assert.match(parsed.n, /^[0-9a-f]{32}$/);
  });

  it('accepts when laptop clock is 3 minutes ahead (no trusted clock)', () => {
    const issuedAt = Date.now();
    const token = issue('start', issuedAt);
    const localAhead = issuedAt + 3 * 60 * 1000;
    assert.ok(
      verifyHandshake('start', token, publicKey, localAhead, null),
      '3 min ahead should still accept without trusted clock'
    );
  });

  it('accepts when laptop clock is 3 minutes behind (no trusted clock)', () => {
    const issuedAt = Date.now();
    const token = issue('stop', issuedAt);
    const localBehind = issuedAt - 3 * 60 * 1000;
    assert.ok(
      verifyHandshake('stop', token, publicKey, localBehind, null),
      '3 min behind should still accept without trusted clock'
    );
  });

  it('rejects tokens older than TTL + skew', () => {
    const issuedAt = Date.now() - 12 * 60 * 1000;
    const token = issue('preflight', issuedAt);
    assert.equal(verifyHandshake('preflight', token, publicKey), null);
  });

  it('rejects expired tokens when trusted clock is available', () => {
    const issuedAt = Date.now() - 12 * 60 * 1000;
    const token = issue('preflight', issuedAt);
    const trusted = Date.now();
    assert.equal(
      verifyHandshake('preflight', token, publicKey, trusted, trusted),
      null
    );
  });

  it('rejects wrong action', () => {
    const token = issue('start');
    assert.equal(verifyHandshake('stop', token, publicKey), null);
  });

  it('rejects tampered signature', () => {
    const token = issue('start');
    const dot = token.lastIndexOf('.');
    const flipped =
      token.slice(0, dot + 1) +
      (token[dot + 1] === 'A' ? 'B' : 'A') +
      token.slice(dot + 2);
    assert.equal(verifyHandshake('start', flipped, publicKey), null);
  });
});

describe('consumeHandshake', () => {
  it('rejects replay of the same nonce', () => {
    const anchors = [];
    const consume = createHandshakeConsumer({
      publicKey,
      getTrustedMs: () => null,
      onAnchor: (t) => anchors.push(t),
    });
    const token = issue('preflight');
    assert.equal(consume('preflight', token), true);
    assert.equal(consume('preflight', token), false);
    assert.equal(anchors.length, 1);
  });

  it('does not rewind trusted clock from a stale handshake', () => {
    const anchors = [];
    let trusted = Date.now();
    const consume = createHandshakeConsumer({
      publicKey,
      getTrustedMs: () => trusted,
      onAnchor: (t) => {
        anchors.push(t);
        trusted = t;
      },
    });
    const staleIssue = Date.now() - 10 * 60 * 1000;
    // Mint with current key but old t — claims consistent with that t.
    // Trusted clock should reject expiry, so consume returns null.
    const stale = issue('start', staleIssue);
    assert.equal(consume('start', stale), null);
    assert.equal(anchors.length, 0);
  });
});
