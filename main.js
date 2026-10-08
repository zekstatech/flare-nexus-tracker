/**
 * Flare Nexus desktop productivity tracker (MVP).
 * Local HTTP on 127.0.0.1:17345 — status / start / stop.
 * Idle detection via Electron powerMonitor.getSystemIdleTime().
 * Sampling, minute buckets, and uploads run in this main process on a
 * 1-second wall-clock ticker. While a session is active, macOS App Nap
 * is blocked so that hidden-tray timer is not suspended. The browser only
 * hands off a token via POST /start; batches go to the API with Node
 * http/https, not Chromium.
 * The active session and every minute bucket are stored in an encrypted
 * SQLite ledger. While the API is unreachable, tracking continues and
 * cloud calls pause. A probe resumes an in-order bulk sync, and minutes
 * are deleted only after the API returns 200.
 * Minute timestamps advance from the server clock with process.hrtime,
 * so a laptop clock change does not move them. Each minute is
 * HMAC-signed with a per-session key issued by the API.
 * This app embeds only the handshake public key. The API rejects a
 * batch whose signature does not match that session's key.
 * Packaged builds send one SHA-256 of app.asar plus every unpacked
 * native addon. The API rejects it when that hash is not on the
 * official-build list.
 * POST /start, /stop, and /preflight require a single-use handshake
 * token signed by the HRMS API. /status stays open for the install check.
 * The window is static — hidden renderers throttle timers.
 * No screenshots in MVP.
 */

const {
  app,
  BrowserWindow,
  powerMonitor,
  powerSaveBlocker,
  screen,
  Tray,
  Menu,
  nativeImage,
  dialog,
  safeStorage,
} = require('electron');
const { autoUpdater } = require('electron-updater');
const http = require('http');
const https = require('https');
const crypto = require('crypto');
const { execFileSync, execFile } = require('child_process');
const { URL } = require('url');
const fs = require('fs');
const path = require('path');
const { openLedger } = require('./ledger');
const { hashResources, hashDevSources } = require('./buildHash');

const AGENT_PORT = Number(process.env.TRACKER_AGENT_PORT || 17345);
const AGENT_VERSION = require('./package.json').version;
/** Must match backend PRODUCTIVITY_AGENT_APP_KEY (or its default). */
const AGENT_APP_KEY =
  process.env.TRACKER_APP_KEY || 'flare-nexus-tracker';
/**
 * Ed25519 public key for local /start, /stop, and /preflight.
 * The private key stays on the API (PRODUCTIVITY_HANDSHAKE_PRIVATE_KEY).
 */
const HANDSHAKE_PUBLIC_KEY = `-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEA/4wxGscxh0m1c/m4kOGMluGP8s9o/W8t+xpf9M8fXB4=
-----END PUBLIC KEY-----`;
const TICK_MS = 1000;
const SLEEP_GAP_MS = 90 * 1000;
const FLUSH_INTERVAL_MS = 30 * 1000;
const HEARTBEAT_INTERVAL_MS = 2 * 60 * 1000;
const ONLINE_PROBE_MS = 30 * 1000;
const UPLOAD_CHUNK = 120;
const UPDATE_CHECK_INTERVAL_MS = 4 * 60 * 60 * 1000;

let buildHashPromise = null;

/** Packaged: app.asar + unpacked .node files. Dev: the source files that ship. */
function getBuildHash() {
  if (!buildHashPromise) {
    buildHashPromise = (
      app.isPackaged ? hashResources(process.resourcesPath) : Promise.resolve(hashDevSources(__dirname))
    ).catch((err) => {
      buildHashPromise = null;
      throw err;
    });
  }
  return buildHashPromise;
}

/** Packaged installs stay in background — no tray Quit (dev can still quit). */
function canUserQuit() {
  if (process.env.TRACKER_ALLOW_QUIT === '1') return true;
  if (process.env.TRACKER_ALLOW_QUIT === '0') return false;
  return !app.isPackaged;
}

let mainWindow = null;
let tray = null;
let server = null;
let isQuitting = false;
let quitFlushDone = false;
let allowQuitForUpdate = false;
let pendingUpdateVersion = null;

/** Only one tracker process — second launch focuses the existing one. */
const gotSingleInstanceLock = app.requestSingleInstanceLock();
if (!gotSingleInstanceLock) {
  app.quit();
} else {
  app.on('second-instance', () => {
    if (mainWindow) {
      if (mainWindow.isMinimized()) mainWindow.restore();
      mainWindow.show();
      mainWindow.focus();
    }
  });
}

/** @type {null | {
 *   sessionId: string,
 *   token: string,
 *   apiBaseUrl: string,
 *   idleThresholdSec: number,
 *   signingKey: string
 * }} */
let activeSession = null;

/** SQLite ledger opened once app userData is available. */
let ledger = null;

/**
 * Current minute, built one second at a time.
 * @type {null | { key: string, activeSeconds: number, idleSeconds: number }}
 */
let currentBucket = null;

let lastIdleSec = 0;
let lastIdleState = 'unknown';
let lastTickAt = 0;
let lastFlushAt = 0;
let lastHeartbeatAt = 0;
let lastProbeAt = 0;
/** True after a transport failure. Tracking still writes the ledger. */
let cloudOffline = false;

/** Main-process ticker only. Renderer timers are throttled when hidden. */
let monitoring = false;
let tickerTimer = null;
let inputPollTimer = null;
/** macOS App Nap id while a session is tracking. Display sleep stays allowed. */
let appSuspensionBlocker = null;

const INPUT_POLL_MS = 250;
const PATTERN_KEEP = 16;
/** Rolling inter-move gaps and small pixel steps, across minutes. */
let recentIntervals = [];
let recentDeltas = [];
let lastCursor = null;
let lastIdleSample = null;
let lastMoveAt = 0;
let lastForegroundAt = 0;
let foregroundPending = false;

function ledgerFile() {
  return path.join(app.getPath('userData'), 'ledger.sqlite');
}

function ledgerKeyFile() {
  return path.join(app.getPath('userData'), 'ledger.key');
}

/** OS keychain key. A copied ledger.sqlite does not decrypt on another login. */
function loadOrCreateLedgerKey() {
  const file = ledgerKeyFile();
  const available = safeStorage.isEncryptionAvailable();
  if (fs.existsSync(file)) {
    const stored = fs.readFileSync(file);
    if (available) {
      return Buffer.from(safeStorage.decryptString(stored), 'base64');
    }
    if (stored.length === 32) return stored;
  }
  const key = crypto.randomBytes(32);
  if (available) {
    fs.writeFileSync(file, safeStorage.encryptString(key.toString('base64')));
  } else {
    console.warn('[ledger] OS encryption unavailable; key file is local only');
    fs.writeFileSync(file, key, { mode: 0o600 });
  }
  return key;
}

function isNetworkError(err) {
  if (!err || Number.isFinite(err.status)) return false;
  const code = String(err.code || '');
  if (
    /^(ECONNREFUSED|ENOTFOUND|EAI_AGAIN|ECONNRESET|ENETUNREACH|EHOSTUNREACH|EPIPE|ETIMEDOUT|ECONNABORTED)$/.test(
      code
    )
  ) {
    return true;
  }
  return /timeout|socket hang up|getaddrinfo|network/i.test(String(err.message || ''));
}

function markOffline(err) {
  lastProbeAt = Date.now();
  if (cloudOffline) return;
  cloudOffline = true;
  console.warn(
    '[offline] cloud API unreachable, tracking continues locally:',
    err?.message || err
  );
}

function markOnline() {
  if (!cloudOffline) return;
  cloudOffline = false;
  console.log('[offline] connection restored, syncing local cache');
}

function legacySessionPath() {
  return path.join(app.getPath('userData'), 'active-session.json');
}

function legacyQueuePath() {
  return path.join(app.getPath('userData'), 'activity-queue.json');
}

function clearLocalSession(reason) {
  if (reason) console.warn('[session]', reason);
  const sessionId = activeSession?.sessionId;
  stopMonitoringTimers();
  activeSession = null;
  currentBucket = null;
  if (ledger) {
    if (sessionId) ledger.clearMinutes(sessionId);
    ledger.clearSession();
  }
  refreshTrayMenu();
}

function isSessionGoneError(err) {
  const msg = String(err?.message || '');
  return msg.includes('HTTP 404') || msg.includes('HTTP 409');
}

function saveSessionMarker() {
  if (!ledger) return;
  if (!activeSession) {
    ledger.clearSession();
    return;
  }
  ledger.saveSession(activeSession);
}

function loadSessionMarker() {
  if (!ledger) return null;
  return ledger.loadSession();
}

function minuteTick(bucket, isActive) {
  return {
    minute_ts: bucket.key,
    is_active: isActive,
    ...patternFields(bucket),
  };
}

function saveMinuteTick(tick) {
  if (clockWritesBlocked || !ledger || !activeSession) return;
  const machineId = getMachineId();
  if (!machineId) return;
  const signature = signActivity(
    activeSession.sessionId,
    machineId,
    [tick],
    activeSession.signingKey
  );
  if (!signature) return;
  ledger.saveMinute(activeSession.sessionId, tick, signature);
}

function saveBucket(bucket) {
  if (!bucket || bucket.activeSeconds + bucket.idleSeconds === 0) return;
  saveMinuteTick(minuteTick(bucket, minuteIsActive(bucket)));
}

const HANDSHAKE_TTL_SEC = 60;
const HANDSHAKE_SKEW_SEC = 30;
/** nonce -> expiry unix seconds. Replay of a captured token is rejected. */
const usedHandshakes = new Map();

/**
 * Same token format as backend/src/utils/agentHandshake.js.
 * Returns { n, exp } or null.
 */
function verifyHandshake(action, token, nowMs = Date.now()) {
  const tokenStr = String(token || '');
  const dot = tokenStr.lastIndexOf('.');
  if (dot <= 0) return null;
  const payload = tokenStr.slice(0, dot);
  const sig = tokenStr.slice(dot + 1);
  if (!sig) return null;
  let authentic = false;
  try {
    authentic = crypto.verify(
      null,
      Buffer.from(`agent-handshake.${payload}`),
      HANDSHAKE_PUBLIC_KEY,
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
  const now = Math.floor(nowMs / 1000);
  const serverMs = Number(body.t);
  const serverSec = Number.isFinite(serverMs) ? Math.floor(serverMs / 1000) : null;
  if (!Number.isFinite(exp)) return null;
  // A shifted laptop clock must not expire a freshly signed token.
  const clockForExpiry =
    serverSec != null && Math.abs(now - serverSec) > 5 * 60 ? serverSec : now;
  if (clockForExpiry > exp + HANDSHAKE_SKEW_SEC) return null;
  if (exp - clockForExpiry > HANDSHAKE_TTL_SEC + HANDSHAKE_SKEW_SEC) return null;
  return { n: body.n, exp, t: Number.isFinite(serverMs) ? serverMs : null };
}

function consumeHandshake(action, token) {
  const parsed = verifyHandshake(action, token);
  if (!parsed) return null;
  if (parsed.t) anchorTrustedClock(parsed.t);
  const now = Math.floor(Date.now() / 1000);
  for (const [nonce, exp] of usedHandshakes) {
    if (exp + HANDSHAKE_SKEW_SEC < now) usedHandshakes.delete(nonce);
  }
  if (usedHandshakes.has(parsed.n)) return false;
  usedHandshakes.set(parsed.n, parsed.exp);
  return true;
}

function statOrNull(value) {
  if (value == null || value === '') return null;
  const n = Number(value);
  if (!Number.isFinite(n)) return null;
  return Math.round(n * 10000) / 10000;
}

/** Same bytes as backend/src/utils/tickSignature.js */
function canonicalActivity(sessionId, machineId, ticks) {
  const rows = (Array.isArray(ticks) ? ticks : []).map((tick) => ({
    minute_ts: String(tick.minute_ts),
    is_active: tick.is_active === true,
    mouse_events: Number(tick.mouse_events) || 0,
    key_events: Number(tick.key_events) || 0,
    interval_cv: statOrNull(tick.interval_cv),
    loop_score: statOrNull(tick.loop_score),
    editor_active: tick.editor_active === true,
  }));
  rows.sort((a, b) => a.minute_ts.localeCompare(b.minute_ts));
  return JSON.stringify({
    v: 1,
    sessionId: String(sessionId),
    machineId: String(machineId),
    ticks: rows,
  });
}

function sessionKeyBuffer(signingKey) {
  const hex = String(signingKey || '');
  if (!/^[0-9a-f]{64}$/i.test(hex)) return null;
  return Buffer.from(hex, 'hex');
}

function signActivity(sessionId, machineId, ticks, signingKey) {
  const key = sessionKeyBuffer(signingKey);
  if (!key) return '';
  return crypto
    .createHmac('sha256', key)
    .update(canonicalActivity(sessionId, machineId, ticks))
    .digest('hex');
}

function verifyActivity(sessionId, machineId, ticks, signature, signingKey) {
  const presented = String(signature || '');
  if (!/^[0-9a-f]{64}$/i.test(presented)) return false;
  if (!machineId || !sessionId) return false;
  const expected = signActivity(sessionId, machineId, ticks, signingKey);
  const a = Buffer.from(expected, 'hex');
  const b = Buffer.from(presented, 'hex');
  if (a.length !== b.length) return false;
  return crypto.timingSafeEqual(a, b);
}

let cachedMachineId = '';

function readOsMachineId() {
  if (process.platform === 'darwin') {
    const out = execFileSync('ioreg', ['-rd1', '-c', 'IOPlatformExpertDevice'], {
      encoding: 'utf8',
      timeout: 3000,
    });
    const match = out.match(/"IOPlatformUUID"\s*=\s*"([^"]+)"/);
    return match ? match[1].trim() : '';
  }
  if (process.platform === 'win32') {
    const out = execFileSync(
      'reg',
      ['query', 'HKLM\\SOFTWARE\\Microsoft\\Cryptography', '/v', 'MachineGuid'],
      { encoding: 'utf8', timeout: 3000, windowsHide: true }
    );
    const match = out.match(/MachineGuid\s+REG_SZ\s+(\S+)/i);
    return match ? match[1].trim() : '';
  }
  return fs.readFileSync('/etc/machine-id', 'utf8').trim();
}

function getMachineId() {
  if (cachedMachineId) return cachedMachineId;
  try {
    const id = readOsMachineId();
    if (id && id.length >= 8 && id.length <= 128) cachedMachineId = id;
  } catch (err) {
    console.warn('machine id:', err.message);
  }
  return cachedMachineId;
}

function importLegacyFiles() {
  if (!ledger || ledger.loadSession()) return;
  let marker = null;
  try {
    marker = JSON.parse(fs.readFileSync(legacySessionPath(), 'utf8'));
  } catch {
    marker = null;
  }
  if (!marker?.sessionId || !marker?.token || !marker?.apiBaseUrl) return;
  activeSession = {
    sessionId: String(marker.sessionId),
    token: String(marker.token),
    apiBaseUrl: String(marker.apiBaseUrl),
    idleThresholdSec: Math.max(60, Number(marker.idleThresholdSec) || 300),
  };
  ledger.saveSession(activeSession);
  try {
    const parsed = JSON.parse(fs.readFileSync(legacyQueuePath(), 'utf8'));
    const machineId = getMachineId();
    const intact =
      machineId &&
      parsed.sessionId === activeSession.sessionId &&
      parsed.machineId === machineId &&
      verifyActivity(
        parsed.sessionId,
        parsed.machineId,
        parsed.ticks,
        parsed.signature,
        activeSession.signingKey
      );
    if (intact && Array.isArray(parsed.ticks)) {
      for (const tick of parsed.ticks) saveMinuteTick(tick);
    } else if (parsed?.ticks) {
      console.warn('[ledger] legacy activity file signature mismatch — not imported');
    }
  } catch {
    // no legacy queue
  }
  for (const file of [legacySessionPath(), legacyQueuePath()]) {
    try {
      fs.unlinkSync(file);
    } catch {
      // ignore
    }
  }
  activeSession = null;
}

function apiUrl(base, suffix) {
  const root = String(base || '').replace(/\/$/, '');
  const pathPart = suffix.startsWith('/') ? suffix : `/${suffix}`;
  return `${root}${pathPart}`;
}

/**
 * POST JSON with Node's http/https. Electron's fetch uses Chromium's
 * network stack and can pause when every window is hidden; the HRMS tab
 * is not on this path.
 */
function postJson(urlString, token, body, extraHeaders) {
  const payload = Buffer.from(JSON.stringify(body ?? {}), 'utf8');
  const target = new URL(urlString);
  const lib = target.protocol === 'https:' ? https : http;
  return new Promise((resolve, reject) => {
    const req = lib.request(
      {
        protocol: target.protocol,
        hostname: target.hostname,
        port: target.port || undefined,
        path: `${target.pathname}${target.search}`,
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Content-Length': payload.length,
          Authorization: `Bearer ${token}`,
          ...(extraHeaders || {}),
        },
      },
      (res) => {
        const chunks = [];
        res.on('data', (chunk) => chunks.push(chunk));
        res.on('end', () => {
          const text = Buffer.concat(chunks).toString('utf8');
          let json = {};
          if (text) {
            try {
              json = JSON.parse(text);
            } catch {
              json = {};
            }
          }
          if (res.statusCode < 200 || res.statusCode >= 300) {
            const err = new Error(
              `HTTP ${res.statusCode}: ${(json.message || text).slice(0, 200)}`
            );
            err.status = res.statusCode;
            reject(err);
            return;
          }
          resolve(Object.assign({}, json, { statusCode: res.statusCode }));
        });
      }
    );
    req.setTimeout(20000, () => {
      req.destroy(new Error('request timeout'));
    });
    req.on('error', reject);
    req.end(payload);
  });
}

/**
 * Prove this desktop agent is running: call HRMS with user JWT + app key.
 * Browser check-in requires a fresh agent-ready mark from this call.
 */
async function runPreflight({ token, apiBaseUrl }) {
  if (!token || !apiBaseUrl) {
    const err = new Error('token and apiBaseUrl are required');
    err.status = 400;
    throw err;
  }
  const url = apiUrl(apiBaseUrl, '/time-tracking/agent-ready');
  let json;
  try {
    json = await postJson(
      url,
      token,
      {
        version: AGENT_VERSION,
        appKey: AGENT_APP_KEY,
        buildHash: await getBuildHash(),
      },
      { 'X-Productivity-Agent-Key': AGENT_APP_KEY }
    );
  } catch (err) {
    const wrapped = new Error(err.message || 'Agent ready failed');
    wrapped.status =
      err.status >= 400 && err.status < 600 ? err.status : 502;
    throw wrapped;
  }
  return {
    ok: true,
    version: AGENT_VERSION,
    ...(json.data || {}),
  };
}

/** Server time at the last anchor, plus CPU monotonic time since then. */
let clockAnchorMs = 0;
let clockAnchorHr = 0n;
/** While true, the ticker must not seal or write a minute. */
let clockWritesBlocked = false;

function anchorTrustedClock(serverNowMs) {
  const ms = Number(serverNowMs);
  if (!Number.isFinite(ms) || ms < 1_000_000_000_000) return false;
  clockAnchorMs = ms;
  clockAnchorHr = process.hrtime.bigint();
  return true;
}

function trustedNowMs() {
  if (!clockAnchorMs) return null;
  const elapsedMs = Number((process.hrtime.bigint() - clockAnchorHr) / 1_000_000n);
  return clockAnchorMs + elapsedMs;
}

function releaseClockHold() {
  const now = trustedNowMs();
  if (now == null) return;
  clockWritesBlocked = false;
  lastTickAt = now;
  lastFlushAt = now;
  lastHeartbeatAt = now;
}

/** Drop the in-progress minute. Sleep time is not productive and its stamp is stale. */
function discardOpenMinute() {
  const key = currentBucket?.key;
  currentBucket = null;
  if (!key || !ledger || !activeSession) return;
  ledger.deleteMinutes(activeSession.sessionId, [key]);
}

function minuteKey(date) {
  const instant = date instanceof Date ? date : new Date(trustedNowMs() || Date.now());
  const minute = new Date(instant);
  minute.setSeconds(0, 0);
  minute.setMilliseconds(0);
  return minute.toISOString();
}

/**
 * Read OS idle. A minute is idle when the user has been idle for at least
 * idleThresholdSec (org setting), or the screen is locked.
 */
function readIdle() {
  let idleSec = 0;
  let state = 'unknown';
  try {
    idleSec = Number(powerMonitor.getSystemIdleTime()) || 0;
  } catch (err) {
    console.warn('getSystemIdleTime failed:', err.message);
  }
  try {
    const threshold = activeSession?.idleThresholdSec || 300;
    state = powerMonitor.getSystemIdleState(threshold) || 'unknown';
  } catch (err) {
    console.warn('getSystemIdleState failed:', err.message);
  }
  lastIdleSec = idleSec;
  lastIdleState = state;
  return { idleSec, state };
}

function isIdleNow(idleSec, state, thresholdSec) {
  if (state === 'locked' || state === 'idle') return true;
  return idleSec >= thresholdSec;
}

function minuteIsActive(bucket) {
  return bucket.activeSeconds > 0;
}

function pushCap(list, value, max) {
  list.push(value);
  if (list.length > max) list.splice(0, list.length - max);
}

function intervalCv(intervals) {
  if (!intervals || intervals.length < 4) return null;
  const mean = intervals.reduce((sum, n) => sum + n, 0) / intervals.length;
  if (mean <= 0) return null;
  const variance =
    intervals.reduce((sum, n) => sum + (n - mean) ** 2, 0) / intervals.length;
  return Math.round((Math.sqrt(variance) / mean) * 10000) / 10000;
}

function loopScore(deltas) {
  if (!deltas || deltas.length < 6) return null;
  const counts = new Map();
  for (const delta of deltas) counts.set(delta, (counts.get(delta) || 0) + 1);
  let max = 0;
  for (const n of counts.values()) if (n > max) max = n;
  return Math.round((max / deltas.length) * 10000) / 10000;
}

function isEditorOrTextApp(name) {
  return /(visual studio code|visual studio|vscode|vs code|\bcode\b|cursor|\bvim\b|emacs|sublime|xcode|intellij|webstorm|pycharm|goland|android studio|\bnova\b|\bzed\b|atom|notepad|kate|gedit|textedit|microsoft word|\bword\b|\bpages\b|notion|obsidian|typora|libreoffice)/i.test(
    String(name || '')
  );
}

function patternFields(bucket) {
  const samples = bucket?.editorSamples || 0;
  const hits = bucket?.editorHits || 0;
  return {
    mouse_events: bucket?.mouseEvents || 0,
    key_events: bucket?.keyEvents || 0,
    interval_cv: intervalCv(recentIntervals),
    loop_score: loopScore(recentDeltas),
    editor_active: samples > 0 && hits / samples >= 0.5,
  };
}

function emptyPattern() {
  return {
    mouse_events: 0,
    key_events: 0,
    interval_cv: null,
    loop_score: null,
    editor_active: false,
  };
}

function sampleForeground() {
  if (foregroundPending || !currentBucket) return;
  const bucket = currentBucket;
  foregroundPending = true;
  let command = 'xdotool';
  let args = ['getactivewindow', 'getwindowname'];
  if (process.platform === 'darwin') {
    command = 'osascript';
    args = [
      '-e',
      'tell application "System Events" to get name of first application process whose frontmost is true',
    ];
  } else if (process.platform === 'win32') {
    command = 'powershell';
    args = [
      '-NoProfile',
      '-Command',
      "$sig = '[DllImport(\"user32.dll\")] public static extern IntPtr GetForegroundWindow(); [DllImport(\"user32.dll\")] public static extern int GetWindowThreadProcessId(IntPtr h, out int pid);'; $t = Add-Type -MemberDefinition $sig -Name Fg -Namespace P -PassThru; $p = 0; [void]$t::GetWindowThreadProcessId($t::GetForegroundWindow(), [ref]$p); (Get-Process -Id $p).ProcessName",
    ];
  }
  execFile(command, args, { timeout: 2000, windowsHide: true }, (err, stdout) => {
    foregroundPending = false;
    if (!bucket || bucket.editorSamples == null) return;
    bucket.editorSamples += 1;
    if (!err && isEditorOrTextApp(String(stdout || ''))) bucket.editorHits += 1;
  });
}

/** Cursor poll in the main process. A jiggler moves the pointer and does not type. */
function pollInput() {
  if (!monitoring || !activeSession || !currentBucket) return;
  let idle = 0;
  let pos = null;
  try {
    idle = Number(powerMonitor.getSystemIdleTime()) || 0;
    pos = screen.getCursorScreenPoint();
  } catch {
    return;
  }
  if (currentBucket.mouseEvents == null) {
    currentBucket.mouseEvents = 0;
    currentBucket.keyEvents = 0;
    currentBucket.editorSamples = 0;
    currentBucket.editorHits = 0;
  }
  const now = Date.now();
  const moved =
    lastCursor && pos && (pos.x !== lastCursor.x || pos.y !== lastCursor.y);
  if (moved) {
    currentBucket.mouseEvents += 1;
    if (lastMoveAt) pushCap(recentIntervals, now - lastMoveAt, PATTERN_KEEP);
    const dx = pos.x - lastCursor.x;
    const dy = pos.y - lastCursor.y;
    if (Math.abs(dx) + Math.abs(dy) <= 20) {
      pushCap(recentDeltas, `${dx},${dy}`, PATTERN_KEEP);
    }
    lastMoveAt = now;
  } else if (lastIdleSample != null && idle < lastIdleSample) {
    currentBucket.keyEvents += 1;
  }
  lastIdleSample = idle;
  if (pos) lastCursor = { x: pos.x, y: pos.y };
  if (now - lastForegroundAt >= 30000) {
    lastForegroundAt = now;
    sampleForeground();
  }
}

function startInputPoll() {
  if (inputPollTimer) clearInterval(inputPollTimer);
  recentIntervals = [];
  recentDeltas = [];
  lastCursor = null;
  lastIdleSample = null;
  lastMoveAt = 0;
  lastForegroundAt = 0;
  inputPollTimer = setInterval(pollInput, INPUT_POLL_MS);
}

function stopInputPoll() {
  if (inputPollTimer) clearInterval(inputPollTimer);
  inputPollTimer = null;
}

function flushCurrentBucket() {
  if (!currentBucket) return;
  if (currentBucket.activeSeconds + currentBucket.idleSeconds === 0) {
    currentBucket = null;
    return;
  }
  saveBucket(currentBucket);
  console.log(
    `[tick] ${currentBucket.key} active=${minuteIsActive(currentBucket)} activeSec=${currentBucket.activeSeconds} idleSec=${currentBucket.idleSeconds} lastIdle=${lastIdleSec}s state=${lastIdleState}`
  );
  currentBucket = null;
}

/** Fill missing minutes (laptop sleep / suspended timers) as idle. */
function backfillIdleGap(fromMs, toMs) {
  const start = new Date(fromMs);
  start.setSeconds(0, 0);
  start.setMilliseconds(0);
  // Start after the last sampled minute
  start.setMinutes(start.getMinutes() + 1);

  const end = new Date(toMs);
  end.setSeconds(0, 0);
  end.setMilliseconds(0);

  let filled = 0;
  const maxFill = 12 * 60; // cap 12 hours
  for (
    let t = start.getTime();
    t < end.getTime() && filled < maxFill;
    t += 60 * 1000
  ) {
    saveMinuteTick({
      minute_ts: new Date(t).toISOString(),
      is_active: false,
      ...emptyPattern(),
    });
    filled += 1;
  }
  if (filled > 0) {
    console.log(`[gap] backfilled ${filled} idle minute(s) for sleep/suspend`);
  }
}

function isUserIdle() {
  const threshold = activeSession?.idleThresholdSec || 300;
  const { idleSec, state } = readIdle();
  return isIdleNow(idleSec, state, threshold);
}

/** Add one wall-clock second to the minute it belongs to. */
function observeSecond(atMs, idle) {
  const key = minuteKey(new Date(atMs));
  if (!currentBucket || currentBucket.key !== key) {
    flushCurrentBucket();
    currentBucket = {
      key,
      activeSeconds: 0,
      idleSeconds: 0,
      mouseEvents: 0,
      keyEvents: 0,
      editorSamples: 0,
      editorHits: 0,
    };
  }
  if (idle) currentBucket.idleSeconds += 1;
  else currentBucket.activeSeconds += 1;
}

/**
 * One main-process tick. Walk every elapsed wall-clock second so a late
 * timer still fills the right minute instead of drifting.
 * A minute is active when any of its seconds was not idle.
 */
function onSecondTick() {
  if (!activeSession || clockWritesBlocked) return;

  const now = trustedNowMs();
  if (now == null) return;
  if (!lastTickAt || now < lastTickAt) lastTickAt = now;

  const gap = now - lastTickAt;
  if (gap > SLEEP_GAP_MS) {
    flushCurrentBucket();
    backfillIdleGap(lastTickAt, now);
    lastTickAt = now;
    observeSecond(now, isUserIdle());
  } else {
    const idle = isUserIdle();
    while (lastTickAt + TICK_MS <= now) {
      lastTickAt += TICK_MS;
      observeSecond(lastTickAt, idle);
    }
  }

  if (cloudOffline) {
    if (!lastProbeAt || now - lastProbeAt >= ONLINE_PROBE_MS) {
      lastProbeAt = now;
      probeCloud().catch(() => undefined);
    }
  } else {
    if (!lastFlushAt || now - lastFlushAt >= FLUSH_INTERVAL_MS) {
      lastFlushAt = now;
      flushTicks().catch(() => undefined);
    }
    if (!lastHeartbeatAt || now - lastHeartbeatAt >= HEARTBEAT_INTERVAL_MS) {
      lastHeartbeatAt = now;
      sendHeartbeat().catch(() => undefined);
    }
  }

  if (currentBucket && currentBucket.activeSeconds + currentBucket.idleSeconds > 0) {
    saveBucket(currentBucket);
  }
}

function armTicker() {
  if (!monitoring) return;
  let delay = TICK_MS - (Date.now() % TICK_MS);
  if (delay < 50) delay += TICK_MS;
  tickerTimer = setTimeout(() => {
    tickerTimer = null;
    if (!monitoring || !activeSession) return;
    try {
      onSecondTick();
    } catch (err) {
      console.error('[ticker]', err.message);
    }
    armTicker();
  }, delay);
}

let flushInFlight = null;

async function flushTicks() {
  if (flushInFlight) return flushInFlight;
  flushInFlight = uploadLedgerMinutes().finally(() => {
    flushInFlight = null;
  });
  return flushInFlight;
}

async function uploadLedgerMinutes() {
  if (!activeSession || !ledger || cloudOffline) return;
  if (
    !clockWritesBlocked &&
    currentBucket &&
    currentBucket.activeSeconds + currentBucket.idleSeconds > 0
  ) {
    saveBucket(currentBucket);
  }
  const machineId = getMachineId();
  if (!machineId) {
    console.error('flushTicks: machine id unavailable, keeping minutes in ledger');
    return;
  }
  const sessionId = activeSession.sessionId;
  const rows = ledger.listMinutes(sessionId);
  const accepted = [];
  const tampered = [];
  for (const row of rows) {
    if (row.unreadable) {
      tampered.push(row.minute_ts);
    } else if (
      verifyActivity(
        sessionId,
        machineId,
        [row.tick],
        row.signature,
        activeSession.signingKey
      )
    ) {
      accepted.push(row);
    } else {
      tampered.push(row.tick.minute_ts);
    }
  }
  if (tampered.length) {
    ledger.deleteMinutes(sessionId, tampered);
    console.warn('[ledger] discarded tampered minute(s):', tampered.length);
  }
  for (let offset = 0; offset < accepted.length; offset += UPLOAD_CHUNK) {
    if (cloudOffline || !activeSession) return;
    const slice = accepted.slice(offset, offset + UPLOAD_CHUNK);
    const ticks = slice.map((row) => row.tick);
    const signature = signActivity(
      sessionId,
      machineId,
      ticks,
      activeSession.signingKey
    );
    if (!signature) {
      console.error('flushTicks: session signing key missing, keeping minutes in ledger');
      return;
    }
    let response;
    try {
      response = await postJson(
        apiUrl(
          activeSession.apiBaseUrl,
          `/time-tracking/sessions/${sessionId}/activity-ticks`
        ),
        activeSession.token,
        {
          ticks,
          machineId,
          signature,
          buildHash: await getBuildHash(),
        }
      );
    } catch (err) {
      if (isNetworkError(err)) {
        markOffline(err);
        return;
      }
      if (isSessionGoneError(err)) {
        clearLocalSession('Session no longer active — clearing local app session');
        return;
      }
      console.error('flushTicks failed, minutes kept in ledger:', err.message);
      return;
    }
    if (!response || response.statusCode !== 200) {
      console.error('flushTicks: upload was not HTTP 200, minutes kept in ledger');
      return;
    }
    const fresh = ledger.listMinutes(sessionId);
    const confirmed = [];
    for (const row of slice) {
      const current = fresh.find((item) => item.tick && item.tick.minute_ts === row.tick.minute_ts);
      if (current && current.signature === row.signature) {
        confirmed.push(row.tick.minute_ts);
      }
    }
    ledger.deleteMinutes(sessionId, confirmed);
  }
}

async function sendHeartbeat() {
  if (!activeSession || cloudOffline) return;
  try {
    const response = await postJson(
      apiUrl(
        activeSession.apiBaseUrl,
        `/time-tracking/sessions/${activeSession.sessionId}/heartbeat`
      ),
      activeSession.token,
      { buildHash: await getBuildHash() }
    );
    return anchorTrustedClock(response?.data?.serverNow);
  } catch (err) {
    if (isNetworkError(err)) {
      markOffline(err);
      return;
    }
    if (isSessionGoneError(err)) {
      clearLocalSession('Heartbeat: session closed on server');
      return;
    }
    console.error('heartbeat failed:', err.message);
  }
}

/**
 * One reconnect attempt. Upload the queued minutes before the heartbeat
 * so the server's heartbeat wall does not seal the offline backlog.
 */
async function probeCloud() {
  if (!cloudOffline || !activeSession || flushInFlight) return;
  cloudOffline = false;
  await flushTicks();
  if (cloudOffline || !activeSession) return;
  const anchored = await sendHeartbeat();
  if (!anchored || cloudOffline || !activeSession) return;
  releaseClockHold();
  console.log('[offline] connection restored, local cache synced');
}

function startMonitoring() {
  stopMonitoringTimers();
  monitoring = true;
  currentBucket = null;
  const now = clockWritesBlocked ? 0 : trustedNowMs() || 0;
  lastTickAt = now;
  lastFlushAt = now;
  lastHeartbeatAt = now;
  if (now) observeSecond(now, isUserIdle());
  if (!clockWritesBlocked) sendHeartbeat().catch(() => undefined);
  startInputPoll();
  armTicker();
  preventAppNap();

  const onResume = () => {
    console.log('[power] resume/unlock — discard open minute and sync server time');
    syncClockAfterWake().catch((err) => {
      console.warn('[power] wake sync failed:', err.message);
    });
  };
  powerMonitor.removeAllListeners('resume');
  powerMonitor.removeAllListeners('unlock-screen');
  powerMonitor.on('resume', onResume);
  powerMonitor.on('unlock-screen', onResume);
  refreshTrayMenu();
}

function preventAppNap() {
  if (process.platform !== 'darwin') return;
  if (appSuspensionBlocker != null && powerSaveBlocker.isStarted(appSuspensionBlocker)) {
    return;
  }
  appSuspensionBlocker = powerSaveBlocker.start('prevent-app-suspension');
}

function allowAppNap() {
  if (appSuspensionBlocker == null) return;
  if (powerSaveBlocker.isStarted(appSuspensionBlocker)) {
    powerSaveBlocker.stop(appSuspensionBlocker);
  }
  appSuspensionBlocker = null;
}

function stopMonitoringTimers() {
  monitoring = false;
  if (tickerTimer) clearTimeout(tickerTimer);
  tickerTimer = null;
  stopInputPoll();
  allowAppNap();
  flushCurrentBucket();
}

async function startSession(payload) {
  const signingKey = String(payload?.signingKey || '');
  if (
    !payload?.sessionId ||
    !payload?.token ||
    !payload?.apiBaseUrl ||
    !/^[0-9a-f]{64}$/i.test(signingKey)
  ) {
    const err = new Error('sessionId, token, apiBaseUrl, and signingKey are required');
    err.status = 400;
    throw err;
  }

  const next = {
    sessionId: String(payload.sessionId),
    token: String(payload.token),
    apiBaseUrl: String(payload.apiBaseUrl),
    idleThresholdSec: Math.max(
      60,
      Number(payload.idleThresholdSec) || 300
    ),
    signingKey: signingKey.toLowerCase(),
  };

  // Same session already running (e.g. after quit/resume) — refresh creds, stay up
  if (activeSession?.sessionId === next.sessionId) {
    activeSession = next;
    saveSessionMarker();
    if (!monitoring) startMonitoring();
    return { started: true, resumed: true, sessionId: activeSession.sessionId };
  }

  // Different session still marked active — flush/clear, then start the new one
  if (activeSession) {
    await flushTicks().catch(() => undefined);
    const previousId = activeSession.sessionId;
    stopMonitoringTimers();
    activeSession = null;
    if (ledger) ledger.clearMinutes(previousId);
    saveSessionMarker();
  }

  activeSession = next;
  saveSessionMarker();
  startMonitoring();
  return { started: true, sessionId: activeSession.sessionId };
}

async function stopSession() {
  if (!activeSession) {
    return { stopped: false, reason: 'no_active_session' };
  }
  await flushTicks();
  clearLocalSession();
  return { stopped: true };
}

let wakeSync = null;

/**
 * Lid open: drop the unfinished minute, push minutes sealed before sleep,
 * then re-anchor. The ticker stays blocked until serverNow is applied.
 */
async function syncClockAfterWake() {
  if (wakeSync) return wakeSync;
  wakeSync = (async () => {
    clockWritesBlocked = true;
    discardOpenMinute();
    lastTickAt = 0;
    if (!cloudOffline) await flushTicks();
    if (cloudOffline || !activeSession) return;
    if (await sendHeartbeat()) releaseClockHold();
  })().finally(() => {
    wakeSync = null;
  });
  return wakeSync;
}

/** After relaunch: keep the signing key, upload the old queue, then anchor. */
async function validateResumedSession() {
  if (!activeSession) return;
  clockWritesBlocked = true;
  try {
    await flushTicks();
    if (cloudOffline || !activeSession) return;
    const response = await postJson(
      apiUrl(
        activeSession.apiBaseUrl,
        `/time-tracking/sessions/${activeSession.sessionId}/heartbeat`
      ),
      activeSession.token,
      { buildHash: await getBuildHash() }
    );
    if (anchorTrustedClock(response?.data?.serverNow)) releaseClockHold();
  } catch (err) {
    if (isNetworkError(err)) {
      markOffline(err);
      return;
    }
    if (isSessionGoneError(err)) {
      clearLocalSession('Resumed session is no longer active on server');
    } else {
      console.warn('validateResumedSession:', err.message);
    }
  }
}

/**
 * Chrome's private-network preflight (public HTTPS → 127.0.0.1) must
 * get Access-Control-Allow-Private-Network: true. Reflect Origin when
 * the browser sends one so the CORS check matches that site.
 */
function corsHeaders(req) {
  const origin = req?.headers?.origin;
  const allowOrigin =
    typeof origin === 'string' && /^https?:\/\/[^/\s]+$/i.test(origin)
      ? origin
      : '*';
  const requested = req?.headers?.['access-control-request-headers'];
  const allowHeaders =
    typeof requested === 'string' && /^[, \w-]+$/.test(requested)
      ? requested
      : 'Content-Type, Authorization';
  return {
    'Access-Control-Allow-Origin': allowOrigin,
    'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
    'Access-Control-Allow-Headers': allowHeaders,
    'Access-Control-Allow-Private-Network': 'true',
    Vary: 'Origin, Access-Control-Request-Headers, Access-Control-Request-Private-Network',
  };
}

function sendJson(res, status, body, req) {
  const payload = JSON.stringify(body);
  res.writeHead(status, {
    'Content-Type': 'application/json',
    ...corsHeaders(req),
    'Content-Length': Buffer.byteLength(payload),
  });
  res.end(payload);
}

function readBody(req) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    req.on('data', (c) => chunks.push(c));
    req.on('end', () => {
      const raw = Buffer.concat(chunks).toString('utf8');
      if (!raw) return resolve({});
      try {
        resolve(JSON.parse(raw));
      } catch (err) {
        reject(err);
      }
    });
    req.on('error', reject);
  });
}

function createLocalServer() {
  server = http.createServer(async (req, res) => {
    // Chrome LNA/PNA sends OPTIONS before GET/POST. Answer it immediately
    // with Content-Length: 0 so Node does not chunk the 204 (Chrome drops those).
    if (req.method === 'OPTIONS') {
      res.writeHead(204, {
        ...corsHeaders(req),
        'Content-Length': '0',
      });
      res.end();
      return;
    }

    const url = req.url || '/';

    try {
      if (req.method === 'GET' && url.startsWith('/status')) {
        if (!activeSession) {
          readIdle();
        }
        sendJson(
          res,
          200,
          {
            ok: true,
            running: true,
            sessionActive: Boolean(activeSession),
            sessionId: activeSession?.sessionId || null,
            version: AGENT_VERSION,
            idleThresholdSec: activeSession?.idleThresholdSec || null,
            lastIdleSec,
            lastIdleState,
          },
          req
        );
        return;
      }

      if (req.method === 'POST' && url.startsWith('/start')) {
        const body = await readBody(req);
        if (!consumeHandshake('start', body.handshake)) {
          sendJson(res, 401, { success: false, message: 'Handshake rejected' }, req);
          return;
        }
        const result = await startSession(body);
        sendJson(res, 200, { success: true, ...result }, req);
        return;
      }

      if (req.method === 'POST' && url.startsWith('/preflight')) {
        const body = await readBody(req);
        if (!consumeHandshake('preflight', body.handshake)) {
          sendJson(res, 401, { success: false, message: 'Handshake rejected' }, req);
          return;
        }
        const result = await runPreflight(body);
        sendJson(res, 200, { success: true, ...result }, req);
        return;
      }

      if (req.method === 'POST' && url.startsWith('/stop')) {
        const body = await readBody(req);
        if (!consumeHandshake('stop', body.handshake)) {
          sendJson(res, 401, { success: false, message: 'Handshake rejected' }, req);
          return;
        }
        const result = await stopSession();
        sendJson(res, 200, { success: true, ...result }, req);
        return;
      }

      sendJson(res, 404, { success: false, message: 'Not found' }, req);
    } catch (err) {
      sendJson(
        res,
        err.status || 500,
        {
          success: false,
          message: err.message || 'Internal error',
        },
        req
      );
    }
  });

  server.on('error', (err) => {
    console.error('App agent listen failed:', err.message);
    const detail =
      err.code === 'EADDRINUSE'
        ? `Port ${AGENT_PORT} is already in use. Quit any other Productivity App / old tracker, then relaunch.`
        : err.message;
    dialog
      .showMessageBox({
        type: 'error',
        title: 'Productivity App',
        message: 'Local agent could not start',
        detail,
      })
      .catch(() => undefined);
  });

  server.listen(AGENT_PORT, '127.0.0.1', () => {
    console.log(`App agent listening on http://127.0.0.1:${AGENT_PORT}`);
  });
}

/**
 * Install a downloaded update. Must not hit before-quit preventDefault or
 * electron-updater cancels quitAndInstall (app stays on old version).
 */
async function installDownloadedUpdate() {
  if (activeSession) {
    try {
      stopMonitoringTimers();
      await flushTicks();
    } catch {
      // ignore — marker kept so session resumes after relaunch
    }
  }
  allowQuitForUpdate = true;
  quitFlushDone = true;
  isQuitting = true;
  // Defer so dialog/tray handlers finish before quit
  setImmediate(() => {
    autoUpdater.quitAndInstall(false, true);
  });
}

function setupAutoUpdater() {
  if (!app.isPackaged) return;

  autoUpdater.autoDownload = true;
  // Packaged builds often never quit (no tray Quit) — still useful if OS logs out.
  autoUpdater.autoInstallOnAppQuit = true;

  autoUpdater.on('error', (err) => {
    console.warn('[updater]', err?.message || err);
  });

  autoUpdater.on('update-downloaded', (info) => {
    const ver = info?.version || 'new';
    pendingUpdateVersion = ver;
    refreshTrayMenu();
    dialog
      .showMessageBox({
        type: 'info',
        buttons: ['Restart now', 'Later'],
        defaultId: 0,
        cancelId: 1,
        title: 'Update ready',
        message: `Productivity App ${ver} is ready to install.`,
        detail:
          'The app must restart to finish installing.',
      })
      .then(({ response }) => {
        if (response === 0) {
          void installDownloadedUpdate();
        }
      })
      .catch(() => {});
  });

  const check = () => {
    autoUpdater.checkForUpdates().catch((err) => {
      console.warn('[updater] check failed:', err?.message || err);
    });
  };

  check();
  setInterval(check, UPDATE_CHECK_INTERVAL_MS);
}

function refreshTrayMenu() {
  if (!tray) return;
  const monitoring = Boolean(activeSession);
  /** @type {Electron.MenuItemConstructorOptions[]} */
  const items = [
    {
      label: monitoring ? 'Status: Tracking' : 'Status: Ready',
      enabled: false,
    },
    {
      label: `Version ${AGENT_VERSION}`,
      enabled: false,
    },
    {
      label: 'Open',
      click: () => showConnectedWindow(),
    },
  ];

  if (app.isPackaged) {
    if (pendingUpdateVersion) {
      items.push({
        label: `Restart to install v${pendingUpdateVersion}`,
        click: () => {
          void installDownloadedUpdate();
        },
      });
    }
    items.push({
      label: 'Check for updates',
      click: () => {
        const onAvailable = (info) => {
          cleanup();
          dialog.showMessageBox({
            type: 'info',
            message: 'Update available',
            detail: `Version ${info?.version || ''} is downloading.`,
          });
        };
        const onNotAvailable = () => {
          cleanup();
          if (pendingUpdateVersion) {
            dialog
              .showMessageBox({
                type: 'info',
                buttons: ['Restart now', 'Later'],
                defaultId: 0,
                cancelId: 1,
                message: 'Update already downloaded',
                detail: `Version ${pendingUpdateVersion} is ready. Restart to install.`,
              })
              .then(({ response }) => {
                if (response === 0) void installDownloadedUpdate();
              })
              .catch(() => {});
            return;
          }
          dialog.showMessageBox({
            type: 'info',
            message: 'You are up to date',
            detail: `Current version: ${AGENT_VERSION}`,
          });
        };
        const onError = (err) => {
          cleanup();
          dialog.showMessageBox({
            type: 'warning',
            message: 'Could not check for updates',
            detail: String(err?.message || err),
          });
        };
        const cleanup = () => {
          autoUpdater.removeListener('update-available', onAvailable);
          autoUpdater.removeListener('update-not-available', onNotAvailable);
          autoUpdater.removeListener('error', onError);
        };
        autoUpdater.once('update-available', onAvailable);
        autoUpdater.once('update-not-available', onNotAvailable);
        autoUpdater.once('error', onError);
        autoUpdater.checkForUpdates().catch(onError);
      },
    });
  }

  // Installed builds: no Quit — app is a background agent (login item).
  // Dev (`npm start`) keeps Quit so you can stop the process.
  if (canUserQuit()) {
    items.push({ type: 'separator' });
    items.push({
      label: 'Quit',
      click: async () => {
        if (activeSession) {
          const { response } = await dialog.showMessageBox({
            type: 'warning',
            buttons: ['Keep running', 'Quit'],
            defaultId: 0,
            cancelId: 0,
            title: 'Quit App?',
            message:
              'You are still being tracked for an open check-in. Quitting stops monitoring until you open the app again.',
            detail:
              'Check-out in HRMS needs this app running. If you quit, open it again before check-out, or ask HR to force-close the app.',
          });
          if (response !== 1) return;
        }
        app.quit();
      },
    });
  }

  tray.setToolTip(
    monitoring ? 'Productivity App Running' : 'Productivity App — Ready'
  );
  tray.setContextMenu(Menu.buildFromTemplate(items));
}

function createTray() {
  // 16x16 green dot so the tray icon is visible
  const size = 16;
  const canvas = Buffer.alloc(size * size * 4);
  for (let y = 0; y < size; y += 1) {
    for (let x = 0; x < size; x += 1) {
      const dx = x - 7.5;
      const dy = y - 7.5;
      const inside = dx * dx + dy * dy <= 5.5 * 5.5;
      const i = (y * size + x) * 4;
      if (inside) {
        canvas[i] = 34;
        canvas[i + 1] = 197;
        canvas[i + 2] = 94;
        canvas[i + 3] = 255;
      }
    }
  }
  const image = nativeImage.createFromBuffer(canvas, {
    width: size,
    height: size,
  });
  if (process.platform === 'darwin') {
    image.setTemplateImage(false);
  }
  tray = new Tray(image);
  refreshTrayMenu();
  tray.on('click', () => {
    showConnectedWindow();
  });
  tray.on('double-click', () => {
    showConnectedWindow();
  });
}

function connectedPageHtml() {
  return `<!doctype html>
<html><head><meta charset="utf-8"><title>Productivity App</title>
<style>
  html, body { margin: 0; height: 100%; }
  body {
    display: flex;
    flex-direction: column;
    align-items: center;
    justify-content: center;
    gap: 8px;
    background: #0b1220;
    font-family: system-ui, -apple-system, sans-serif;
    color: #e2e8f0;
  }
  button {
    border: 0;
    border-radius: 999px;
    padding: 12px 28px;
    font-size: 15px;
    font-weight: 600;
    color: #052e16;
    background: #4ade80;
    cursor: default;
  }
  p { margin: 0; font-size: 12px; color: #94a3b8; text-align: center; max-width: 200px; }
</style></head>
<body>
  <button type="button" disabled>Connected</button>
</body></html>`;
}

function createWindow() {
  mainWindow = new BrowserWindow({
    width: 260,
    height: 160,
    show: false,
    resizable: false,
    maximizable: false,
    minimizable: false,
    fullscreenable: false,
    title: 'Connected',
    autoHideMenuBar: true,
    skipTaskbar: true,
    webPreferences: {
      nodeIntegration: false,
      contextIsolation: true,
    },
  });
  mainWindow.loadURL(
    `data:text/html;charset=utf-8,${encodeURIComponent(connectedPageHtml())}`
  );
  mainWindow.on('close', (event) => {
    if (!isQuitting) {
      event.preventDefault();
      mainWindow.hide();
    }
  });
}

function showConnectedWindow() {
  if (!mainWindow) createWindow();
  mainWindow.show();
  mainWindow.focus();
}

app.whenReady().then(async () => {
  if (!gotSingleInstanceLock) return;

  try {
    app.setLoginItemSettings({ openAtLogin: true });
  } catch (err) {
    console.warn('setLoginItemSettings failed:', err.message);
  }

  // Background agent: no dock icon on macOS (tray only)
  if (process.platform === 'darwin' && app.dock) {
    app.dock.hide();
  }

  // No app menu Quit path on packaged builds (tray has no Quit either)
  if (!canUserQuit() && process.platform === 'darwin') {
    Menu.setApplicationMenu(null);
  }

  try {
    ledger = openLedger(ledgerFile(), loadOrCreateLedgerKey());
    importLegacyFiles();
  } catch (err) {
    console.error('Ledger failed to open:', err.message);
  }

  createLocalServer();
  createWindow();
  try {
    createTray();
  } catch (err) {
    console.warn('Tray unavailable:', err.message);
  }

  const marker = loadSessionMarker();
  if (marker?.sessionId && marker?.token && marker?.apiBaseUrl) {
    activeSession = {
      sessionId: String(marker.sessionId),
      token: String(marker.token),
      apiBaseUrl: String(marker.apiBaseUrl),
      idleThresholdSec: Math.max(
        60,
        Number(marker.idleThresholdSec) || 300
      ),
      signingKey: String(marker.signingKey || ''),
    };
    console.log('Resuming active session', activeSession.sessionId);
    clockWritesBlocked = true;
    startMonitoring();
    await validateResumedSession();
  } else {
    refreshTrayMenu();
  }

  setupAutoUpdater();
});

app.on('window-all-closed', (e) => {
  e.preventDefault();
});

app.on('before-quit', (e) => {
  // quitAndInstall relies on this quit completing — do not cancel it.
  if (allowQuitForUpdate) {
    if (server) {
      try {
        server.close();
      } catch {
        // ignore
      }
    }
    return;
  }

  if (quitFlushDone) return;
  isQuitting = true;

  // Ensure pending ticks flush before process exits (tray Quit / OS quit)
  if (activeSession) {
    e.preventDefault();
    (async () => {
      try {
        stopMonitoringTimers();
        await flushTicks();
      } catch {
        // ignore
      } finally {
        quitFlushDone = true;
        if (ledger) {
          try {
            ledger.close();
          } catch {
            // ignore
          }
          ledger = null;
        }
        if (server) {
          try {
            server.close();
          } catch {
            // ignore
          }
        }
        app.quit();
      }
    })();
    return;
  }

  quitFlushDone = true;
  if (ledger) {
    try {
      ledger.close();
    } catch {
      // ignore
    }
    ledger = null;
  }
  if (server) {
    try {
      server.close();
    } catch {
      // ignore
    }
  }
});
