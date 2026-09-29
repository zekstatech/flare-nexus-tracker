/**
 * Flare Nexus desktop productivity tracker (MVP).
 * Local HTTP on 127.0.0.1:17345 — status / start / stop.
 * Idle detection via Electron powerMonitor.getSystemIdleTime().
 * No screenshots in MVP.
 */

const {
  app,
  BrowserWindow,
  powerMonitor,
  Tray,
  Menu,
  nativeImage,
  dialog,
} = require('electron');
const { autoUpdater } = require('electron-updater');
const http = require('http');
const fs = require('fs');
const path = require('path');

const AGENT_PORT = Number(process.env.TRACKER_AGENT_PORT || 17345);
const AGENT_VERSION = require('./package.json').version;
const SAMPLE_INTERVAL_MS = 5 * 1000;
const FLUSH_INTERVAL_MS = 30 * 1000;
const HEARTBEAT_INTERVAL_MS = 2 * 60 * 1000;
const UPDATE_CHECK_INTERVAL_MS = 4 * 60 * 60 * 1000;

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
 *   idleThresholdSec: number
 * }} */
let activeSession = null;

/** @type {{ minute_ts: string, is_active: boolean, mouse_events: number, key_events: number }[]} */
let pendingTicks = [];

/** Current minute bucket being accumulated from samples. */
let currentBucket = null;

let lastIdleSec = 0;
let lastIdleState = 'unknown';
let lastSampleAt = 0;

let sampleTimer = null;
let flushTimer = null;
let heartbeatTimer = null;

function sessionStorePath() {
  return path.join(app.getPath('userData'), 'active-session.json');
}

function clearLocalSession(reason) {
  if (reason) console.warn('[session]', reason);
  stopMonitoringTimers();
  activeSession = null;
  pendingTicks = [];
  currentBucket = null;
  saveSessionMarker();
  refreshTrayMenu();
}

function isSessionGoneError(err) {
  const msg = String(err?.message || '');
  return msg.includes('HTTP 404') || msg.includes('HTTP 409');
}

function saveSessionMarker() {
  if (!activeSession) {
    try {
      fs.unlinkSync(sessionStorePath());
    } catch {
      // ignore
    }
    return;
  }
  fs.writeFileSync(
    sessionStorePath(),
    JSON.stringify(activeSession, null, 2),
    'utf8'
  );
}

function loadSessionMarker() {
  try {
    const raw = fs.readFileSync(sessionStorePath(), 'utf8');
    return JSON.parse(raw);
  } catch {
    return null;
  }
}

function apiUrl(base, suffix) {
  const root = String(base || '').replace(/\/$/, '');
  const pathPart = suffix.startsWith('/') ? suffix : `/${suffix}`;
  return `${root}${pathPart}`;
}

async function postJson(url, token, body) {
  const res = await fetch(url, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      Authorization: `Bearer ${token}`,
    },
    body: JSON.stringify(body),
  });
  if (!res.ok) {
    const text = await res.text().catch(() => '');
    throw new Error(`HTTP ${res.status}: ${text.slice(0, 200)}`);
  }
  return res.json().catch(() => ({}));
}

function minuteKey(date = new Date()) {
  const minute = new Date(date);
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

function flushCurrentBucket() {
  if (!currentBucket) return;
  pendingTicks.push({
    minute_ts: currentBucket.key,
    is_active: currentBucket.sawActive,
    mouse_events: 0,
    key_events: 0,
  });
  if (pendingTicks.length > 500) {
    pendingTicks = pendingTicks.slice(-250);
  }
  console.log(
    `[tick] ${currentBucket.key} active=${currentBucket.sawActive} samples=${currentBucket.samples} lastIdle=${lastIdleSec}s state=${lastIdleState}`
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
    pendingTicks.push({
      minute_ts: new Date(t).toISOString(),
      is_active: false,
      mouse_events: 0,
      key_events: 0,
    });
    filled += 1;
  }
  if (filled > 0) {
    console.log(`[gap] backfilled ${filled} idle minute(s) for sleep/suspend`);
    if (pendingTicks.length > 500) {
      pendingTicks = pendingTicks.slice(-250);
    }
  }
}

/**
 * Sample every few seconds. A minute bucket is active if any sample in that
 * minute saw the user as not-idle; otherwise the whole minute is idle.
 */
function sampleActivity() {
  if (!activeSession) return;

  const now = Date.now();
  // Laptop sleep / suspended process: timers pause, so backfill the gap as idle
  if (lastSampleAt > 0 && now - lastSampleAt > 90 * 1000) {
    flushCurrentBucket();
    backfillIdleGap(lastSampleAt, now);
  }
  lastSampleAt = now;

  const threshold = activeSession.idleThresholdSec || 300;
  const { idleSec, state } = readIdle();
  const idle = isIdleNow(idleSec, state, threshold);
  const key = minuteKey();

  if (!currentBucket || currentBucket.key !== key) {
    flushCurrentBucket();
    currentBucket = {
      key,
      sawActive: !idle,
      samples: 1,
    };
    return;
  }

  currentBucket.samples += 1;
  if (!idle) {
    currentBucket.sawActive = true;
  }
}

async function flushTicks() {
  // Include in-progress minute so the UI updates during long idle stretches
  if (currentBucket) {
    const snapshot = {
      minute_ts: currentBucket.key,
      is_active: currentBucket.sawActive,
      mouse_events: 0,
      key_events: 0,
    };
    const already = pendingTicks.find((t) => t.minute_ts === snapshot.minute_ts);
    if (already) {
      already.is_active = snapshot.is_active || already.is_active;
    } else {
      pendingTicks.push(snapshot);
    }
  }

  if (!activeSession || pendingTicks.length === 0) return;
  const ticks = pendingTicks.splice(0, pendingTicks.length);
  try {
    await postJson(
      apiUrl(
        activeSession.apiBaseUrl,
        `/time-tracking/sessions/${activeSession.sessionId}/activity-ticks`
      ),
      activeSession.token,
      { ticks }
    );
  } catch (err) {
    if (isSessionGoneError(err)) {
      clearLocalSession('Session no longer active — clearing local app session');
      return;
    }
    console.error('flushTicks failed, re-queueing:', err.message);
    pendingTicks = ticks.concat(pendingTicks);
  }
}

async function sendHeartbeat() {
  if (!activeSession) return;
  try {
    await postJson(
      apiUrl(
        activeSession.apiBaseUrl,
        `/time-tracking/sessions/${activeSession.sessionId}/heartbeat`
      ),
      activeSession.token,
      {}
    );
  } catch (err) {
    if (isSessionGoneError(err)) {
      clearLocalSession('Heartbeat: session closed on server');
      return;
    }
    console.error('heartbeat failed:', err.message);
  }
}

function startMonitoring() {
  stopMonitoringTimers();
  currentBucket = null;
  lastSampleAt = Date.now();
  sampleActivity();
  sampleTimer = setInterval(sampleActivity, SAMPLE_INTERVAL_MS);
  flushTimer = setInterval(() => {
    flushTicks().catch(() => undefined);
  }, FLUSH_INTERVAL_MS);
  heartbeatTimer = setInterval(() => {
    sendHeartbeat().catch(() => undefined);
  }, HEARTBEAT_INTERVAL_MS);
  sendHeartbeat().catch(() => undefined);

  const onResume = () => {
    console.log('[power] resume/unlock — sampling after possible sleep');
    sampleActivity();
    flushTicks().catch(() => undefined);
  };
  powerMonitor.removeAllListeners('resume');
  powerMonitor.removeAllListeners('unlock-screen');
  powerMonitor.on('resume', onResume);
  powerMonitor.on('unlock-screen', onResume);
  refreshTrayMenu();
}

function stopMonitoringTimers() {
  if (sampleTimer) clearInterval(sampleTimer);
  if (flushTimer) clearInterval(flushTimer);
  if (heartbeatTimer) clearInterval(heartbeatTimer);
  sampleTimer = null;
  flushTimer = null;
  heartbeatTimer = null;
  flushCurrentBucket();
}

async function startSession(payload) {
  if (!payload?.sessionId || !payload?.token || !payload?.apiBaseUrl) {
    const err = new Error('sessionId, token, and apiBaseUrl are required');
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
  };

  // Same session already running (e.g. after quit/resume) — refresh creds, stay up
  if (activeSession?.sessionId === next.sessionId) {
    activeSession = next;
    saveSessionMarker();
    if (!sampleTimer) startMonitoring();
    return { started: true, resumed: true, sessionId: activeSession.sessionId };
  }

  // Different session still marked active — flush/clear, then start the new one
  if (activeSession) {
    await flushTicks().catch(() => undefined);
    stopMonitoringTimers();
    activeSession = null;
    pendingTicks = [];
    saveSessionMarker();
  }

  activeSession = next;
  pendingTicks = [];
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

/** After relaunch: drop marker if server already closed the session. */
async function validateResumedSession() {
  if (!activeSession) return;
  try {
    await postJson(
      apiUrl(
        activeSession.apiBaseUrl,
        `/time-tracking/sessions/${activeSession.sessionId}/heartbeat`
      ),
      activeSession.token,
      {}
    );
  } catch (err) {
    if (isSessionGoneError(err)) {
      clearLocalSession('Resumed session is no longer active on server');
    } else {
      console.warn('validateResumedSession:', err.message);
    }
  }
}

/** CORS + Private/Local Network Access so HTTPS HRMS can reach 127.0.0.1 */
function corsHeaders() {
  return {
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type, Authorization',
    // Required for Chrome PNA preflights (and harmless under LNA).
    'Access-Control-Allow-Private-Network': 'true',
  };
}

function sendJson(res, status, body) {
  const payload = JSON.stringify(body);
  res.writeHead(status, {
    'Content-Type': 'application/json',
    ...corsHeaders(),
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
    if (req.method === 'OPTIONS') {
      res.writeHead(204, corsHeaders());
      res.end();
      return;
    }

    const url = req.url || '/';

    try {
      if (req.method === 'GET' && url.startsWith('/status')) {
        if (!activeSession) {
          readIdle();
        }
        sendJson(res, 200, {
          ok: true,
          running: true,
          sessionActive: Boolean(activeSession),
          sessionId: activeSession?.sessionId || null,
          version: AGENT_VERSION,
          idleThresholdSec: activeSession?.idleThresholdSec || null,
          lastIdleSec,
          lastIdleState,
        });
        return;
      }

      if (req.method === 'POST' && url.startsWith('/start')) {
        const body = await readBody(req);
        const result = await startSession(body);
        sendJson(res, 200, { success: true, ...result });
        return;
      }

      if (req.method === 'POST' && url.startsWith('/stop')) {
        const result = await stopSession();
        sendJson(res, 200, { success: true, ...result });
        return;
      }

      sendJson(res, 404, { success: false, message: 'Not found' });
    } catch (err) {
      sendJson(res, err.status || 500, {
        success: false,
        message: err.message || 'Internal error',
      });
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

function setupAutoUpdater() {
  if (!app.isPackaged) return;

  autoUpdater.autoDownload = true;
  autoUpdater.autoInstallOnAppQuit = true;

  autoUpdater.on('error', (err) => {
    console.warn('[updater]', err?.message || err);
  });

  autoUpdater.on('update-downloaded', (info) => {
    const ver = info?.version || 'new';
    dialog
      .showMessageBox({
        type: 'info',
        buttons: ['Restart now', 'Later'],
        defaultId: 0,
        cancelId: 1,
        title: 'Update ready',
        message: `Productivity App ${ver} is ready to install.`,
        detail: 'Restart to finish the update. Tracking will resume after relaunch if a session is open.',
      })
      .then(({ response }) => {
        if (response === 0) {
          autoUpdater.quitAndInstall(false, true);
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
  <p>Keep this app running. In Chrome, allow local network access when HRMS asks.</p>
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
    };
    console.log('Resuming active session', activeSession.sessionId);
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
  if (server) {
    try {
      server.close();
    } catch {
      // ignore
    }
  }
});
