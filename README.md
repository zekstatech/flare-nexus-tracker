# Flare Nexus Tracker

Electron desktop agent for Flare / Hubanix HRMS productivity monitoring.

Pairs with the HRMS time-tracking module (`flare-human-nexus` → `plans/time-tracking-monitoring.md`).

## MVP behavior

- Runs in the **background** (tray; dock hidden on macOS; opens at login)
- **Single instance** — launching again focuses the existing app
- **Installed builds: no Quit** in the tray (background agent). Closing the window only hides it. Dev (`npm start`) still has Quit. Override with `TRACKER_ALLOW_QUIT=0|1`.
- Local HTTP on `http://127.0.0.1:17345`
  - `GET /status` — agent running + whether a session is active (+ `version`)
  - `POST /start` — `{ sessionId, token, apiBaseUrl, idleThresholdSec }`
  - `POST /stop` — flush activity ticks and clear session
- Tray: status, version, Open, Check for updates (packaged), Quit in dev
- **Auto-update** via GitHub Releases (`electron-updater`) when packaged
- Stays **dormant** until the HRMS web app starts a session after check-in
- Per-minute active/idle buckets via Electron `powerMonitor.getSystemIdleTime()`
- Batch upload + heartbeat to `/api/time-tracking/...`
- Persists an active-session marker and **auto-resumes** after reboot / relaunch
- Validates resumed session against the API (clears marker if server already closed it)
- No screenshots in MVP

## Use cases (installed app)

| Situation | Behavior |
|-----------|----------|
| App not running → Check-in | Blocked — must launch tracker first |
| App running, Ready → Check-in | Creates server session + agent starts Tracking |
| Tracking → Check-out | Agent flushes + stops, then attendance check-out |
| Tray **Quit** while Tracking | **Installed:** no Quit in tray (stays background). **Dev:** confirm + flush; marker kept |
| Close window / Connected UI | Hides only — app keeps running |
| Relaunch after Quit (same day, session still open) | Auto-resumes Tracking |
| Relaunch after auto-checkout / day rollover | Heartbeat fails → clears marker → Ready |
| Quit then Check-out without relaunch | Allowed — attendance closes; productivity may miss last minutes |
| Soft auto-checkout at shift end | Server stops productivity session; agent clears on next sync/flush |
| Check-in again same day (resume) | New productivity session from resume time |
| Double-click app while already running | Focuses existing instance (no second agent) |
| PC restart | Login item starts app; resumes open session if still valid |
| Force-quit / crash | Marker kept; relaunch resumes; pending ticks may be lost |
| New GitHub Release | Auto-update downloads; tray **Check for updates**; HRMS can also raise `min_agent_version` to block punch until upgraded |

## Run

```bash
npm install
npm start
```

### Package installers

```bash
npm run dist:mac      # → release/Productivity-App-mac.dmg (+ zip for updater)
npm run dist:win      # → release/Productivity-App-win.exe
npm run dist:linux    # → release/Productivity-App-linux.AppImage
```

### Publish (GitHub Releases)

You do **not** create the release by hand in the GitHub UI for each ship.

1. Bump `"version"` in `package.json` (e.g. `0.1.4`)
2. Commit + push `main`
3. Tag and push the same version:

```bash
git tag v0.1.4
git push origin v0.1.4
```

CI builds mac/win/linux and publishes a **non-draft** Release. When Actions is green:

- https://github.com/zekstatech/flare-nexus-tracker/releases/latest/download/Productivity-App-mac.dmg
- https://github.com/zekstatech/flare-nexus-tracker/releases/latest/download/Productivity-App-win.exe
- https://github.com/zekstatech/flare-nexus-tracker/releases/latest/download/Productivity-App-linux.AppImage

If the repo is **private**, unauthenticated `/latest/download/...` returns **404**. Make the repo (or at least release assets) public for employee downloads and auto-update.

Install UI in HRMS: `/tracker-install`

Optional: `TRACKER_AGENT_PORT=17345 npm start`  
`TRACKER_ALLOW_QUIT=0` simulates packaged “no Quit” tray.
