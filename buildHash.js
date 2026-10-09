/**
 * One SHA-256 over the packaged app payload:
 * resources/app.asar, then every file under resources/app.asar.unpacked
 * (native .node addons live there). Paths are sorted and hashed as
 * forward-slash names so macOS, Windows, and Linux produce the same
 * digest for the same bytes.
 */
const crypto = require('crypto');
const path = require('path');
// Electron patches fs so app.asar is an archive, not a file. Reading it
// that way throws "ENOENT, … not found in …/app.asar" during check-in.
// original-fs is the real filesystem. Plain Node (the release hash script)
// does not have that module.
let fs;
try {
  fs = require('original-fs');
} catch {
  fs = require('fs');
}

function relativePosix(root, file) {
  return path.relative(root, file).split(path.sep).join('/');
}

function listFiles(dir, found = []) {
  if (!fs.existsSync(dir)) return found;
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) listFiles(full, found);
    else if (entry.isFile()) found.push(full);
  }
  return found;
}

function workspaceFiles(resourcesDir) {
  const files = [];
  const asar = path.join(resourcesDir, 'app.asar');
  if (fs.existsSync(asar)) files.push(asar);
  files.push(...listFiles(path.join(resourcesDir, 'app.asar.unpacked')));
  files.sort((a, b) =>
    relativePosix(resourcesDir, a).localeCompare(relativePosix(resourcesDir, b))
  );
  return files;
}

function hashFileInto(hash, resourcesDir, file) {
  return new Promise((resolve, reject) => {
    hash.update(relativePosix(resourcesDir, file));
    hash.update('\0');
    const stream = fs.createReadStream(file);
    stream.on('error', reject);
    stream.on('data', (chunk) => hash.update(chunk));
    stream.on('end', () => {
      hash.update('\0');
      resolve();
    });
  });
}

async function hashResources(resourcesDir) {
  const hash = crypto.createHash('sha256');
  const files = workspaceFiles(resourcesDir);
  if (files.length === 0) {
    throw new Error(`No app.asar under ${resourcesDir}`);
  }
  for (const file of files) {
    await hashFileInto(hash, resourcesDir, file);
  }
  return hash.digest('hex');
}

function hashDevSources(root) {
  const hash = crypto.createHash('sha256');
  for (const name of ['package.json', 'main.js', 'ledger.js', 'buildHash.js']) {
    hash.update(name);
    hash.update('\0');
    hash.update(fs.readFileSync(path.join(root, name)));
    hash.update('\0');
  }
  return hash.digest('hex');
}

module.exports = {
  hashResources,
  hashDevSources,
  workspaceFiles,
};
