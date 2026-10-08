/**
 * Print the workspace SHA-256 for every packaged Resources directory.
 * The digest covers app.asar and app.asar.unpacked (native .node files).
 * Paste the hashes into PRODUCTIVITY_AGENT_ASAR_SHA256 on the API.
 */
const fs = require('fs');
const path = require('path');
const { hashResources } = require('./buildHash');

function findResourceDirs(dir, found) {
  if (!fs.existsSync(dir)) return;
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    const full = path.join(dir, entry.name);
    if (!entry.isDirectory()) continue;
    if (entry.name === 'resources' && fs.existsSync(path.join(full, 'app.asar'))) {
      found.push(full);
      continue;
    }
    findResourceDirs(full, found);
  }
}

async function main() {
  const root = path.join(__dirname, 'release');
  const dirs = [];
  findResourceDirs(root, dirs);
  if (dirs.length === 0) {
    console.error(`No packaged Resources directory under ${root}`);
    process.exit(1);
  }
  const lines = [];
  for (const dir of dirs) {
    const hash = await hashResources(dir);
    const line = `${hash}  ${path.relative(__dirname, dir)}`;
    lines.push(line);
  }
  const out = process.argv[2];
  if (out) fs.writeFileSync(out, `${lines.join('\n')}\n`);
}

main().catch((err) => {
  console.error(err.message);
  process.exit(1);
});
