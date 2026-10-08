/**
 * Upload one build-hash file onto the GitHub release for this tag.
 * gh release upload fails here: PowerShell does not expand GITHUB_REF_NAME,
 * and the Mac runner's gh client sends a Content-Length GitHub rejects.
 */
const fs = require('fs');
const https = require('https');

function request(options, body) {
  return new Promise((resolve, reject) => {
    const req = https.request(options, (res) => {
      const chunks = [];
      res.on('data', (chunk) => chunks.push(chunk));
      res.on('end', () => {
        const text = Buffer.concat(chunks).toString('utf8');
        if (res.statusCode < 200 || res.statusCode >= 300) {
          reject(new Error(`HTTP ${res.statusCode}: ${text.slice(0, 300)}`));
          return;
        }
        resolve(text ? JSON.parse(text) : null);
      });
    });
    req.on('error', reject);
    if (body) req.end(body);
    else req.end();
  });
}

async function main() {
  const token = process.env.GH_TOKEN;
  const repo = process.env.GITHUB_REPOSITORY;
  const tag = process.env.GITHUB_REF_NAME;
  const name = process.argv[2];
  if (!token || !repo || !tag || !name) {
    throw new Error('GH_TOKEN, GITHUB_REPOSITORY, GITHUB_REF_NAME, and a filename are required');
  }
  const file = fs.readFileSync(name);
  const headers = {
    Authorization: `Bearer ${token}`,
    Accept: 'application/vnd.github+json',
    'User-Agent': 'flare-nexus-tracker-release',
  };
  const release = await request({
    host: 'api.github.com',
    path: `/repos/${repo}/releases/tags/${encodeURIComponent(tag)}`,
    headers,
  });
  const assets = await request({
    host: 'api.github.com',
    path: `/repos/${repo}/releases/${release.id}/assets`,
    headers,
  });
  for (const asset of assets || []) {
    if (asset.name !== name) continue;
    await request({
      host: 'api.github.com',
      method: 'DELETE',
      path: `/repos/${repo}/releases/assets/${asset.id}`,
      headers,
    });
  }
  await request(
    {
      host: 'uploads.github.com',
      method: 'POST',
      path: `/repos/${repo}/releases/${release.id}/assets?name=${encodeURIComponent(name)}`,
      headers: {
        ...headers,
        'Content-Type': 'text/plain',
        'Content-Length': file.length,
      },
    },
    file
  );
  console.log(`Uploaded ${name} (${file.length} bytes) to ${tag}`);
}

main().catch((err) => {
  console.error(err.message);
  process.exit(1);
});
