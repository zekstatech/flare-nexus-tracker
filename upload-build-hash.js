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
        let json = null;
        if (text) {
          try {
            json = JSON.parse(text);
          } catch {
            json = null;
          }
        }
        resolve({ status: res.statusCode, json, text });
      });
    });
    req.on('error', reject);
    if (body) req.end(body);
    else req.end();
  });
}

function assertOk(res) {
  if (res.status < 200 || res.status >= 300) {
    throw new Error(`HTTP ${res.status}: ${(res.text || '').slice(0, 300)}`);
  }
  return res.json;
}

async function releaseForTag(repo, tag, headers) {
  const byTag = await request({
    host: 'api.github.com',
    path: `/repos/${repo}/releases/tags/${encodeURIComponent(tag)}`,
    headers,
  });
  if (byTag.status === 200) return byTag.json;
  if (byTag.status !== 404) assertOk(byTag);

  const listed = assertOk(await request({
    host: 'api.github.com',
    path: `/repos/${repo}/releases?per_page=100`,
    headers,
  }));
  const found = (listed || []).find((item) => item.tag_name === tag);
  if (found) return found;

  const created = await request(
    {
      host: 'api.github.com',
      method: 'POST',
      path: `/repos/${repo}/releases`,
      headers: { ...headers, 'Content-Type': 'application/json' },
    },
    JSON.stringify({ tag_name: tag, name: tag, draft: false })
  );
  if (created.status === 422) {
    const again = assertOk(await request({
      host: 'api.github.com',
      path: `/repos/${repo}/releases?per_page=100`,
      headers,
    }));
    const retry = (again || []).find((item) => item.tag_name === tag);
    if (retry) return retry;
  }
  return assertOk(created);
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
  const release = await releaseForTag(repo, tag, headers);
  const assets = assertOk(await request({
    host: 'api.github.com',
    path: `/repos/${repo}/releases/${release.id}/assets`,
    headers,
  }));
  for (const asset of assets || []) {
    if (asset.name !== name) continue;
    assertOk(await request({
      host: 'api.github.com',
      method: 'DELETE',
      path: `/repos/${repo}/releases/assets/${asset.id}`,
      headers,
    }));
  }
  assertOk(await request(
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
  ));
  console.log(`Uploaded ${name} (${file.length} bytes) to ${tag}`);
}

main().catch((err) => {
  console.error(err.message);
  process.exit(1);
});
