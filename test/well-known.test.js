// Microsoft's publisher-domain verification file must always reach the app:
// the verifier is a server-side fetch from Azure with an undocumented (maybe
// empty) User-Agent, so the empty-UA hard block would otherwise refuse it and
// the app registration's publisher domain could not be verified.

const { test, before, after } = require('node:test');
const assert = require('node:assert');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const http = require('node:http');

const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'bb-well-known-'));
process.env.LOG_DIR = path.join(tmp, 'logs');
process.env.GEODB_DIR = path.join(tmp, 'no-geodb');
fs.mkdirSync(process.env.LOG_DIR, { recursive: true });

const { server } = require('../server.js');

let port;
before(async () => {
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  port = server.address().port;
});
after(async () => {
  await new Promise((resolve) => server.close(resolve));
});

function forward(uri, ua) {
  return new Promise((resolve, reject) => {
    http.get({
      host: '127.0.0.1', port, path: '/',
      headers: {
        'x-forwarded-for': '20.190.160.10', // an Azure address
        'x-forwarded-uri': uri,
        'x-forwarded-user-agent': ua,
        'x-forwarded-method': 'GET',
        'x-original-protocol': 'HTTP/1.1',
        'accept': 'application/json',
      },
    }, (res) => { res.resume(); resolve(res.statusCode); }).on('error', reject);
  });
}

test('Microsoft identity association file passes even with an empty User-Agent', async () => {
  assert.strictEqual(await forward('/.well-known/microsoft-identity-association.json', ''), 200);
  assert.strictEqual(await forward('/.well-known/microsoft-identity-association.json', 'Mozilla/5.0'), 200);
});

test('the exemption is exact - other well-known paths keep the empty-UA rule', async () => {
  assert.strictEqual(await forward('/.well-known/microsoft-identity-association.json.bak', ''), 403);
  assert.strictEqual(await forward('/.well-known/other.json', ''), 403);
});
