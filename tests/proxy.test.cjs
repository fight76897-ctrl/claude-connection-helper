const test = require('node:test');
const assert = require('node:assert/strict');
const net = require('node:net');
const http = require('node:http');
const { once } = require('node:events');
const { listen, proxyFixture, connect } = require('./helpers.cjs');
const { startProxy, validateConfig } = require('../src/proxy.cjs');

async function setup(t, reject = false, options) {
  const history = [];
  const auth = 'Basic ' + Buffer.from('alice:secret:@/word').toString('base64');
  const residential = await proxyFixture({ name: 'residential', history, auth, reject });
  const vpn = await proxyFixture({ name: 'vpn', history });
  const config = {
    vpnHost: '127.0.0.1', vpnPort: vpn.port,
    residentialHost: '127.0.0.1', residentialPort: residential.port,
    username: 'alice', password: 'secret:@/word', localPort: 0,
  };
  const logs = [];
  const proxy = await startProxy(config, event => logs.push(event), options);
  t.after(async () => { await proxy.stop(); await vpn.close(); await residential.close(); });
  return { history, residential, vpn, proxy, config, logs, auth };
}

test('CONNECT traffic traverses VPN then authenticated residential proxy; bytes survive the tunnel', async t => {
  const f = await setup(t);
  const echo = await listen(net.createServer(socket => socket.pipe(socket)));
  t.after(() => echo.close());
  const { socket, headers } = await connect(f.proxy.port, `127.0.0.1:${echo.port}`);
  t.after(() => socket.destroy());
  assert.match(headers, /^HTTP\/1.1 200/);
  const reply = once(socket, 'data');
  socket.resume();
  socket.write('hello through two proxies');
  assert.equal((await reply)[0].toString(), 'hello through two proxies');
  assert.deepEqual(f.history.map(x => [x.name, x.target]), [
    ['vpn', `127.0.0.1:${f.residential.port}`],
    ['residential', `127.0.0.1:${echo.port}`],
  ]);
  assert.equal(f.history[0].auth, undefined);
  assert.equal(f.history[1].auth, f.auth);
  assert.ok(!JSON.stringify(f.logs).includes('secret'));
});

test('residential authentication failure cannot fall back to a reachable target', async t => {
  const f = await setup(t, true);
  let reachedTarget = 0;
  const target = await listen(net.createServer(() => reachedTarget++));
  t.after(() => target.close());
  const { socket, headers } = await connect(f.proxy.port, `127.0.0.1:${target.port}`);
  t.after(() => socket.destroy());
  assert.match(headers, /^HTTP\/1.1 502/);
  assert.equal(reachedTarget, 0);
  assert.equal(f.history.length, 2);
  assert.match(f.logs.at(-1).message, /407/);
});

test('VPN refusal returns failure without contacting the residential endpoint', async t => {
  const f = await setup(t);
  await f.vpn.close();
  const { socket, headers } = await connect(f.proxy.port, 'example.com:443');
  t.after(() => socket.destroy());
  assert.match(headers, /^HTTP\/1.1 502/);
  assert.equal(f.history.length, 0);
});

test('ordinary HTTP request travels through the chain and never leaks proxy credentials to target', async t => {
  const f = await setup(t);
  let received;
  const target = await listen(http.createServer((req, res) => {
    received = req.headers;
    res.end('target response');
  }));
  t.after(() => target.close());
  const body = await new Promise((resolve, reject) => {
    http.get({ host: '127.0.0.1', port: f.proxy.port,
      path: `http://127.0.0.1:${target.port}/test?q=1`,
      headers: { 'Proxy-Authorization': 'Basic must-not-leak', Authorization: 'Bearer target-token' },
    }, res => {
      let data = ''; res.on('data', chunk => data += chunk); res.on('end', () => resolve(data));
    }).on('error', reject);
  });
  assert.equal(body, 'target response');
  assert.equal(received['proxy-authorization'], undefined);
  assert.equal(received.authorization, 'Bearer target-token');
  assert.equal(f.history.length, 2);
});

test('stopping the proxy closes existing tunnels and listener', async t => {
  const f = await setup(t);
  const echo = await listen(net.createServer(socket => socket.pipe(socket)));
  t.after(() => echo.close());
  const { socket } = await connect(f.proxy.port, `127.0.0.1:${echo.port}`);
  socket.resume();
  const closed = once(socket, 'close');
  await f.proxy.stop();
  await closed;
  await assert.rejects(connect(f.proxy.port, 'example.com:443'), { code: 'ECONNREFUSED' });
});

test('invalid proxy settings are rejected before listening', () => {
  const config = { vpnHost: '127.0.0.1', vpnPort: 15236, residentialHost: 'proxy.example.com', residentialPort: 8080, username: '', password: '' };
  for (const change of [
    { residentialHost: 'http://proxy.example.com' }, { residentialHost: 'evil\r\nHeader: test' },
    { residentialPort: 0 }, { residentialPort: 65536 }, { username: 'bad:name' },
    { vpnHost: 'remote.example.com' }, { vpnPort: 17861 },
    { expectedIp: 'not-an-ip' },
  ]) assert.throws(() => validateConfig({ ...config, ...change }));
  assert.equal(validateConfig(config).residentialPort, 8080);
});

test('an unverified listener rejects CONNECT and HTTP without contacting either upstream', async t => {
  let verified = false;
  const f = await setup(t, false, { allowTraffic: () => verified });
  const denied = await connect(f.proxy.port, 'example.com:443');
  denied.socket.destroy();
  assert.match(denied.headers, /^HTTP\/1.1 503/);
  const status = await new Promise((resolve, reject) => {
    http.get({ host: '127.0.0.1', port: f.proxy.port, path: 'http://example.com/' }, res => { res.resume(); resolve(res.statusCode); }).on('error', reject);
  });
  assert.equal(status, 503);
  assert.equal(f.history.length, 0);
  verified = true;
  const echo = await listen(net.createServer(socket => socket.pipe(socket)));
  t.after(() => echo.close());
  const allowed = await connect(f.proxy.port, `127.0.0.1:${echo.port}`);
  allowed.socket.destroy();
  assert.match(allowed.headers, /^HTTP\/1.1 200/);
  assert.equal(f.history.length, 2);
});
