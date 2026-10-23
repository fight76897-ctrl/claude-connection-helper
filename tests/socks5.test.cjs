const test = require('node:test');
const assert = require('node:assert/strict');
const net = require('node:net');
const { once } = require('node:events');
const { startProxy, validateConfig } = require('../src/proxy.cjs');
const { listen, proxyFixture, connect } = require('./helpers.cjs');

async function setup(t, { authenticate = true, failAuth = false, failConnect = false, earlyClose = false, replyType = 1 } = {}) {
  const history = [];
  const seen = { requests: [], auth: null, reached: 0 };
  const echo = await listen(net.createServer(socket => { seen.reached++; socket.pipe(socket); }));
  const residential = await listen(net.createServer(socket => {
    let buffer = Buffer.alloc(0), stage = 'greeting';
    const fragment = response => {
      socket.write(response.subarray(0, 1));
      setTimeout(() => { if (!socket.destroyed) socket.write(response.subarray(1)); }, 5);
    };
    socket.on('data', function receive(chunk) {
      buffer = Buffer.concat([buffer, chunk]);
      if (stage === 'greeting') {
        if (buffer[0] !== 5 || earlyClose) { socket.end(); return; }
        if (buffer.length < 2 + buffer[1]) return;
        seen.methods = [...buffer.subarray(2, 2 + buffer[1])];
        buffer = buffer.subarray(2 + buffer[1]);
        stage = authenticate ? 'auth' : 'connect';
        fragment(Buffer.from([5, authenticate ? 2 : 0])); return;
      }
      if (stage === 'auth') {
        if (buffer.length < 2) return;
        const userEnd = 2 + buffer[1];
        if (buffer.length <= userEnd || buffer.length < userEnd + 1 + buffer[userEnd]) return;
        const end = userEnd + 1 + buffer[userEnd];
        seen.auth = [buffer.subarray(2, userEnd).toString(), buffer.subarray(userEnd + 1, end).toString()];
        buffer = buffer.subarray(end); stage = 'connect';
        fragment(Buffer.from([1, failAuth ? 1 : 0])); return;
      }
      if (stage !== 'connect' || buffer.length < 5) return;
      const addressLength = buffer[3] === 1 ? 4 : buffer[3] === 4 ? 16 : buffer[4];
      const addressStart = buffer[3] === 3 ? 5 : 4;
      const end = addressStart + addressLength + 2;
      if (buffer.length < end) return;
      seen.requests.push({ type: buffer[3], address: buffer.subarray(addressStart, end - 2), port: buffer.readUInt16BE(end - 2) });
      stage = 'tunnel';
      if (failConnect) { fragment(Buffer.from([5, 5, 0, 1, 0, 0, 0, 0, 0, 0])); return; }
      const remote = net.connect(echo.port, '127.0.0.1', () => {
        const address = replyType === 3 ? Buffer.from([3, 97, 98, 99]) : Buffer.alloc(replyType === 4 ? 16 : 4);
        const response = Buffer.concat([Buffer.from([5, 0, 0, replyType]), address, Buffer.from([0, 0])]);
        fragment(response);
        socket.removeListener('data', receive);
        if (buffer.length > end) remote.write(buffer.subarray(end));
        socket.pipe(remote).pipe(socket);
      });
      remote.on('error', () => socket.destroy());
      remote.on('close', () => socket.destroy()); socket.on('close', () => remote.destroy());
    });
  }));
  const vpn = await proxyFixture({ history, name: 'vpn' });
  const config = { vpnHost: '127.0.0.1', vpnPort: vpn.port, residentialHost: '127.0.0.1', residentialPort: residential.port,
    residentialProtocol: 'socks5', username: authenticate ? 'fixture-user' : '', password: authenticate ? 'fixture-secret' : '', localPort: 0 };
  const logs = [];
  const proxy = await startProxy(config, event => logs.push(event));
  t.after(async () => { await proxy.stop(); await vpn.close(); await residential.close(); await echo.close(); });
  return { proxy, seen, history, logs, config };
}

test('SOCKS5 authenticates inside the VPN tunnel and resolves target domain at the residential proxy', async t => {
  const f = await setup(t);
  const { socket, headers } = await connect(f.proxy.port, 'remote-only.invalid:443');
  t.after(() => socket.destroy());
  assert.match(headers, /^HTTP\/1.1 200/);
  assert.deepEqual(f.seen.methods, [2]);
  assert.deepEqual(f.seen.auth, ['fixture-user', 'fixture-secret']);
  assert.equal(f.history[0].auth, undefined);
  assert.equal(f.seen.requests[0].type, 3);
  assert.equal(f.seen.requests[0].address.toString(), 'remote-only.invalid');
  const reply = once(socket, 'data'); socket.resume(); socket.write('socks echo');
  assert.equal((await reply)[0].toString(), 'socks echo');
  assert.ok(!JSON.stringify(f.logs).includes('fixture-secret'));
});

test('SOCKS5 supports no authentication, IPv4/IPv6 targets and all bound address reply types', async t => {
  for (const replyType of [1, 3, 4]) {
    const f = await setup(t, { authenticate: false, replyType });
    const ipv6 = replyType === 4;
    const { socket, headers } = await connect(f.proxy.port, ipv6 ? '[2001:db8::1]:443' : '192.0.2.1:443');
    socket.destroy();
    assert.match(headers, /^HTTP\/1.1 200/);
    assert.deepEqual(f.seen.methods, [0]);
    assert.equal(f.seen.requests[0].type, ipv6 ? 4 : 1);
    assert.equal(f.seen.requests[0].address.toString('hex'), ipv6 ? '20010db8000000000000000000000001' : 'c0000201');
  }
});

test('SOCKS5 authentication/CONNECT failures and premature closure never reach the destination', async t => {
  for (const option of ['failAuth', 'failConnect', 'earlyClose']) {
    const f = await setup(t, { [option]: true });
    const { socket, headers } = await connect(f.proxy.port, 'remote-only.invalid:443'); socket.destroy();
    assert.match(headers, /^HTTP\/1.1 502/);
    assert.equal(f.seen.reached, 0);
    assert.match(f.logs.at(-1).message, option === 'failAuth' ? /SOCKS5.*认证/ : option === 'failConnect' ? /SOCKS5.*拒绝/ : /SOCKS5.*关闭/);
  }
});

test('proxy protocol is explicit, backward compatible and SOCKS5 credentials respect byte limits', () => {
  const base = { vpnHost: '127.0.0.1', vpnPort: 15236, residentialHost: 'proxy.example', residentialPort: 1080 };
  assert.equal(validateConfig(base).residentialProtocol, 'http');
  assert.equal(validateConfig({ ...base, residentialProtocol: 'socks5' }).residentialProtocol, 'socks5');
  assert.throws(() => validateConfig({ ...base, residentialProtocol: 'https' }), /协议/);
  assert.throws(() => validateConfig({ ...base, residentialProtocol: 'socks5', username: 'x', password: '' }), /密码/);
  assert.throws(() => validateConfig({ ...base, residentialProtocol: 'socks5', username: 'x', password: '密'.repeat(86) }), /255/);
});
