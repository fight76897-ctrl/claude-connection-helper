const http = require('node:http');
const net = require('node:net');

const LOCAL_PORT = 17861;
const CONNECT_TIMEOUT = 15000;

function host(value) {
  const result = String(value ?? '').trim();
  if (!result || result.length > 253 || (!net.isIP(result) && !/^[a-zA-Z0-9](?:[a-zA-Z0-9.-]*[a-zA-Z0-9])?$/.test(result))) {
    throw new Error('代理地址请只填写 IP 或域名，不包含 http://、端口或路径。');
  }
  return result;
}

function port(value) {
  const result = Number(value);
  if (!Number.isInteger(result) || result < 1 || result > 65535) throw new Error('端口必须为 1–65535 的整数。');
  return result;
}

function validateConfig(input) {
  const result = {
    vpnHost: host(input.vpnHost), vpnPort: port(input.vpnPort),
    residentialHost: host(input.residentialHost), residentialPort: port(input.residentialPort),
    residentialProtocol: input.residentialProtocol ?? 'http',
    username: String(input.username ?? ''), password: String(input.password ?? ''),
    expectedIp: String(input.expectedIp ?? '').trim(),
    localPort: input.localPort === 0 ? 0 : port(input.localPort ?? LOCAL_PORT),
  };
  if (!['http', 'socks5'].includes(result.residentialProtocol)) throw new Error('住宅代理协议请选择 HTTP CONNECT 或 SOCKS5。');
  if (!['localhost', '127.0.0.1', '::1'].includes(result.vpnHost)) throw new Error('VPN 入口必须是本机回环地址。');
  if (result.vpnPort === result.localPort) throw new Error('VPN 端口不能与助手监听端口相同，否则会形成循环。');
  if ((result.residentialProtocol === 'http' && result.username.includes(':')) || /[\r\n\0]/.test(result.username + result.password)) throw new Error('HTTP 用户名不能含冒号，代理凭据不能含换行。');
  if (!result.username && result.password) throw new Error('填写代理密码时也需要填写用户名。');
  if (result.residentialProtocol === 'socks5' && result.username) {
    if (!result.password) throw new Error('SOCKS5 用户名认证需要填写密码。');
    if (Buffer.byteLength(result.username) > 255 || Buffer.byteLength(result.password) > 255) throw new Error('SOCKS5 用户名和密码各自不能超过 255 字节。');
  }
  if (result.expectedIp && !net.isIP(result.expectedIp)) throw new Error('预期出口请填写有效 IPv4 或 IPv6 地址。');
  return result;
}

function authority(hostname, targetPort) {
  return `${net.isIP(hostname) === 6 ? `[${hostname}]` : hostname}:${targetPort}`;
}

function connectRequest(socket, target, authorization, label) {
  return new Promise((resolve, reject) => {
    let buffer = Buffer.alloc(0);
    const cleanup = () => {
      socket.removeListener('data', onData);
      socket.removeListener('error', onError);
      socket.removeListener('close', onClose);
    };
    const onError = () => { cleanup(); reject(new Error(`${label}连接中断。`)); };
    const onClose = () => { cleanup(); reject(new Error(`${label}在建立隧道前关闭连接。`)); };
    const onData = chunk => {
      buffer = Buffer.concat([buffer, chunk]);
      const end = buffer.indexOf('\r\n\r\n');
      if ((end < 0 && buffer.length > 16384) || end > 16384) {
        cleanup(); reject(new Error(`${label}返回了过大的响应头。`)); return;
      }
      if (end < 0) return;
      socket.pause();
      cleanup();
      const status = /^HTTP\/1\.[01] (\d{3})(?: |\r\n)/.exec(buffer.toString('latin1'))?.[1];
      if (status !== '200') {
        reject(new Error(status === '407' ? `${label}认证失败（407），请核对 HTTP 端口、用户名和密码。` : `${label}拒绝建立隧道（${status || '无效响应'}）。`));
        return;
      }
      const remainder = buffer.subarray(end + 4);
      if (remainder.length) socket.unshift(remainder);
      resolve();
    };
    socket.on('data', onData);
    socket.once('error', onError);
    socket.once('close', onClose);
    socket.write(`CONNECT ${target} HTTP/1.1\r\nHost: ${target}\r\n${authorization ? `Proxy-Authorization: ${authorization}\r\n` : ''}\r\n`);
    socket.resume();
  });
}

function readSocksBytes(socket, size) {
  return new Promise((resolve, reject) => {
    let buffer = Buffer.alloc(0);
    const cleanup = () => {
      socket.pause();
      socket.removeListener('data', onData); socket.removeListener('error', onError); socket.removeListener('close', onClose);
    };
    const onError = () => { cleanup(); reject(new Error('住宅 SOCKS5 连接中断或超时。')); };
    const onClose = () => { cleanup(); reject(new Error('住宅 SOCKS5 在握手完成前关闭连接，请核对协议和端口。')); };
    const onData = chunk => {
      buffer = Buffer.concat([buffer, chunk]);
      if (buffer.length < size) return;
      cleanup();
      if (buffer.length > size) socket.unshift(buffer.subarray(size));
      resolve(buffer.subarray(0, size));
    };
    if (socket.destroyed) { onClose(); return; }
    socket.on('data', onData); socket.once('error', onError); socket.once('close', onClose); socket.resume();
  });
}

async function socksConnect(socket, config, hostname, targetPort) {
  const method = config.username ? 2 : 0;
  let pending = readSocksBytes(socket, 2);
  socket.write(Buffer.from([5, 1, method]));
  const greeting = await pending;
  if (greeting[0] !== 5 || greeting[1] !== method) throw new Error('住宅 SOCKS5 不接受当前认证方式，请核对用户名、密码及服务商白名单。');
  if (method === 2) {
    const username = Buffer.from(config.username), password = Buffer.from(config.password);
    pending = readSocksBytes(socket, 2);
    socket.write(Buffer.concat([Buffer.from([1, username.length]), username, Buffer.from([password.length]), password]));
    const auth = await pending;
    if (auth[0] !== 1 || auth[1] !== 0) throw new Error('住宅 SOCKS5 认证失败，请核对用户名和密码。');
  }
  let address;
  if (net.isIP(hostname) === 4) {
    address = Buffer.from([1, ...hostname.split('.').map(Number)]);
  } else if (net.isIP(hostname) === 6) {
    // URL canonicalizes embedded IPv4; fill the omitted IPv6 words explicitly.
    const canonical = new URL(`http://[${hostname}]`).hostname.slice(1, -1);
    const [left, right] = canonical.split('::').map(part => part ? part.split(':') : []);
    const words = right ? [...left, ...Array(8 - left.length - right.length).fill('0'), ...right] : left;
    address = Buffer.alloc(17); address[0] = 4;
    words.forEach((word, index) => address.writeUInt16BE(parseInt(word, 16), 1 + index * 2));
  } else {
    const domain = Buffer.from(hostname, 'ascii');
    address = Buffer.concat([Buffer.from([3, domain.length]), domain]);
  }
  const destinationPort = Buffer.alloc(2); destinationPort.writeUInt16BE(targetPort);
  pending = readSocksBytes(socket, 4);
  socket.write(Buffer.concat([Buffer.from([5, 1, 0]), address, destinationPort]));
  const reply = await pending;
  if (reply[0] !== 5 || reply[2] !== 0) throw new Error('住宅 SOCKS5 返回无效握手响应。');
  if (reply[1] !== 0) throw new Error(`住宅 SOCKS5 拒绝建立隧道（状态 ${reply[1]}）。`);
  const addressLength = reply[3] === 1 ? 4 : reply[3] === 4 ? 16 : reply[3] === 3 ? (await readSocksBytes(socket, 1))[0] : 0;
  if (!addressLength) throw new Error('住宅 SOCKS5 返回无效地址类型。');
  await readSocksBytes(socket, addressLength + 2);
}

async function openTunnel(config, destinationHost, destinationPort, { track = () => {}, timeoutMs = CONNECT_TIMEOUT } = {}) {
  const destination = authority(host(destinationHost), port(destinationPort));
  const socket = net.createConnection({ host: config.vpnHost, port: config.vpnPort });
  track(socket);
  socket.on('error', () => {});
  const timer = setTimeout(() => socket.destroy(new Error('timeout')), timeoutMs);
  try {
    await new Promise((resolve, reject) => {
      const cleanup = () => {
        socket.removeListener('connect', onConnect);
        socket.removeListener('error', onError);
        socket.removeListener('close', onClose);
      };
      const onConnect = () => { cleanup(); resolve(); };
      const onError = () => { cleanup(); reject(new Error('无法连接本地 VPN，请确认 Veee 已连接且代理端口正确。')); };
      const onClose = () => { cleanup(); reject(new Error('本地 VPN 连接已关闭。')); };
      socket.once('connect', onConnect);
      socket.once('error', onError);
      socket.once('close', onClose);
    });
    await connectRequest(socket, authority(config.residentialHost, config.residentialPort), null, 'VPN → 住宅代理');
    if (config.residentialProtocol === 'socks5') {
      await socksConnect(socket, config, host(destinationHost), port(destinationPort));
    } else {
      const auth = config.username ? `Basic ${Buffer.from(`${config.username}:${config.password}`, 'utf8').toString('base64')}` : null;
      await connectRequest(socket, destination, auth, '住宅代理');
    }
    return socket;
  } catch (error) {
    socket.destroy();
    throw error;
  } finally {
    clearTimeout(timer);
  }
}

function cleanHeaders(headers) {
  const result = { ...headers };
  const remove = ['proxy-authorization', 'proxy-authenticate', 'proxy-connection', 'connection', 'keep-alive', 'upgrade', 'te', 'trailer', 'transfer-encoding'];
  for (const name of String(headers.connection || '').split(',')) remove.push(name.trim().toLowerCase());
  for (const name of remove) delete result[name];
  result.connection = 'close';
  return result;
}

async function startProxy(input, onEvent = () => {}, { allowTraffic = () => true } = {}) {
  const config = validateConfig(input);
  const sockets = new Set();
  let stopped = false;
  const track = socket => {
    if (stopped) { socket.destroy(); return; }
    sockets.add(socket);
    socket.on('error', () => {});
    socket.once('close', () => sockets.delete(socket));
  };
  const emit = (level, message) => onEvent({ time: new Date().toISOString(), level, message });
  const server = http.createServer(async (req, res) => {
    if (!allowTraffic()) { res.writeHead(503, { Connection: 'close' }); res.end('Exit not verified'); return; }
    let tunnel;
    try {
      const url = new URL(req.url);
      if (url.protocol !== 'http:' || url.username || url.password) throw new Error('此入口需要 HTTP 代理请求；HTTPS 请使用 CONNECT。');
      tunnel = await openTunnel(config, url.hostname.replace(/^\[|\]$/g, ''), Number(url.port || 80), { track });
      if (stopped || req.destroyed || !allowTraffic()) { tunnel.destroy(); res.destroy(); return; }
      const agent = new http.Agent({ keepAlive: false });
      agent.createConnection = () => tunnel;
      const headers = cleanHeaders(req.headers);
      headers.host = url.host;
      const upstream = http.request(url, { method: req.method, headers, agent }, response => {
        res.writeHead(response.statusCode, cleanHeaders(response.headers));
        response.pipe(res);
        response.on('error', () => res.destroy());
      });
      upstream.on('error', () => {
        if (!res.headersSent) res.writeHead(502);
        res.end('Upstream connection failed');
      });
      res.on('close', () => { upstream.destroy(); tunnel.destroy(); agent.destroy(); });
      req.on('aborted', () => upstream.destroy());
      req.pipe(upstream);
      tunnel.resume();
      emit('info', `已转发 ${url.hostname}（HTTP）`);
    } catch (error) {
      tunnel?.destroy();
      if (!res.headersSent) res.writeHead(502, { 'Content-Type': 'text/plain; charset=utf-8' });
      res.end('代理链路不可用，已停止本次请求。');
      emit('error', error.message);
    }
  });
  server.on('connection', track);
  server.on('clientError', (_, socket) => socket.destroy());
  server.on('connect', async (req, client, head) => {
    if (!allowTraffic()) { client.end('HTTP/1.1 503 Service Unavailable\r\nConnection: close\r\nContent-Length: 0\r\n\r\n'); return; }
    let remote;
    try {
      const match = /^(\[[a-fA-F0-9:]+\]|[a-zA-Z0-9.-]+):(\d+)$/.exec(req.url);
      if (!match) throw new Error('无效的 CONNECT 目标地址。');
      const targetHost = match[1].replace(/^\[|\]$/g, '');
      const targetPort = port(match[2]);
      if (['127.0.0.1', 'localhost', '::1'].includes(targetHost) && targetPort === server.address()?.port) throw new Error('已阻止代理循环。');
      remote = await openTunnel(config, targetHost, targetPort, { track });
      if (client.destroyed || stopped || !allowTraffic()) { remote.destroy(); client.destroy(); return; }
      client.write('HTTP/1.1 200 Connection Established\r\n\r\n');
      if (head.length) remote.write(head);
      client.on('error', () => remote.destroy());
      remote.on('error', () => client.destroy());
      client.on('close', () => remote.destroy());
      remote.on('close', () => client.destroy());
      client.pipe(remote).pipe(client);
      remote.resume();
      emit('info', `已建立隧道 ${targetHost}:${targetPort}`);
    } catch (error) {
      remote?.destroy();
      if (!client.destroyed) client.end('HTTP/1.1 502 Bad Gateway\r\nConnection: close\r\nContent-Length: 0\r\n\r\n');
      emit('error', error.message);
    }
  });
  await new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(config.localPort, '127.0.0.1', resolve);
  });
  return {
    port: server.address().port,
    async stop() {
      if (stopped) return;
      stopped = true;
      for (const socket of sockets) socket.destroy();
      await new Promise(resolve => server.close(resolve));
    },
  };
}

module.exports = { LOCAL_PORT, validateConfig, openTunnel, startProxy };
