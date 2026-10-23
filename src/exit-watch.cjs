const https = require('node:https');
const tls = require('node:tls');
const net = require('node:net');
const { openTunnel } = require('./proxy.cjs');

const CHECK_INTERVAL_MS = 30000;
const CHECK_TIMEOUT_MS = 25000;

function validateExit(value, expectedIp) {
  if (!net.isIP(value?.ip || '') || !/^[A-Z]{2}$/.test(value?.country || '')) throw new Error('出口查询未返回有效 IP 和国家。');
  // Normalize IPv6 text so compressed and expanded forms compare correctly.
  const canonical = ip => new URL(`http://${net.isIP(ip) === 6 ? `[${ip}]` : ip}`).hostname;
  if (canonical(value.ip) !== canonical(expectedIp)) throw new Error(`检测出口 ${value.ip} 与预期 ${expectedIp} 不一致，已截断助手连接。`);
  if (value.country !== 'US') throw new Error(`出口国家检测为 ${value.country}，要求美国 US，已截断助手连接。`);
  return value;
}

function probeExit(config, signal) {
  return new Promise((resolve, reject) => {
    const sockets = new Set();
    let request;
    let agent;
    let finished = false;
    const started = Date.now();
    const finish = (error, result) => {
      if (finished) return;
      finished = true;
      clearTimeout(timer);
      signal?.removeEventListener('abort', abort);
      request?.destroy(); agent?.destroy();
      for (const socket of sockets) socket.destroy();
      error ? reject(error) : resolve(result);
    };
    const abort = () => finish(new Error('出口检测已取消。'));
    const timer = setTimeout(() => finish(new Error('出口检测超时，已截断助手连接。')), CHECK_TIMEOUT_MS);
    const track = socket => {
      sockets.add(socket);
      if (finished) socket.destroy();
    };
    if (signal?.aborted) { abort(); return; }
    signal?.addEventListener('abort', abort, { once: true });
    // The check uses the identical two-hop chain, independent of the gated listener.
    openTunnel(config, 'api.country.is', 443, { track }).then(tunnel => {
      if (finished) { tunnel.destroy(); return; }
      const secure = tls.connect({ socket: tunnel, servername: 'api.country.is', ALPNProtocols: ['http/1.1'] });
      track(secure);
      secure.on('error', () => finish(new Error('出口检测 TLS 连接失败；证书验证保持开启。')));
      agent = new https.Agent({ keepAlive: false });
      agent.createConnection = () => secure;
      request = https.get('https://api.country.is/', { agent }, response => {
        if (response.statusCode !== 200) { finish(new Error(`出口查询返回 HTTP ${response.statusCode}，已截断助手连接。`)); return; }
        let body = '';
        response.on('data', chunk => {
          body += chunk;
          if (body.length > 8192) finish(new Error('出口查询响应过大。'));
        });
        response.on('error', () => finish(new Error('出口查询响应中断。')));
        response.on('end', () => {
          try {
            const { ip, country } = JSON.parse(body);
            if (!net.isIP(ip || '') || !/^[A-Z]{2}$/.test(country || '')) throw new Error();
            finish(null, { ip, country, latencyMs: Date.now() - started });
          } catch { finish(new Error('出口查询结果无效，已截断助手连接。')); }
        });
      });
      request.on('error', () => finish(new Error('出口查询连接失败，已截断助手连接。')));
    }).catch(error => finish(error));
  });
}

function createExitMonitor({ expectedIp, probe, onVerified = () => {}, onFailure = () => {}, intervalMs = CHECK_INTERVAL_MS }) {
  if (!net.isIP(expectedIp || '')) throw new Error('必须填写服务商提供的预期静态出口 IP。');
  let active = true;
  let pending;
  let timer;
  let controller;
  const stop = () => { active = false; clearTimeout(timer); controller?.abort(); };
  const check = () => {
    if (pending) return pending;
    if (!active) return Promise.reject(new Error('出口监测已取消。'));
    clearTimeout(timer);
    controller = new AbortController();
    // Invoke synchronously so stop() can immediately cancel the in-flight probe.
    let probing;
    try { probing = probe(controller.signal); } catch (error) { probing = Promise.reject(error); }
    pending = Promise.resolve(probing).then(async result => {
      if (!active) throw new Error('出口监测已取消。');
      validateExit(result, expectedIp);
      await onVerified(result);
      if (!active) throw new Error('出口监测已取消。');
      timer = setTimeout(() => check().catch(() => {}), intervalMs);
      return result;
    }).catch(async error => {
      if (active) { stop(); await onFailure(error); }
      throw error;
    }).finally(() => { pending = undefined; });
    return pending;
  };
  return { check, stop, get active() { return active; } };
}

module.exports = { CHECK_INTERVAL_MS, CHECK_TIMEOUT_MS, validateExit, probeExit, createExitMonitor };
