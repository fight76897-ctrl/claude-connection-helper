const http = require('node:http');
const net = require('node:net');

async function listen(server) {
  const sockets = new Set();
  server.on('connection', socket => {
    sockets.add(socket);
    socket.on('error', () => {});
    socket.on('close', () => sockets.delete(socket));
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  return {
    server, port: server.address().port,
    async close() {
      for (const socket of sockets) socket.destroy();
      await new Promise(resolve => server.close(resolve));
    },
  };
}

async function proxyFixture({ auth, reject = false, history, name }) {
  const server = http.createServer();
  server.on('connect', (req, client, head) => {
    history.push({ name, target: req.url, auth: req.headers['proxy-authorization'] });
    if (reject || (auth && req.headers['proxy-authorization'] !== auth)) {
      client.end('HTTP/1.1 407 Proxy Authentication Required\r\nContent-Length: 0\r\n\r\n');
      return;
    }
    const dest = new URL(`http://${req.url}`);
    const remote = net.connect(Number(dest.port), dest.hostname, () => {
      client.write('HTTP/1.1 200 Connection Established\r\n\r\n');
      if (head.length) remote.write(head);
      client.pipe(remote).pipe(client);
    });
    remote.on('error', () => client.destroy());
    client.on('close', () => remote.destroy());
    remote.on('close', () => client.destroy());
  });
  return listen(server);
}

async function connect(port, target) {
  return new Promise((resolve, reject) => {
    const socket = net.connect(port, '127.0.0.1');
    socket.setTimeout(3000, () => socket.destroy(new Error('test timeout')));
    socket.on('error', reject);
    let buffer = Buffer.alloc(0);
    function read(chunk) {
      buffer = Buffer.concat([buffer, chunk]);
      const end = buffer.indexOf('\r\n\r\n');
      if (end < 0) return;
      socket.pause();
      socket.removeListener('data', read);
      const rest = buffer.subarray(end + 4);
      if (rest.length) socket.unshift(rest);
      resolve({ socket, headers: buffer.subarray(0, end).toString() });
    }
    socket.on('data', read);
    socket.on('connect', () => socket.write(`CONNECT ${target} HTTP/1.1\r\nHost: ${target}\r\n\r\n`));
  });
}

module.exports = { listen, proxyFixture, connect };
