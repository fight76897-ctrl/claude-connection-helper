const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const vm = require('node:vm');
const { promisify } = require('node:util');
const sourceFile = path.join(__dirname, '../src/proxybridge.cjs');
const bridge = fs.existsSync(sourceFile) ? require(sourceFile) : {};
const programs = ['C:\\Program Files\\Claude\\Claude.exe', 'C:\\Tools\\claude-science.exe'];

test('dedicated profile blocks UDP and alternate localhost routes before proxying selected TCP', () => {
  assert.equal(typeof bridge.buildProfile, 'function');
  const profile = bridge.buildProfile([...programs, programs[0].toUpperCase()], { port: 17861 });
  assert.equal(profile.Version, '1.0');
  assert.equal(profile.ProxyConfigs.length, 1);
  assert.deepEqual(profile.ProxyConfigs[0], {
    Id: 1, Name: 'Claude local helper', Type: 'HTTP', Host: '127.0.0.1', Port: '17861',
    Username: '', Password: '', SendDomainToProxy: true,
  });
  assert.deepEqual(profile.ProxyRules.map(rule => [rule.Protocol, rule.Action]), [['UDP', 'BLOCK'], ['TCP', 'BLOCK'], ['TCP', 'PROXY']]);
  for (const rule of profile.ProxyRules) {
    assert.equal(rule.ProcessName, programs.map(file => `"${file}"`).join(';'));
    assert.equal(rule.IsEnabled, true);
    assert.equal(rule.TargetPorts, '*');
  }
  assert.match(profile.ProxyRules[1].TargetHosts, /127\.0\.0\.0\/8/);
  assert.match(profile.ProxyRules[1].TargetHosts, /::1/);
  assert.equal(profile.ProxyRules[1].TargetDomains, '');
  assert.equal(profile.ProxyRules[2].ProxyConfigId, 1);
  assert.equal(profile.ProxyRules[2].LocalhostViaProxy, true);
  assert.equal(profile.ProxyRules.some(rule => rule.Action === 'DIRECT' || rule.ProcessName === '*'), false);
});

test('profile rejects process selectors that could broaden rule coverage', () => {
  assert.equal(typeof bridge.buildProfile, 'function');
  for (const value of ['Claude.exe', '*', 'C:\\x;other.exe', 'C:\\a,b.exe', 'C:\\a"b.exe', 'C:\\a?b.exe', '\\\\server\\share\\Claude.exe']) {
    assert.throws(() => bridge.buildProfile([value], { port: 17861 }));
  }
  assert.throws(() => bridge.buildProfile([], { port: 17861 }));
  assert.throws(() => bridge.buildProfile(programs, { port: 0 }));
});

test('many selected processes are split before CLI selector buffers can truncate paths', () => {
  const paths = Array.from({ length: 8 }, (_, index) => `C:\\Program Files\\Claude companion ${index}\\Claude.exe`);
  const profile = bridge.buildProfile(paths, { port: 17861 });
  assert.ok(profile.ProxyRules.length > 3);
  for (const rule of profile.ProxyRules) assert.ok(Buffer.byteLength(rule.ProcessName, 'utf8') < 255);
  const proxied = profile.ProxyRules.filter(rule => rule.Action === 'PROXY').flatMap(rule => rule.ProcessName.split(';'));
  assert.deepEqual(proxied, paths.map(file => `"${file}"`));
  const firstProxy = profile.ProxyRules.findIndex(rule => rule.Action === 'PROXY');
  assert.equal(profile.ProxyRules.slice(firstProxy).every(rule => rule.Action === 'PROXY'), true);
});

test('profile export preserves the user default and contains no residential credentials', t => {
  assert.equal(typeof bridge.writeProfile, 'function');
  const dataDir = fs.mkdtempSync(path.join(os.tmpdir(), 'cch-pb-profile-'));
  t.after(() => fs.rmSync(dataDir, { recursive: true, force: true }));
  const userProfile = path.join(dataDir, 'Default.pbprofile');
  fs.writeFileSync(userProfile, 'user configuration');
  const profilePath = bridge.writeProfile(programs, { port: 17861, dataDir });
  assert.notEqual(profilePath, userProfile);
  assert.equal(fs.readFileSync(userProfile, 'utf8'), 'user configuration');
  const saved = JSON.parse(fs.readFileSync(profilePath, 'utf8'));
  assert.deepEqual(saved, bridge.buildProfile(programs, { port: 17861 }));
  assert.equal(saved.ProxyConfigs[0].Password, '');
});

test('connection parser accepts only bounded metadata and never equates proxy selection with success', () => {
  assert.equal(typeof bridge.parseConnectionLine, 'function');
  const event = bridge.parseConnectionLine('[CONN] C:\\Program Files\\Claude\\Claude.exe (PID:4052) -> 2606:4700::1:443 via Proxy HTTP://127.0.0.1:17861', { port: 17861, paths: programs });
  assert.equal(event.processPath, programs[0]);
  assert.equal(event.destination, '2606:4700::1');
  assert.equal(event.port, 443);
  assert.equal(event.route, 'proxy');
  assert.equal(event.outcome, 'attempted');
  const blocked = bridge.parseConnectionLine('[CONN] C:\\Tools\\claude-science.exe (PID:4) -> 1.2.3.4:443 via Blocked (UDP)', { port: 17861 });
  assert.equal(blocked.route, 'blocked');
  assert.equal(blocked.protocol, 'UDP');
  for (const line of [
    '[LOG] Authorization: secret',
    '[CONN] C:\\Tools\\claude-science.exe (PID:4) -> 1.2.3.4:443 via Proxy HTTP://user:secret@other:80',
    '[CONN] C:\\Tools\\claude-science.exe (PID:4) -> login?token=secret:443 via Direct',
    '[CONN] C:\\Tools\\unselected.exe (PID:4) -> 1.2.3.4:443 via Direct',
  ]) assert.equal(bridge.parseConnectionLine(line, { port: 17861, paths: programs }), null);
});

test('wrapper monitors parent identity, rejects other controllers, and only stops its owned CLI child', () => {
  assert.equal(typeof bridge.buildStartScript, 'function');
  const script = bridge.buildStartScript({ cliPath: 'E:\\tools\\proxybridge\\ProxyBridge_CLI.exe',
    profilePath: 'C:\\Local\\cch\\profile.pbprofile', logPath: 'C:\\Local\\cch\\stdout.log',
    errorPath: 'C:\\Local\\cch\\stderr.log', statePath: 'C:\\Local\\cch\\state.json',
    stopPath: 'C:\\Local\\cch\\stop', parentPid: 123, parentTicks: '123456789' });
  assert.match(script, /StartTime\.ToUniversalTime\(\)\.Ticks/);
  assert.match(script, /123456789/);
  assert.match(script, /ProxyBridge,ProxyBridge_CLI/);
  assert.match(script, /--verbose/);
  assert.match(script, /-RedirectStandardOutput/);
  assert.match(script, /finally/);
  assert.match(script, /\$child\.Kill\(\)/);
  assert.doesNotMatch(script, /Stop-Service|Stop-Process|taskkill|Default\.pbprofile|Remove-NetFirewallRule/);
});

function loadWithRuntime(runtime) {
  runtime.childProcess.execFile[promisify.custom] = (...args) => new Promise((resolve, reject) => {
    runtime.childProcess.execFile(...args, (error, stdout, stderr) => error ? reject(error) : resolve({ stdout, stderr }));
  });
  const module = { exports: {} };
  vm.runInNewContext(fs.readFileSync(sourceFile, 'utf8'), {
    require: name => name === 'node:child_process' ? runtime.childProcess : name === 'node:fs' ? runtime.fs || fs : require(name),
    module, exports: module.exports, process: { ...process, env: { ...process.env } },
    Buffer, setTimeout, clearTimeout, setInterval, clearInterval,
  }, { filename: sourceFile });
  return module.exports;
}

test('start refuses an existing controller before requesting elevation', async () => {
  assert.equal(typeof bridge.startBridge, 'function');
  const commands = [];
  const module = loadWithRuntime({ fs: { ...fs, statSync: file => String(file).endsWith('ProxyBridge_CLI.exe') ? { isFile: () => true } : fs.statSync(file) }, childProcess: { execFile(file, args, options, callback) {
    commands.push({ file, args });
    if (file.toLowerCase().endsWith('proxybridge_cli.exe')) callback(null, 'V4.2.0', '');
    else callback(null, JSON.stringify([{ Id: 50, ProcessName: 'ProxyBridge' }]), '');
  } } });
  const detection = await module.detectProxyBridge();
  assert.equal(detection.version, '4.2.0');
  assert.equal(detection.running[0].pid, 50);
  commands.length = 0;
  await assert.rejects(module.startBridge(programs, { port: 17861, dataDir: os.tmpdir() }), /ProxyBridge/);
  assert.equal(commands.some(item => item.args.some(arg => String(arg).includes('RunAs'))), false);
  assert.equal(commands.filter(item => item.file.toLowerCase().endsWith('powershell.exe')).length, 1);
});

test('owned CLI lifecycle emits route attempts, ignores arbitrary output, and reports exits', { timeout: 5000 }, async t => {
  const dataDir = fs.mkdtempSync(path.join(os.tmpdir(), 'cch-pb-session-'));
  let sessionDir;
  const seenSessionDirs = new Set();
  const events = [];
  const polls = [];
  t.after(() => { for (const timer of polls) clearInterval(timer); fs.rmSync(dataDir, { recursive: true, force: true }); });
  const module = loadWithRuntime({ fs: { ...fs, statSync: file => String(file).endsWith('ProxyBridge_CLI.exe') ? { isFile: () => true } : fs.statSync(file) }, childProcess: { execFile(file, args, options, callback) {
    if (file.toLowerCase().endsWith('proxybridge_cli.exe')) { callback(null, 'V4.2.0', ''); return; }
    const script = Buffer.from(args.at(-1), 'base64').toString('utf16le');
    if (script.includes('Get-Process -Name')) { callback(null, '[]', ''); return; }
    if (script.includes('StartTime.ToUniversalTime().Ticks')) { callback(null, '123456789', ''); return; }
    assert.match(script, /-Verb RunAs -WindowStyle Hidden/);
    const root = path.join(dataDir, 'proxybridge');
    const fresh = fs.readdirSync(root).filter(name => name.startsWith('run-') && !seenSessionDirs.has(name));
    assert.equal(fresh.length, 1);
    seenSessionDirs.add(fresh[0]);
    const currentSessionDir = path.join(root, fresh[0]);
    sessionDir = currentSessionDir;
    fs.writeFileSync(path.join(sessionDir, 'state.json'), JSON.stringify({ state: 'process-running' }));
    fs.writeFileSync(path.join(sessionDir, 'connections.log'), '[LOG] authorization: do-not-show\n[CONN] C:\\Program Files\\Claude\\Claude.exe (PID:6) -> 1.2.3.4:443 via Proxy HTTP://127.0.0.1:17861\n');
    polls.push(setInterval(() => {
      if (fs.existsSync(path.join(currentSessionDir, 'stop'))) fs.writeFileSync(path.join(currentSessionDir, 'state.json'), JSON.stringify({ state: 'stopped', reason: 'requested' }));
    }, 20));
    callback(null, '', '');
  } } });
  const session = await module.startBridge(programs, { port: 17861, dataDir, onEvent: event => events.push(event) });
  assert.equal(session.status, 'running');
  assert.equal(session.readiness, 'process-only');
  assert.equal(events.some(event => event.type === 'connection' && event.route === 'proxy' && event.outcome === 'attempted'), true);
  assert.equal(JSON.stringify(events).includes('do-not-show'), false);
  await session.stop();
  assert.equal(session.status, 'stopped');
  assert.equal(fs.existsSync(path.join(sessionDir, 'stop')), true);
  const second = await module.startBridge(programs, { port: 17861, dataDir, onEvent: event => events.push(event) });
  const crash = new Promise(resolve => {
    const timer = setInterval(() => {
      if (second.status === 'failed') { clearInterval(timer); resolve(); }
    }, 20);
    polls.push(timer);
  });
  fs.writeFileSync(path.join(sessionDir, 'state.json'), JSON.stringify({ state: 'stopped', reason: 'child-exit' }));
  await crash;
  assert.equal(events.some(event => event.state === 'failed' && event.message.includes('恢复直连')), true);
});

test('a readiness banner followed by immediate exit cannot return a live session', async t => {
  const dataDir = fs.mkdtempSync(path.join(os.tmpdir(), 'cch-pb-early-exit-'));
  t.after(() => fs.rmSync(dataDir, { recursive: true, force: true }));
  const module = loadWithRuntime({ fs: { ...fs, statSync: file => String(file).endsWith('ProxyBridge_CLI.exe') ? { isFile: () => true } : fs.statSync(file) }, childProcess: { execFile(file, args, options, callback) {
    if (file.toLowerCase().endsWith('proxybridge_cli.exe')) { callback(null, 'V4.2.0', ''); return; }
    const script = Buffer.from(args.at(-1), 'base64').toString('utf16le');
    if (script.includes('Get-Process -Name')) { callback(null, '[]', ''); return; }
    if (script.includes('StartTime.ToUniversalTime().Ticks')) { callback(null, '123456789', ''); return; }
    const root = path.join(dataDir, 'proxybridge');
    const sessionDir = path.join(root, fs.readdirSync(root).find(name => name.startsWith('run-')));
    fs.writeFileSync(path.join(sessionDir, 'state.json'), JSON.stringify({ state: 'stopped', reason: 'child-exit' }));
    fs.writeFileSync(path.join(sessionDir, 'connections.log'), 'ProxyBridge is running. Press Ctrl+C to stop.\n');
    callback(null, '', '');
  } } });
  const keeper = setInterval(() => {}, 1000);
  try { await assert.rejects(module.startBridge(programs, { port: 17861, dataDir }), /ProxyBridge/); }
  finally { clearInterval(keeper); }
});
