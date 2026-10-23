const { app, BrowserWindow, ipcMain, dialog, safeStorage } = require('electron');
const path = require('node:path');
const fs = require('node:fs');
const { pathToFileURL } = require('node:url');
const { LOCAL_PORT, validateConfig, startProxy } = require('./proxy.cjs');
const { detectApps, launchApp, launchDesktopCallback, refreshInstalledApps, readAppVersions, discoverGuardTargets } = require('./launchers.cjs');
const { openBrowser } = require('./browser.cjs');
const { createExitMonitor, probeExit, CHECK_INTERVAL_MS } = require('./exit-watch.cjs');
const proxybridge = require('./proxybridge.cjs');
const guard = require('./guard.cjs');

app.setName('ClaudeConnectionHelper');
app.commandLine.appendSwitch('disable-quic');
let window;
let service;
let quitting = false;
let busy = false;
let exitIp = null;
let lastCheck = null;
let exitCountry = null;
let latencyMs = null;
let monitor;
let bridge;
let bridgeInfo = { installed: false, status: '尚未检测', running: [] };
let appPaths = {};
let desktopLaunched = false;
let appScanAt = null;
let appVersions = { desktop: null, science: null };
let appScanTimer;
let scanningApps;
let projectFolder;
let generation = 0;
let guardInfo = { enabled: false, rules: [], error: '尚未读取系统状态。' };
let guardTargets = [];
let config = { vpnHost: '127.0.0.1', vpnPort: 15236, residentialProtocol: 'http', residentialHost: '', residentialPort: '', username: '', password: '', expectedIp: '' };
const logs = [];
const page = pathToFileURL(path.join(__dirname, 'renderer/index.html')).href;
const dataDir = () => app.getPath('userData');

function state() {
  const apps = detectApps(appPaths);
  return { config: { ...config }, running: Boolean(service), port: LOCAL_PORT,
    exitIp, exitCountry, latencyMs, lastCheck, checkIntervalMs: CHECK_INTERVAL_MS, busy, logs: [...logs], projectFolder, guard: guardInfo, guardTargets,
    appPaths, appScanAt, appVersions, bridge: { ...bridgeInfo, active: Boolean(bridge) },
    apps: Object.fromEntries(Object.entries(apps).map(([name, executable]) => [name, Boolean(executable)])),
  };
}

function broadcast() {
  if (window && !window.isDestroyed()) window.webContents.send('helper:changed', state());
}

function log(level, message) {
  logs.unshift({ time: new Date().toISOString(), level, message });
  if (logs.length > 80) logs.length = 80;
  broadcast();
}

function loadConfig() {
  try { appPaths = JSON.parse(fs.readFileSync(path.join(dataDir(), 'app-paths.json'), 'utf8')); } catch { appPaths = {}; }
  const file = path.join(dataDir(), 'config.json');
  if (!fs.existsSync(file)) return;
  try {
    const stored = JSON.parse(fs.readFileSync(file, 'utf8'));
    const credentials = JSON.parse(safeStorage.decryptString(Buffer.from(stored.credentials, 'base64')));
    config = validateConfig({ ...stored.connection, ...credentials });
  } catch {
    log('error', '本地配置无法解密或格式不正确。请重新填写并保存；原文件会在保存时替换。');
  }
}

function saveConfig(input) {
  const next = validateConfig({ ...input, localPort: LOCAL_PORT });
  if (!safeStorage.isEncryptionAvailable()) throw new Error('Windows 凭据加密当前不可用，配置未保存。');
  const { username, password, ...connection } = next;
  const credentials = safeStorage.encryptString(JSON.stringify({ username, password })).toString('base64');
  fs.mkdirSync(dataDir(), { recursive: true });
  const file = path.join(dataDir(), 'config.json');
  fs.writeFileSync(`${file}.tmp`, JSON.stringify({ connection, credentials }, null, 2), { mode: 0o600 });
  fs.renameSync(`${file}.tmp`, file);
  config = next;
}

async function stopConnection() {
  generation++;
  monitor?.stop(); monitor = undefined;
  const previous = service;
  service = undefined;
  exitIp = null; exitCountry = null; lastCheck = null; latencyMs = null;
  await previous?.stop();
}

async function requireGuard(paths) {
  guardInfo = await guard.inspectGuard();
  const covered = new Set(guardInfo.rules.map(rule => rule.program.toLowerCase()));
  if (!guardInfo.enabled || paths.some(file => !covered.has(file.toLowerCase()))) {
    throw new Error('请先在直连阻断中启用这些程序的保护，再启动应用或 ProxyBridge。');
  }
}

function scanApps() {
  if (scanningApps) return scanningApps;
  scanningApps = (async () => {
    const previousDesktop = detectApps(appPaths).desktop;
    await refreshInstalledApps();
    const previousVersions = appVersions;
    appVersions = await readAppVersions(detectApps(appPaths));
    const discovered = await discoverGuardTargets(appPaths);
    if (previousDesktop !== detectApps(appPaths).desktop) desktopLaunched = false;
    const saved = new Map(guardTargets.map(target => [target.path.toLowerCase(), target]));
    let added = 0;
    for (const target of discovered) {
      if (!saved.has(target.path.toLowerCase())) added++;
      saved.set(target.path.toLowerCase(), target);
    }
    for (const rule of guardInfo.rules) {
      if (!saved.has(rule.program.toLowerCase())) saved.set(rule.program.toLowerCase(), { path: rule.program, label: '此前加入保护的程序', shared: true });
    }
    guardTargets = [...saved.values()];
    const wasScanned = appScanAt;
    appScanAt = new Date().toISOString();
    if (wasScanned && added) log('info', `自动版本追踪发现 ${added} 个新增程序路径。请补齐防火墙保护；若 ProxyBridge 正在运行，请重启拦截以更新规则。`);
    if (wasScanned) {
      for (const kind of ['desktop', 'science']) {
        if (previousVersions[kind] && appVersions[kind] && previousVersions[kind] !== appVersions[kind]) {
          log('info', `${kind === 'desktop' ? 'Desktop' : 'Science'} 可执行文件版本已变化：${previousVersions[kind]} → ${appVersions[kind]}。请核对新增路径保护，再从助手重新启动客户端。`);
        }
      }
    }
    broadcast();
  })().finally(() => { scanningApps = undefined; });
  return scanningApps;
}

function selectedTargets(paths) {
  const selected = guard.normalizePaths(paths);
  for (const file of selected) {
    if (!guardTargets.some(target => target.path.toLowerCase() === file.toLowerCase())) throw new Error('保护列表已变化，请重新扫描后重试。');
  }
  return selected;
}

function handle(name, action, locked = true) {
  ipcMain.handle(`helper:${name}`, async (event, ...args) => {
    if (event.sender !== window?.webContents || event.senderFrame !== window.webContents.mainFrame || event.senderFrame.url !== page) return { ok: false, error: '请求来源无效。' };
    if (locked && busy) return { ok: false, error: '上一项操作正在进行，请稍候。' };
    if (locked) { busy = true; broadcast(); }
    try {
      return await action(...args);
    } catch (error) {
      const message = error.code === 'EADDRINUSE' ? `本地端口 ${LOCAL_PORT} 已被占用，请关闭另一份连接助手后重试。` : error.message;
      log('error', message);
      return { ok: false, error: message };
    } finally {
      if (locked) { busy = false; broadcast(); }
    }
  });
}

if (!app.requestSingleInstanceLock()) {
  app.quit();
} else {
  app.on('second-instance', () => { if (window) { if (window.isMinimized()) window.restore(); window.show(); window.focus(); } });
  app.whenReady().then(() => {
    projectFolder = app.getPath('documents');
    loadConfig();
    handle('state', () => state(), false);
    handle('save', input => {
      if (service) throw new Error('请先停止连接，再修改配置。');
      saveConfig(input); log('info', '配置已保存，代理凭据已使用 Windows 账户加密。');
      return { ok: true };
    });
    handle('start', async input => {
      if (service) return { ok: true };
      const next = validateConfig({ ...input, localPort: LOCAL_PORT });
      if (!next.expectedIp) throw new Error('请填写服务商提供的预期静态出口 IP，严格模式必须核对固定美国出口。');
      const startGeneration = ++generation;
      const startedService = await startProxy(next, event => log(event.level, event.message), { allowTraffic: () => Boolean(exitIp) });
      if (startGeneration !== generation) { await startedService.stop(); throw new Error('启动已取消。'); }
      service = startedService;
      config = next; exitIp = null; exitCountry = null; lastCheck = null;
      monitor = createExitMonitor({ expectedIp: next.expectedIp, probe: signal => probeExit(next, signal),
        onVerified: result => {
          if (service !== startedService || startGeneration !== generation) throw new Error('代理已停止，检测结果已丢弃。');
          exitIp = result.ip; exitCountry = result.country; latencyMs = result.latencyMs; lastCheck = new Date().toISOString();
          log('info', `出口核对通过：${result.ip} · US · ${result.latencyMs} ms。下次检查约 30 秒后。`);
        },
        onFailure: async error => {
          if (service !== startedService) return;
          await stopConnection();
          log('error', `${error.message} 所有助手隧道已关闭；已启用的程序防火墙规则继续保留。`);
        },
      });
      log('info', '正在核对静态美国出口，检查通过前拒绝所有业务流量。');
      const result = await monitor.check();
      return { ok: true, ...result, message: '静态 IP 与美国归属核对通过，已启用持续监测。' };
    });
    handle('stop', async () => {
      await stopConnection();
      log('info', '助手代理已停止，现有隧道已断开。ProxyBridge 与防火墙保护如已启用会继续保留。');
      return { ok: true };
    }, false);
    handle('check', async () => {
      if (!service || !monitor) throw new Error('请先启动连接。');
      return { ok: true, ...await monitor.check() };
    });
    handle('launch', async kind => {
      if (!service || !exitIp) throw new Error('请先启动连接并通过固定美国出口检测。');
      if (!['browser', 'desktop', 'code', 'science'].includes(kind)) throw new Error('无效的应用入口。');
      const targets = await discoverGuardTargets(appPaths);
      const required = targets.filter(target => kind === 'browser' ? target.path.toLowerCase() === process.execPath.toLowerCase()
        : kind === 'desktop' ? target.label.startsWith('Claude 桌面版')
        : kind === 'science' ? target.label.startsWith('Claude Science') : target.label.startsWith('Claude Code'));
      if (!required.length) throw new Error('未找到此程序，请重新扫描或手动选择客户端。');
      await requireGuard(required.map(target => target.path));
      if (!service || !exitIp) throw new Error('连接已停止，请重新检测。');
      if (kind === 'browser') {
        await openBrowser(service.port, { onDesktopCallback: async url => {
          if (!desktopLaunched || !service || !exitIp) throw new Error('请先通过助手启动桌面版。');
          const desktop = detectApps(appPaths).desktop;
          await requireGuard([desktop]);
          if (!service || !exitIp) throw new Error('出口已失效。');
          await launchDesktopCallback(url, { port: service.port, appPaths });
          log('info', '已将登录回调交给 Claude 桌面版，未记录回调内容。');
        } });
        return { ok: true, message: '已打开专用浏览器；授权链接可通过“导航 → 粘贴并打开登录链接”打开。' };
      }
      const message = await launchApp(kind, { port: service.port, dataDir: dataDir(), folder: projectFolder, appPaths });
      if (kind === 'desktop') desktopLaunched = true;
      log('info', message);
      return { ok: true, message };
    });
    handle('select-app', async kind => {
      if (!['desktop', 'science'].includes(kind)) throw new Error('只能选择桌面客户端。');
      if (bridge) throw new Error('请先停止 ProxyBridge 再更改客户端路径。');
      const result = await dialog.showOpenDialog(window, { title: `选择 ${kind === 'desktop' ? 'Claude Desktop' : 'Claude Science'} 程序`, filters: [{ name: 'Windows 程序', extensions: ['exe'] }], properties: ['openFile'] });
      if (result.canceled) return { ok: true };
      appPaths[kind] = guard.normalizePaths(result.filePaths)[0];
      desktopLaunched = false;
      fs.mkdirSync(dataDir(), { recursive: true });
      fs.writeFileSync(path.join(dataDir(), 'app-paths.json'), JSON.stringify(appPaths, null, 2));
      const discovered = await discoverGuardTargets(appPaths);
      for (const target of discovered) {
        if (!guardTargets.some(existing => existing.path.toLowerCase() === target.path.toLowerCase())) guardTargets.push(target);
      }
      return { ok: true, message: '已记录客户端位置，请核对并启用新增程序的防火墙保护。' };
    });
    handle('folder', async () => {
      const result = await dialog.showOpenDialog(window, { title: '选择 Claude Code 项目文件夹', defaultPath: projectFolder, properties: ['openDirectory'] });
      if (result.canceled) return { ok: false, error: '未更改项目文件夹。' };
      projectFolder = result.filePaths[0];
      return { ok: true, path: projectFolder };
    });
    handle('guard-refresh', async () => {
      guardInfo = await guard.inspectGuard();
      await scanApps();
      return { ok: true };
    });
    handle('guard-add', async () => {
      const result = await dialog.showOpenDialog(window, { title: '添加使用 Claude API 的程序或子进程', filters: [{ name: 'Windows 程序', extensions: ['exe'] }], properties: ['openFile', 'multiSelections'] });
      if (result.canceled) return { ok: true };
      for (const file of result.filePaths) {
        if (/^veee\.exe$/i.test(path.basename(file))) throw new Error('Veee 是上游出口，不能加入阻断列表。');
        if (!guardTargets.some(target => target.path.toLowerCase() === file.toLowerCase())) guardTargets.push({ path: file, label: '手动添加的 API 程序', shared: true });
      }
      return { ok: true };
    });
    handle('guard-apply', async paths => {
      const selected = guard.normalizePaths(paths);
      for (const file of selected) {
        if (!guardTargets.some(target => target.path.toLowerCase() === file.toLowerCase())) throw new Error('保护列表已变化，请刷新后重试。');
      }
      const answer = await dialog.showMessageBox(window, { type: 'warning', title: '启用程序直连阻断',
        buttons: ['取消', '启用并请求管理员授权'], defaultId: 0, cancelId: 0,
        message: `将阻断 ${selected.length} 个程序的非回环外网连接。`,
        detail: `${selected.join('\n')}\n\n这些路径对应的所有进程都会受影响，包括共享 Node/Python 的其他任务。规则在助手退出后仍生效。可使用“恢复直连”移除本助手规则。` });
      if (answer.response !== 1) return { ok: false, error: '已取消，没有应用新规则。' };
      try { await guard.applyGuard(selected, dataDir()); }
      finally { guardInfo = await guard.inspectGuard(); }
      const applied = new Set(guardInfo.rules.map(rule => rule.program.toLowerCase()));
      if (!guardInfo.enabled || selected.some(file => !applied.has(file.toLowerCase()))) throw new Error('操作已结束，但无法确认所有规则有效。请刷新状态，当前不视为完全受保护。');
      log('info', `已确认 ${selected.length} 个程序的出站阻断规则生效。未列入的程序不在此保护范围内。`);
      return { ok: true, message: '所选程序直连阻断已启用。规则将在助手退出后继续保留。' };
    });
    handle('guard-remove', async () => {
      if (service || bridge) throw new Error('请先停止连接和 ProxyBridge，再恢复直连。');
      const answer = await dialog.showMessageBox(window, { type: 'question', title: '恢复程序直连',
        buttons: ['保留保护', '恢复直连'], defaultId: 0, cancelId: 0, message: '移除本助手创建的阻断规则？', detail: '所选程序之后可以直接访问外网。其他防火墙规则不会更改。' });
      if (answer.response !== 1) return { ok: false, error: '已保留保护。' };
      try { await guard.removeGuard(dataDir()); }
      finally { guardInfo = await guard.inspectGuard(); }
      if (guardInfo.rules.length || guardInfo.error) throw new Error('尚未确认所有本助手规则已移除，请刷新状态。');
      return { ok: true, message: '已移除本助手的防火墙规则。' };
    });
    handle('bridge-refresh', async () => {
      bridgeInfo = { ...await proxybridge.detectProxyBridge(), status: bridge ? bridge.status : '未启动' };
      return { ok: true };
    });
    handle('bridge-export', async paths => {
      const selected = selectedTargets(paths).filter(file => file.toLowerCase() !== process.execPath.toLowerCase());
      const profilePath = proxybridge.writeProfile(selected, { port: LOCAL_PORT, dataDir: dataDir() });
      dialog.showMessageBox(window, { type: 'info', message: '已生成独立 ProxyBridge 配置。', detail: `${profilePath}\n\n未覆盖你现有的 Default 配置，尚未启动流量拦截。` });
      return { ok: true, message: `配置已生成：${profilePath}` };
    });
    handle('bridge-start', async paths => {
      if (bridge) return { ok: true };
      if (!service || !exitIp) throw new Error('请先通过静态美国出口检测。');
      const selected = selectedTargets(paths).filter(file => file.toLowerCase() !== process.execPath.toLowerCase());
      await requireGuard(selected);
      const answer = await dialog.showMessageBox(window, { type: 'warning', title: '启动 ProxyBridge 程序拦截',
        buttons: ['取消', '启动并请求管理员授权'], defaultId: 0, cancelId: 0,
        message: `为 ${selected.length} 个程序启用独立代理规则。`,
        detail: `${selected.join('\n')}\n\n先阻断 UDP 和其他本机回环连接，再将 TCP 交给助手。会影响 MCP、本机工具和共享 Node/Python；已有连接请先自行退出客户端再重新启动。Windows 防火墙可能使未配置显式代理的程序连接失败。退出 ProxyBridge 后，本机回环阻断会失效。现有 Default 配置不变。` });
      if (answer.response !== 1) return { ok: false, error: '已取消。' };
      if (!service || !exitIp) throw new Error('出口已失效，请重新启动连接。');
      const bridgeGeneration = generation;
      bridgeInfo.status = '正在启动';
      const startedBridge = await proxybridge.startBridge(selected, { port: LOCAL_PORT, dataDir: dataDir(), onEvent: event => {
        if (event.type === 'connection') {
          const route = { proxy: '代理尝试', direct: '直连尝试', blocked: '已阻断' }[event.route];
          log(event.route === 'direct' ? 'error' : 'info', `ProxyBridge · ${path.basename(event.processPath)} PID ${event.pid} → ${event.destination}:${event.port} · ${route}（不代表出口已验证）`);
        } else if (event.type === 'status') {
          bridgeInfo.status = event.message;
          if (event.state === 'failed' || event.state === 'stopped') {
            bridge = undefined;
            if (event.state === 'failed') stopConnection().catch(() => {});
          }
          log(event.state === 'failed' ? 'error' : 'info', event.message);
        }
      } });
      if (quitting || !service || !exitIp || bridgeGeneration !== generation || startedBridge.status !== 'running') {
        await startedBridge.stop();
        throw new Error('连接已停止或出口失效，已关闭本次 ProxyBridge。');
      }
      bridge = startedBridge;
      return { ok: true, message: 'ProxyBridge 进程已启动。请查看实际连接记录，进程运行状态不能证明透明路由已成功。' };
    });
    handle('bridge-stop', async () => {
      if (!bridge) return { ok: true };
      const answer = await dialog.showMessageBox(window, { type: 'warning', message: '停止助手的 ProxyBridge 拦截？',
        detail: '将同时关闭助手代理。已启用的防火墙公网阻断保留，但其他本机代理的阻断会失效。', buttons: ['保持运行', '停止拦截'], defaultId: 0, cancelId: 0 });
      if (answer.response !== 1) return { ok: false, error: '已保留拦截。' };
      await stopConnection();
      const previous = bridge;
      await previous.stop();
      bridge = undefined; bridgeInfo.status = '已停止';
      return { ok: true };
    });
    window = new BrowserWindow({
      width: 1280, height: 920, minWidth: 1000, minHeight: 740,
      title: 'Claude 连接助手', backgroundColor: '#f5f6f3', autoHideMenuBar: true,
      webPreferences: { preload: path.join(__dirname, 'preload.cjs'), contextIsolation: true, nodeIntegration: false, sandbox: true },
    });
    window.webContents.setWindowOpenHandler(() => ({ action: 'deny' }));
    window.webContents.on('will-navigate', event => event.preventDefault());
    window.webContents.session.setPermissionRequestHandler((_, __, callback) => callback(false));
    window.on('close', event => {
      if (quitting) return;
      event.preventDefault();
      if (service || bridge) {
        const choice = dialog.showMessageBoxSync(window, { type: 'question', buttons: ['保持运行', '退出并断开连接'], defaultId: 0, cancelId: 0,
          title: '代理正在运行', message: '退出助手会断开使用此代理的 Claude 连接。', detail: '退出会停止助手的 ProxyBridge 拦截。程序防火墙规则继续保留，但其他本机代理的阻断将失效。继续研究或编程时请保持助手运行。' });
        if (choice === 0) return;
      }
      app.quit();
    });
    window.loadFile(path.join(__dirname, 'renderer/index.html'));
    proxybridge.detectProxyBridge().then(info => { bridgeInfo = { ...info, status: '未启动' }; broadcast(); }).catch(() => {});
    guard.inspectGuard().then(async info => { guardInfo = info; await scanApps(); }).catch(() => {});
    appScanTimer = setInterval(() => { if (!busy && !quitting) scanApps().catch(() => {}); }, 60000);
  });
  app.on('window-all-closed', () => app.quit());
  app.on('before-quit', event => {
    if (quitting) return;
    quitting = true;
    clearInterval(appScanTimer);
    if (!service && !bridge) { monitor?.stop(); return; }
    event.preventDefault();
    const previousBridge = bridge; bridge = undefined;
    Promise.allSettled([stopConnection(), previousBridge?.stop()]).finally(() => app.quit());
  });
}
