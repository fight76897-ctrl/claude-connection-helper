const fs = require('node:fs');
const path = require('node:path');
const { spawn, execFile } = require('node:child_process');
const { promisify } = require('node:util');
const runFile = promisify(execFile);
let packagedDesktopPaths = [];

async function refreshInstalledApps(run = runFile) {
  const script = '[Console]::OutputEncoding = [Text.Encoding]::UTF8; Get-AppxPackage -Name Claude | Select-Object -ExpandProperty InstallLocation | ConvertTo-Json -Compress';
  try {
    const { stdout } = await run('powershell.exe', ['-NoProfile', '-EncodedCommand', Buffer.from(script, 'utf16le').toString('base64')], { windowsHide: true, timeout: 12000 });
    const values = JSON.parse(stdout.replace(/^\uFEFF/, '') || '[]');
    packagedDesktopPaths = (Array.isArray(values) ? values : [values]).filter(value => typeof value === 'string' && path.isAbsolute(value))
      .map(directory => path.join(directory, 'app', 'Claude.exe'));
  } catch { /* Classic installs and manual selection remain available. */ }
}

function buildProxyEnv(base, port) {
  const env = {};
  for (const [key, value] of Object.entries(base)) {
    if (!['http_proxy', 'https_proxy', 'all_proxy', 'no_proxy', 'electron_run_as_node'].includes(key.toLowerCase())) env[key] = value;
  }
  env.HTTP_PROXY = env.HTTPS_PROXY = `http://127.0.0.1:${port}`;
  env.NO_PROXY = 'localhost,127.0.0.1,::1';
  return env;
}

function psQuote(value) { return `'${value.replaceAll("'", "''")}'`; }

async function readAppVersions(apps = detectApps(), run = runFile) {
  const versions = { desktop: null, science: null };
  const selected = Object.keys(versions).filter(kind => typeof apps[kind] === 'string' && /^[A-Za-z]:\\/.test(apps[kind]) && /\.exe$/i.test(apps[kind]) && !/[\x00-\x1f\x7f]/.test(apps[kind]));
  if (!selected.length) return versions;
  const clean = value => typeof value === 'string' && !/[\x00-\x1f\x7f]/.test(value) && /^[0-9][0-9A-Za-z.+_ -]{0,63}$/.test(value.trim()) ? value.trim() : null;
  const script = '[Console]::OutputEncoding = [Text.Encoding]::UTF8; $versions = @{}; ' + selected.map(kind =>
    `try { $v = (Get-Item -LiteralPath ${psQuote(apps[kind])} -ErrorAction Stop).VersionInfo; $versions[${psQuote(kind)}] = @{ product = $v.ProductVersion; file = $v.FileVersion } } catch { }`
  ).join('; ') + '; $versions | ConvertTo-Json -Compress';
  try {
    const { stdout } = await run('powershell.exe', ['-NoProfile', '-EncodedCommand', Buffer.from(script, 'utf16le').toString('base64')], { windowsHide: true, timeout: 12000, maxBuffer: 16384 });
    const data = JSON.parse(stdout.replace(/^\uFEFF/, '') || '{}');
    // These are executable metadata; Science's value may identify its Electron runtime.
    for (const kind of selected) versions[kind] = clean(data?.[kind]?.product) || clean(data?.[kind]?.file);
  } catch { /* Missing metadata does not prevent discovering or starting the app. */ }
  return versions;
}

function powershellCommand(executable, folder, settingsPath) {
  return `Set-Location -LiteralPath ${psQuote(folder)}; & ${psQuote(executable)}${settingsPath ? ` --settings ${psQuote(settingsPath)}` : ''}`;
}

function versionedExecutables(directory, executable, prefix = '') {
  try {
    return fs.readdirSync(directory, { withFileTypes: true })
      .filter(entry => entry.isDirectory() && entry.name.startsWith(prefix))
      .sort((a, b) => b.name.localeCompare(a.name, 'en', { numeric: true }))
      .map(entry => path.join(directory, entry.name, executable));
  } catch { return []; }
}

function desktopPaths() {
  const local = process.env.LOCALAPPDATA || '';
  return [
    ...packagedDesktopPaths,
    path.join(local, 'AnthropicClaude/claude.exe'),
    ...versionedExecutables(path.join(local, 'AnthropicClaude'), 'claude.exe', 'app-'),
    path.join(local, 'Programs/Claude/Claude.exe'),
    path.join(local, 'Programs/Claude/claude.exe'),
    path.join(process.env.ProgramFiles || '', 'Claude/Claude.exe'),
  ];
}

function detectApps(overrides = {}) {
  const first = paths => paths.find(p => p && fs.existsSync(p) && fs.statSync(p).isFile());
  const local = process.env.LOCALAPPDATA || '';
  const home = process.env.USERPROFILE || '';
  const directories = [path.join(process.env.USERPROFILE || '', '.local/bin'), ...(process.env.PATH || '').split(path.delimiter)];
  const code = first([overrides.code, ...directories.flatMap(p => ['claude.exe', 'claude.cmd'].map(name => path.join(p, name)))]);
  const desktop = first([overrides.desktop, ...desktopPaths()]);
  const science = first([overrides.science, path.join(local, 'Programs/ClaudeScience/claude-science.exe'),
    ...versionedExecutables(path.join(home, '.claude-science/electron'), 'claude-science.exe')]);
  return { browser: process.execPath, desktop, code, science };
}

function desktopProxyArgs(port) {
  return [`--proxy-server=http://127.0.0.1:${port}`, '--proxy-bypass-list=localhost;127.0.0.1;[::1]', '--disable-quic'];
}

function hasRunningExecutable(processes, paths) {
  const wanted = new Set((Array.isArray(paths) ? paths : [paths]).filter(Boolean).map(file => path.resolve(file).toLowerCase()));
  return processes.some(process => process.ExecutablePath && wanted.has(path.resolve(process.ExecutablePath).toLowerCase()));
}

async function readProcessPaths() {
  // Read process identities only: no arguments, environment variables or credentials.
  const script = '[Console]::OutputEncoding = [Text.Encoding]::UTF8; Get-CimInstance Win32_Process | Select-Object ProcessId,ParentProcessId,ExecutablePath | ConvertTo-Json -Compress';
  const { stdout } = await runFile('powershell.exe', ['-NoProfile', '-EncodedCommand', Buffer.from(script, 'utf16le').toString('base64')], { windowsHide: true, timeout: 12000 });
  const data = JSON.parse(stdout.replace(/^\uFEFF/, '') || '[]');
  return Array.isArray(data) ? data : data ? [data] : [];
}

function detached(executable, args, env, visible = false) {
  return new Promise((resolve, reject) => {
    const child = spawn(executable, args, { env, detached: true, stdio: 'ignore', windowsHide: !visible });
    child.once('error', () => reject(new Error('无法启动程序，请检查安装路径和系统权限。')));
    child.once('spawn', () => { child.unref(); resolve(); });
  });
}

async function launchApp(kind, { port, dataDir, folder, appPaths = {} }) {
  const apps = detectApps(appPaths);
  if (!['code', 'desktop', 'science'].includes(kind) || !apps[kind]) throw new Error('未找到此程序。请先安装官方客户端，或选择安装位置。');
  const env = buildProxyEnv(process.env, port);
  if (kind === 'desktop') {
    let processes;
    try { processes = await readProcessPaths(); }
    catch { throw new Error('无法确认 Claude 桌面版是否已退出，请关闭程序后重试。'); }
    if (hasRunningExecutable(processes, [apps.desktop, ...desktopPaths()])) {
      throw new Error('Claude 桌面版已在运行。请先保存任务并从托盘完全退出，再从这里启动，让新代理生效。');
    }
    await detached(apps.desktop, desktopProxyArgs(port), env);
    return '已通过住宅线路启动 Claude 桌面版。若登录页在默认浏览器打开，请把链接复制到专用浏览器完成登录。';
  }
  if (kind === 'science') {
    let output;
    try {
      ({ stdout: output } = await runFile('tasklist.exe', ['/FI', 'IMAGENAME eq claude-science.exe', '/FO', 'CSV', '/NH'], { windowsHide: true, timeout: 5000 }));
    } catch {
      throw new Error('无法确认 Science 是否已退出，请关闭 Science 后重试。');
    }
    if (output.toLowerCase().includes('"claude-science.exe"')) throw new Error('Science 已在运行。请先保存研究任务并从托盘完全退出 Science，再从这里启动，让新代理生效。');
    await detached(apps.science, [], env);
    return '已启动 Science。若授权页在默认浏览器打开，请把链接复制到专用浏览器完成登录。';
  }
  if (!fs.existsSync(folder) || !fs.statSync(folder).isDirectory()) throw new Error('请选择存在的项目文件夹。');
  const settingsPath = path.join(dataDir, 'code-proxy-settings.json');
  const proxy = `http://127.0.0.1:${port}`;
  const proxyEnv = { HTTP_PROXY: proxy, HTTPS_PROXY: proxy, http_proxy: proxy, https_proxy: proxy,
    ALL_PROXY: proxy, all_proxy: proxy, NO_PROXY: 'localhost,127.0.0.1,::1', no_proxy: 'localhost,127.0.0.1,::1' };
  fs.writeFileSync(settingsPath, JSON.stringify({ env: proxyEnv }, null, 2));
  const command = powershellCommand(apps.code, folder, settingsPath);
  const encoded = Buffer.from(command, 'utf16le').toString('base64');
  const powershell = path.join(process.env.SystemRoot || 'C:\\Windows', 'System32/WindowsPowerShell/v1.0/powershell.exe');
  await detached(powershell, ['-NoLogo', '-NoProfile', '-NoExit', '-EncodedCommand', encoded], env, true);
  return '已打开 Code 终端。用 /status 查看代理；首次登录请在专用浏览器打开授权链接。';
}

async function launchDesktopCallback(url, { port, appPaths = {} }) {
  if (typeof url !== 'string' || url.length > 8192 || /[\u0000-\u001f\u007f]/.test(url)) throw new Error('无效的桌面登录回调。');
  const parsed = new URL(url);
  if (parsed.protocol !== 'claude:' || !parsed.hostname || parsed.username || parsed.password) throw new Error('无效的桌面登录回调。');
  const desktop = detectApps(appPaths).desktop;
  if (!desktop) throw new Error('未找到 Claude 桌面版。');
  await detached(desktop, [...desktopProxyArgs(port), '--', url], buildProxyEnv(process.env, port));
}

async function discoverGuardTargets(appPaths = {}) {
  const apps = detectApps(appPaths);
  const candidates = new Map();
  const add = (executable, label, shared = false) => {
    if (executable && fs.existsSync(executable) && executable.toLowerCase().endsWith('.exe')) {
      if (!candidates.has(executable.toLowerCase())) candidates.set(executable.toLowerCase(), { path: executable, label, shared });
    }
  };
  add(process.execPath, '连接助手与内置专用浏览器');
  add(apps.desktop, 'Claude 桌面版');
  for (const executable of desktopPaths()) add(executable, 'Claude 桌面版');
  if (apps.desktop) {
    for (const name of ['chrome-native-host.exe', 'claude-ssh-broker.exe', 'claude-ssh-proxy.exe', 'cowork-svc.exe']) {
      add(path.join(path.dirname(apps.desktop), 'resources', name), 'Claude 桌面版附属程序（需核对使用范围）', true);
    }
  }
  add(apps.science, 'Claude Science');
  const scienceRuntimes = versionedExecutables(path.join(process.env.USERPROFILE || '', '.claude-science/electron'), 'claude-science.exe');
  for (const executable of scienceRuntimes) add(executable, 'Claude Science 浏览器进程');
  if (apps.code?.toLowerCase().endsWith('.exe')) add(apps.code, 'Claude Code');
  else if (apps.code) {
    const node = [path.join(path.dirname(apps.code), 'node.exe'), ...(process.env.PATH || '').split(path.delimiter).map(dir => path.join(dir, 'node.exe'))].find(file => fs.existsSync(file));
    add(node, 'Claude Code 使用的 Node.js（会影响此 Node 的其他任务）', true);
  }
  try {
    const processes = await readProcessPaths();
    const nativeApps = [apps.desktop, ...desktopPaths(), apps.science, ...scienceRuntimes, apps.code?.toLowerCase().endsWith('.exe') ? apps.code : null];
    const roots = new Set(processes.filter(p => hasRunningExecutable([p], nativeApps)).map(p => p.ProcessId));
    let changed = true;
    while (changed) {
      changed = false;
      for (const process of processes) {
        if (roots.has(process.ParentProcessId) && !roots.has(process.ProcessId)) {
          roots.add(process.ProcessId); changed = true;
          add(process.ExecutablePath, `当前 Claude 子进程：${path.basename(process.ExecutablePath || '')}`, true);
        }
      }
    }
  } catch { /* The core known paths remain available; custom tools can be added manually. */ }
  return [...candidates.values()];
}

module.exports = { buildProxyEnv, powershellCommand, desktopProxyArgs, hasRunningExecutable, detectApps, refreshInstalledApps, readAppVersions, launchApp, launchDesktopCallback, discoverGuardTargets };
