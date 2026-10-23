const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const { isIP } = require('node:net');
const { execFile } = require('node:child_process');
const { promisify } = require('node:util');
const run = promisify(execFile);
const ps = value => `'${String(value).replaceAll("'", "''")}'`;
const encode = value => Buffer.from(value, 'utf16le').toString('base64');
const powershell = () => path.join(process.env.SystemRoot || 'C:\\Windows', 'System32/WindowsPowerShell/v1.0/powershell.exe');
const MAX_LOG_BYTES = 8 * 1024 * 1024;
let activeBridge;

// Schema/CLI output checked against ProxyBridge 4.2.0, commit c855ffd931744d4685938dd19673893f2914c26e.
// This optional packet redirector is NOT fail closed: missing PID matches, engine stop/crash,
// and some special destinations bypass its rules. Persistent firewall protection is separate.
async function detectProxyBridge() {
  const candidates = ['E:\\tools\\proxybridge\\ProxyBridge_CLI.exe',
    ...[process.env.ProgramFiles, process.env['ProgramFiles(x86)'], process.env.LOCALAPPDATA]
      .filter(Boolean).map(root => path.join(root, 'ProxyBridge', 'ProxyBridge_CLI.exe')),
    ...(process.env.PATH || '').split(path.delimiter).filter(Boolean).map(root => path.join(root, 'ProxyBridge_CLI.exe'))];
  const cliPath = candidates.find(file => {
    try { return fs.statSync(file).isFile(); } catch { return false; }
  });
  if (!cliPath) return { installed: false, cliPath: null, version: null, compatible: false, running: [] };
  let version = null;
  try {
    const { stdout } = await run(cliPath, ['--help'], { windowsHide: true, timeout: 8000, maxBuffer: 65536 });
    version = stdout.match(/\bV?(\d+\.\d+\.\d+)\b/i)?.[1] || null;
  } catch { /* An unknown binary/version is never started. */ }
  try {
    const script = '[Console]::OutputEncoding=[Text.Encoding]::UTF8; @(Get-Process -Name ProxyBridge,ProxyBridge_CLI -ErrorAction SilentlyContinue | Select-Object Id,ProcessName) | ConvertTo-Json -Compress';
    const { stdout } = await run(powershell(), ['-NoLogo', '-NoProfile', '-EncodedCommand', encode(script)], { windowsHide: true, timeout: 10000, maxBuffer: 65536 });
    const value = JSON.parse(stdout.replace(/^\uFEFF/, '') || '[]');
    const running = (Array.isArray(value) ? value : value ? [value] : []).map(item => ({ pid: item.Id, name: item.ProcessName }));
    return { installed: true, cliPath, version, compatible: version === '4.2.0', running };
  } catch {
    return { installed: true, cliPath, version, compatible: false, running: [], error: '无法确认 ProxyBridge 是否已有控制器运行。' };
  }
}

function checkedPaths(paths) {
  if (!Array.isArray(paths) || !paths.length || paths.length > 100) throw new Error('请选择 1–100 个完整 .exe 路径。');
  const unique = new Map();
  for (const value of paths) {
    if (typeof value !== 'string' || !/^[A-Za-z]:\\/.test(value) || !/\.exe$/i.test(value) || /[\x00-\x1f"*?;,]/.test(value)) {
      throw new Error('ProxyBridge 规则必须使用完整本地 .exe 路径，不能含通配符或列表分隔符。');
    }
    const file = path.win32.normalize(value);
    // 4.2.0 CLI stores each rule's selector in a 256-byte buffer; do not let it truncate.
    if (Buffer.byteLength(file, 'utf8') > 240) throw new Error('此程序路径过长，ProxyBridge 4.2.0 CLI 无法完整读取。');
    if (!unique.has(file.toLowerCase())) unique.set(file.toLowerCase(), file);
  }
  return [...unique.values()];
}

function checkedPort(port) {
  if (!Number.isInteger(port) || port < 1 || port > 65535) throw new Error('助手端口无效。');
  return port;
}

function buildProfile(paths, { port }) {
  checkedPort(port);
  const groups = [];
  for (const file of checkedPaths(paths)) {
    const quoted = `"${file}"`;
    const previous = groups.at(-1);
    if (previous && Buffer.byteLength(previous + ';' + quoted, 'utf8') < 255) groups[groups.length - 1] += ';' + quoted;
    else groups.push(quoted);
  }
  const rule = (ProcessName, Name, Protocol, Action, TargetHosts = '*', TargetDomains = '*') => ({
    Name, ProcessName, TargetHosts, TargetDomains, TargetPorts: '*', Protocol, Action,
    IsEnabled: true, LocalhostViaProxy: true, ProxyConfigId: Action === 'PROXY' ? 1 : 0,
  });
  return {
    Version: '1.0', Name: 'Claude helper protected route', IsTrafficLoggingEnabled: true,
    AutoClearConnectionLogs: true, CloseToTray: false, NextProxyConfigId: 2,
    ProxyConfigs: [{ Id: 1, Name: 'Claude local helper', Type: 'HTTP', Host: '127.0.0.1',
      Port: String(port), Username: '', Password: '', SendDomainToProxy: true }],
    ProxyRules: [
      // HTTP proxy + UDP silently becomes DIRECT in 4.2.0 unless blocked first.
      ...groups.map(process => rule(process, 'Block selected UDP', 'UDP', 'BLOCK')),
      // The configured helper endpoint is globally bypassed before rule evaluation in 4.2.0.
      // All other loopback routes are blocked; local app IPC may therefore need review.
      ...groups.map(process => rule(process, 'Block alternate loopback', 'TCP', 'BLOCK', '127.0.0.0/8;::1;::ffff:127.0.0.0/104', '')),
      ...groups.map(process => rule(process, 'Selected TCP through helper', 'TCP', 'PROXY')),
    ], LogFilters: [],
  };
}

function writeProfile(paths, { port, dataDir }) {
  const profile = buildProfile(paths, { port });
  if (typeof dataDir !== 'string' || !path.isAbsolute(dataDir)) throw new Error('需要有效的助手数据目录。');
  const folder = path.join(dataDir, 'proxybridge');
  fs.mkdirSync(folder, { recursive: true });
  const profilePath = path.join(folder, 'claude-helper.pbprofile');
  fs.writeFileSync(profilePath, JSON.stringify(profile, null, 2), 'utf8');
  return profilePath;
}

function parseConnectionLine(line, { port, paths } = {}) {
  if (typeof line !== 'string' || line.length > 2048) return null;
  const match = line.match(/^\[CONN\] (.+\.exe) \(PID:(\d+)\) -> (.+):(\d+) via (Direct|Blocked|Proxy HTTP:\/\/127\.0\.0\.1:(\d+))( \(UDP\))?\r?$/i);
  if (!match || /[\x00-\x1f]/.test(match[1]) || !isIP(match[3]) || Number(match[4]) < 1 || Number(match[4]) > 65535 || Number(match[2]) < 1 || Number(match[2]) > 0xffffffff) return null;
  if (paths && !paths.some(file => file.toLowerCase() === match[1].toLowerCase())) return null;
  if (match[6] && (port === undefined || Number(match[6]) !== port)) return null;
  const route = match[5].toLowerCase() === 'direct' ? 'direct' : match[5].toLowerCase() === 'blocked' ? 'blocked' : 'proxy';
  return { type: 'connection', processPath: match[1], pid: Number(match[2]), destination: match[3], port: Number(match[4]),
    protocol: match[7] ? 'UDP' : 'TCP', route, outcome: route === 'blocked' ? 'blocked' : 'attempted', timestamp: new Date().toISOString() };
}

function buildStartScript({ cliPath, profilePath, logPath, errorPath, statePath, stopPath, parentPid, parentTicks }) {
  if (!Number.isSafeInteger(parentPid) || parentPid < 1 || !/^\d+$/.test(parentTicks)) throw new Error('父进程身份无效。');
  return `$ErrorActionPreference = 'Stop'
$child = $null
$reason = 'failed'
function Write-State($state, $why) {
  @{ state = $state; reason = $why } | ConvertTo-Json -Compress | Set-Content -LiteralPath ${ps(statePath)} -Encoding UTF8
}
function Parent-Alive {
  $owner = Get-Process -Id ${parentPid} -ErrorAction SilentlyContinue
  return ($null -ne $owner -and $owner.StartTime.ToUniversalTime().Ticks.ToString() -eq ${ps(parentTicks)})
}
try {
  if (-not (Parent-Alive)) { throw 'Parent process has exited' }
  if (@(Get-Process -Name ProxyBridge,ProxyBridge_CLI -ErrorAction SilentlyContinue).Count -gt 0) { throw 'Another controller is running' }
  if (Test-Path -LiteralPath ${ps(stopPath)}) { $reason = 'requested'; return }
  Write-State 'starting' ''
  $child = Start-Process -FilePath ${ps(cliPath)} -WorkingDirectory ${ps(path.win32.dirname(cliPath))} -WindowStyle Hidden -PassThru -RedirectStandardOutput ${ps(logPath)} -RedirectStandardError ${ps(errorPath)} -ArgumentList @('--profile', ${ps('"' + profilePath + '"')}, '--verbose', '2')
  Start-Sleep -Milliseconds 1000
  $child.Refresh()
  if (-not $child.HasExited) { Write-State 'process-running' '' }
  while (-not $child.HasExited) {
    if (Test-Path -LiteralPath ${ps(stopPath)}) { $reason = 'requested'; break }
    if (-not (Parent-Alive)) { $reason = 'parent-exit'; break }
    $log = Get-Item -LiteralPath ${ps(logPath)} -ErrorAction SilentlyContinue
    $errors = Get-Item -LiteralPath ${ps(errorPath)} -ErrorAction SilentlyContinue
    if (($log -and $log.Length -gt ${MAX_LOG_BYTES}) -or ($errors -and $errors.Length -gt ${MAX_LOG_BYTES})) { $reason = 'log-limit'; break }
    Start-Sleep -Milliseconds 500
    $child.Refresh()
    if (-not $child.HasExited) { Write-State 'process-running' '' }
  }
  if ($child.HasExited) { $reason = 'child-exit' }
} catch {
  $reason = 'failed'
} finally {
  if ($null -ne $child -and -not $child.HasExited) { $child.Kill(); $null = $child.WaitForExit(5000) }
  Write-State 'stopped' $reason
}
`;
}

async function createSession(paths, { port, dataDir, onEvent = () => {} }) {
  const programs = checkedPaths(paths);
  checkedPort(port);
  const installation = await detectProxyBridge();
  if (!installation.installed || !installation.compatible || installation.error) throw new Error(installation.error || '需要已验证的 ProxyBridge 4.2.0 CLI。');
  if (installation.running.length) throw new Error('ProxyBridge 已有窗口或 CLI 运行。请先自行退出，助手不会修改其配置。');
  const profilePath = writeProfile(programs, { port, dataDir });
  // The installed CLI uses ANSI argv + fopen_s, so Unicode profile paths are unsupported.
  if (/[^\x20-\x7e]/.test(profilePath) || profilePath.length >= 250 || profilePath.includes('"')) throw new Error('ProxyBridge 4.2.0 CLI 需要短的英文数据目录路径。');
  const sessionDir = path.join(path.dirname(profilePath), 'run-' + crypto.randomUUID());
  fs.mkdirSync(sessionDir);
  const logPath = path.join(sessionDir, 'connections.log');
  const errorPath = path.join(sessionDir, 'errors.log');
  const statePath = path.join(sessionDir, 'state.json');
  const stopPath = path.join(sessionDir, 'stop');
  const scriptPath = path.join(sessionDir, 'controller.ps1');
  let timer, state = 'starting', readiness = 'process-only', offset = 0, pending = '', stopped = false, expectedStop = false;
  let readyResolve, readyReject;
  const ready = new Promise((resolve, reject) => { readyResolve = resolve; readyReject = reject; });
  // UAC cancellation can happen before the readiness promise is awaited.
  ready.catch(() => {});
  const emit = event => { try { onEvent(event); } catch { /* UI callbacks cannot break cleanup. */ } };
  const stopMarker = () => { fs.writeFileSync(stopPath, 'stop', 'utf8'); };
  const finished = reason => {
    if (stopped) return;
    stopped = true;
    clearInterval(timer);
    if (activeBridge === session) activeBridge = null;
    state = expectedStop || reason === 'requested' ? 'stopped' : 'failed';
    const message = state === 'stopped' ? 'ProxyBridge 已停止；透明转发规则已卸载，请保持直连阻断。' : 'ProxyBridge 已退出，透明转发可能恢复直连。助手代理应立即停止，并检查防火墙保护。';
    emit({ type: 'status', state, message });
    readyReject(new Error(message));
  };
  const poll = () => {
    try {
      if (fs.existsSync(logPath)) {
        const size = fs.statSync(logPath).size;
        if (size < offset) { offset = 0; pending = ''; }
        const start = Math.max(offset, size - 65536);
        if (start > offset) pending = '';
        if (size > offset) {
          const length = Math.min(size - Math.max(offset, start), 65536);
          const buffer = Buffer.alloc(length);
          const fd = fs.openSync(logPath, 'r');
          try { fs.readSync(fd, buffer, 0, length, Math.max(offset, start)); } finally { fs.closeSync(fd); }
          offset = size;
          const lines = (pending + buffer.toString('utf8')).split('\n');
          pending = lines.pop().slice(-2048);
          for (const line of lines) {
            if (line.trim() === 'ProxyBridge is running. Press Ctrl+C to stop.' && readiness !== 'engine-banner') {
              readiness = 'engine-banner';
              state = 'running';
              emit({ type: 'status', state, readiness, message: 'ProxyBridge 已报告引擎启动。连接日志记录路由尝试，成功状态以助手隧道记录为准。' });
              readyResolve();
            }
            const event = parseConnectionLine(line, { port, paths: programs });
            if (event) emit(event);
          }
        }
      }
      if (fs.existsSync(statePath)) {
        const value = JSON.parse(fs.readFileSync(statePath, 'utf8').replace(/^\uFEFF/, ''));
        if (value.state === 'stopped') finished(value.reason);
        else if (state === 'running' && Date.now() - fs.statSync(statePath).mtimeMs > 6000) {
          try { stopMarker(); } finally { finished('controller-lost'); }
        }
        else if (value.state === 'process-running' && state === 'starting') {
          state = 'running';
          emit({ type: 'status', state, readiness, message: 'ProxyBridge CLI 进程已启动，实际路由仍需连接验证。' });
          readyResolve();
        }
      }
    } catch { /* A state file may be between writes; retry on the next bounded poll. */ }
  };
  const session = { profilePath, logPath, get status() { return state; }, get readiness() { return readiness; }, async stop() {
    if (stopped) return;
    expectedStop = true;
    stopMarker();
    for (let i = 0; i < 40 && !stopped; i++) { await new Promise(resolve => setTimeout(resolve, 250)); poll(); }
    if (!stopped) throw new Error('未确认 ProxyBridge 已停止，请检查任务管理器中的助手 CLI。');
  } };
  activeBridge = session;
  emit({ type: 'status', state: 'starting', message: '正在请求 Windows 管理员授权启动助手专用 ProxyBridge 会话。' });
  try {
    const parentQuery = `(Get-Process -Id ${process.pid} -ErrorAction Stop).StartTime.ToUniversalTime().Ticks.ToString()`;
    const { stdout } = await run(powershell(), ['-NoLogo', '-NoProfile', '-EncodedCommand', encode(parentQuery)], { windowsHide: true, timeout: 10000 });
    const parentTicks = stdout.trim();
    fs.writeFileSync(scriptPath, '\uFEFF' + buildStartScript({ cliPath: installation.cliPath, profilePath, logPath, errorPath, statePath, stopPath, parentPid: process.pid, parentTicks }), 'utf8');
    const command = encode(`& ${ps(scriptPath)}`);
    const bootstrap = `$ErrorActionPreference='Stop'; Start-Process -FilePath ${ps(powershell())} -Verb RunAs -WindowStyle Hidden -ArgumentList @('-NoLogo','-NoProfile','-ExecutionPolicy','Bypass','-EncodedCommand',${ps(command)}) | Out-Null`;
    await run(powershell(), ['-NoLogo', '-NoProfile', '-EncodedCommand', encode(bootstrap)], { windowsHide: true, timeout: 180000, maxBuffer: 65536 });
    timer = setInterval(poll, 500);
    timer.unref?.();
    const timeout = setTimeout(() => { try { stopMarker(); } catch { /* Parent monitor also stops an abandoned session. */ } finished('failed'); }, 20000);
    try { await ready; } finally { clearTimeout(timeout); }
    if (stopped || state !== 'running') throw new Error('ProxyBridge 在完成启动前已退出。请保持直连阻断。');
    return session;
  } catch (error) {
    try { stopMarker(); } catch { /* Parent monitor also stops an abandoned session. */ }
    if (!timer) finished('failed');
    throw new Error(error.message.includes('ProxyBridge') ? error.message : 'ProxyBridge 管理员授权未完成或启动失败。');
  }
}

async function startBridge(paths, options) {
  if (activeBridge) throw new Error('助手已有 ProxyBridge 会话，请先停止。');
  const reservation = {};
  activeBridge = reservation;
  try { return await createSession(paths, options); }
  catch (error) { if (activeBridge === reservation) activeBridge = null; throw error; }
}

module.exports = { detectProxyBridge, buildProfile, writeProfile, parseConnectionLine, buildStartScript, startBridge };
