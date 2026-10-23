const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const { execFile } = require('node:child_process');
const { promisify } = require('node:util');
const run = promisify(execFile);

const GROUP = 'ClaudeConnectionHelper.OutboundGuard.v1';
const REMOTE_RANGES = ['0.0.0.0-126.255.255.255', '128.0.0.0-255.255.255.255', '::2-ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff'];
const ps = value => `'${value.replaceAll("'", "''")}'`;
const powershell = () => path.join(process.env.SystemRoot || 'C:\\Windows', 'System32/WindowsPowerShell/v1.0/powershell.exe');
const encode = value => Buffer.from(value, 'utf16le').toString('base64');

function normalizePaths(paths) {
  if (!Array.isArray(paths) || !paths.length || paths.length > 100) throw new Error('请选择 1–100 个需要保护的程序。');
  const found = new Map();
  for (const value of paths) {
    if (typeof value !== 'string' || !/^[A-Za-z]:\\/.test(value) || !value.toLowerCase().endsWith('.exe') || /[\r\n\0"*?]/.test(value)) throw new Error('保护范围必须是本地程序的完整 .exe 路径。');
    const normalized = path.win32.normalize(value);
    if (!found.has(normalized.toLowerCase())) found.set(normalized.toLowerCase(), normalized);
  }
  return [...found.values()];
}

function resultWrapper(body, resultFile) {
  return `$ErrorActionPreference = 'Stop'\ntry {\n${body}\n  @{ ok = $true } | ConvertTo-Json -Compress | Set-Content -LiteralPath ${ps(resultFile)} -Encoding UTF8\n} catch {\n  @{ ok = $false; error = $_.Exception.Message } | ConvertTo-Json -Compress | Set-Content -LiteralPath ${ps(resultFile)} -Encoding UTF8\n  exit 1\n}\n`;
}

function buildApplyScript(paths, resultFile) {
  const programs = normalizePaths(paths);
  const names = programs.map(program => 'CCH-Guard-v1-' + crypto.createHash('sha256').update(program.toLowerCase()).digest('hex').slice(0, 20));
  const lines = [
    "  if ((Get-Service MpsSvc).Status -ne 'Running') { throw 'Windows 防火墙服务未运行，请先在系统设置中启用。' }",
    '  $profiles = @(Get-NetFirewallProfile -PolicyStore ActiveStore)',
    "  if ($profiles.Count -ne 3 -or @($profiles | Where-Object { -not $_.Enabled -or $_.AllowLocalFirewallRules -eq 'False' }).Count -gt 0) { throw '防火墙配置未全部启用，或组织策略禁用了本地规则。未应用保护。' }",
  ];
  programs.forEach((program, index) => {
    lines.push(`  if (-not (Test-Path -LiteralPath ${ps(program)} -PathType Leaf)) { throw '一个所选程序已移动或不存在。' }`);
    lines.push(`  $old = Get-NetFirewallRule -Name ${ps(names[index])} -ErrorAction SilentlyContinue`);
    lines.push(`  if ($old -and $old.Group -ne ${ps(GROUP)}) { throw '规则名称被其他程序占用，未修改现有规则。' }`);
    const displayName = ps('Claude 连接助手 · ' + path.win32.basename(program));
    const settings = `-Name ${ps(names[index])} -Direction Outbound -Action Block -Enabled True -Profile Any -Protocol Any -Program ${ps(program)} -RemoteAddress @(${REMOTE_RANGES.map(ps).join(',')})`;
    lines.push(`  if ($old) { Set-NetFirewallRule ${settings} -NewDisplayName ${displayName} | Out-Null } else { New-NetFirewallRule ${settings} -DisplayName ${displayName} -Group ${ps(GROUP)} | Out-Null }`);
  });
  lines.push(`  $keep = @(${names.map(ps).join(',')})`);
  lines.push(`  Get-NetFirewallRule -Group ${ps(GROUP)} -ErrorAction SilentlyContinue | Where-Object { $_.Name -notin $keep } | Remove-NetFirewallRule`);
  return resultWrapper(lines.join('\n'), resultFile);
}

function buildRemoveScript(resultFile) {
  return resultWrapper(`  Get-NetFirewallRule -Group ${ps(GROUP)} -ErrorAction SilentlyContinue | Remove-NetFirewallRule`, resultFile);
}

function parseInspection(text) {
  const value = JSON.parse(text.replace(/^\uFEFF/, ''));
  const profiles = Array.isArray(value.profiles) ? value.profiles : [];
  return {
    enabled: value.serviceRunning === true && profiles.length === 3 && profiles.every(p => p.enabled === true && p.localAllowed === true),
    rules: Array.isArray(value.rules) ? value.rules : [],
  };
}

async function inspectGuard() {
  const script = `$ErrorActionPreference = 'Stop'
[Console]::OutputEncoding = [Text.Encoding]::UTF8
$profiles = @(Get-NetFirewallProfile -PolicyStore ActiveStore | ForEach-Object { @{ enabled = [bool]$_.Enabled; localAllowed = ($_.AllowLocalFirewallRules -ne 'False') } })
$required = @(${REMOTE_RANGES.map(ps).join(',')})
$rules = @(Get-NetFirewallRule -PolicyStore ActiveStore -Group ${ps(GROUP)} -ErrorAction SilentlyContinue | ForEach-Object {
  $rule = $_
  $remote = @($rule | Get-NetFirewallAddressFilter | Select-Object -ExpandProperty RemoteAddress)
  $protocol = ($rule | Get-NetFirewallPortFilter).Protocol
  $profile = [string]$rule.Profile
  if ($rule.Enabled -eq 'True' -and $rule.Direction -eq 'Outbound' -and $rule.Action -eq 'Block' -and $protocol -eq 'Any' -and $profile -eq 'Any' -and $remote.Count -eq $required.Count -and @($required | Where-Object { $_ -notin $remote }).Count -eq 0) {
    @{ name = $rule.Name; program = [string]($rule | Get-NetFirewallApplicationFilter).Program }
  }
})
@{ profiles = $profiles; rules = $rules; serviceRunning = ((Get-Service MpsSvc).Status -eq 'Running') } | ConvertTo-Json -Depth 5 -Compress`;
  try {
    const { stdout } = await run(powershell(), ['-NoLogo', '-NoProfile', '-EncodedCommand', encode(script)], { windowsHide: true, timeout: 15000, maxBuffer: 1024 * 1024 });
    return parseInspection(stdout);
  } catch {
    return { enabled: false, rules: [], error: '无法确认 Windows 防火墙状态，当前不视为受保护。' };
  }
}

async function elevate(builder, dataDir) {
  fs.mkdirSync(dataDir, { recursive: true });
  const id = crypto.randomUUID();
  const scriptFile = path.join(dataDir, `firewall-${id}.ps1`);
  const resultFile = path.join(dataDir, `firewall-${id}.json`);
  fs.writeFileSync(scriptFile, '\uFEFF' + builder(resultFile), 'utf8');
  const encoded = encode(`& ${ps(scriptFile)}`);
  const bootstrap = `$ErrorActionPreference='Stop'; Start-Process -FilePath ${ps(powershell())} -Verb RunAs -WindowStyle Hidden -ArgumentList @('-NoLogo','-NoProfile','-ExecutionPolicy','Bypass','-EncodedCommand',${ps(encoded)}) -Wait`;
  let launchFailed = false;
  try {
    try { await run(powershell(), ['-NoLogo', '-NoProfile', '-EncodedCommand', encode(bootstrap)], { windowsHide: true, timeout: 180000 }); }
    catch { launchFailed = true; }
    if (!fs.existsSync(resultFile)) throw new Error(launchFailed ? 'Windows 管理员授权未完成或已取消，未确认规则变更。' : '未取得防火墙操作结果，请刷新保护状态。');
    const result = JSON.parse(fs.readFileSync(resultFile, 'utf8').replace(/^\uFEFF/, ''));
    if (!result.ok) throw new Error(`防火墙操作失败：${result.error}`);
    return { ok: true };
  } finally {
    for (const file of [scriptFile, resultFile]) {
      try { fs.unlinkSync(file); } catch { /* A still-running elevated process may own the file. */ }
    }
  }
}

async function applyGuard(paths, dataDir) {
  const programs = normalizePaths(paths);
  return elevate(resultFile => buildApplyScript(programs, resultFile), dataDir);
}

async function removeGuard(dataDir) {
  return elevate(buildRemoveScript, dataDir);
}

module.exports = { GROUP, REMOTE_RANGES, normalizePaths, buildApplyScript, buildRemoveScript, parseInspection, inspectGuard, applyGuard, removeGuard };
