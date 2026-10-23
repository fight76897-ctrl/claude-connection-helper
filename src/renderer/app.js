'use strict';

const byId = id => document.getElementById(id);
const api = window.helper;
const configFields = {
  vpnHost: 'vpn-host', vpnPort: 'vpn-port',
  residentialProtocol: 'proxy-protocol', residentialHost: 'proxy-host', residentialPort: 'proxy-port',
  username: 'proxy-username', password: 'proxy-password', localPort: 'local-port',
  expectedIp: 'expected-ip',
};
let current = { running: false, busy: false, logs: [], apps: {}, port: 17861 };
let pending = '';
let exitError = '';
let initialized = false;
const hiddenLogs = new Set();
const targetChoices = new Map();

function renderGuard(busy) {
  const guard = current.guard || { enabled: false, rules: [] };
  const covered = new Set(guard.rules.map(rule => rule.program.toLowerCase()));
  const targets = current.guardTargets || [];
  const list = byId('guard-targets');
  list.replaceChildren();
  for (const target of targets) {
    if (!targetChoices.has(target.path)) targetChoices.set(target.path, true);
    const row = document.createElement('label'); row.className = 'guard-target';
    const checkbox = document.createElement('input'); checkbox.type = 'checkbox';
    checkbox.checked = targetChoices.get(target.path); checkbox.disabled = busy;
    checkbox.addEventListener('change', () => targetChoices.set(target.path, checkbox.checked));
    const description = document.createElement('span');
    const name = document.createElement('strong'); name.textContent = target.label;
    const file = document.createElement('small'); file.textContent = target.path;
    description.append(name, file);
    const coverage = document.createElement('span'); coverage.className = 'coverage';
    coverage.textContent = guard.enabled && covered.has(target.path.toLowerCase()) ? '规则有效' : '未保护';
    row.append(checkbox, description, coverage); list.append(row);
  }
  const activeCount = guard.enabled ? covered.size : 0;
  byId('guard-status').textContent = activeCount ? `${activeCount} 个程序有阻断规则` : '尚未启用';
  byId('guard-status').classList.toggle('protected-tag', activeCount > 0);
  byId('guard-detail').textContent = guard.error || (guard.enabled
    ? activeCount ? '有效规则已从 Windows 读取。程序通过助手发起的连接走住宅代理；直接访问外网会被阻断。' : 'Windows 防火墙可用。请核对程序列表，再启用所选保护。'
    : '系统防火墙未全部启用，或本地规则被组织策略限制。当前无法确认阻断有效。');
  for (const action of ['refresh', 'add', 'apply', 'remove']) byId(`guard-${action}`).disabled = busy || (action === 'apply' && !targets.length);
}

function showNotice(message, isError = false) {
  const notice = byId('notice');
  notice.textContent = message;
  notice.classList.toggle('error', isError);
  notice.hidden = !message;
}

function readConfig() {
  return Object.fromEntries(Object.entries(configFields).map(([key, id]) => [
    key, key.endsWith('Port') ? Number(byId(id).value) : byId(id).value,
  ]));
}

function fillConfig(config = {}) {
  for (const [key, id] of Object.entries(configFields)) {
    if (config[key] !== undefined) byId(id).value = config[key];
  }
  byId('local-port').value = current.port;
  byId('password-hint').textContent = config.password
    ? '已加载本机保存的密码；清空后保存可移除密码。'
    : '凭据通过 Windows 账户加密保存。';
}

function updateRoute() {
  const config = current.running ? current.config : readConfig();
  byId('vpn-summary').textContent = config?.vpnHost && config?.vpnPort
    ? `${config.vpnHost}:${config.vpnPort}` : '等待配置';
  byId('residential-summary').textContent = config?.residentialHost && config?.residentialPort
    ? `${config.residentialProtocol === 'socks5' ? 'SOCKS5' : 'HTTP'} · ${config.residentialHost}:${config.residentialPort}` : '等待配置';
}

function formatTime(value) {
  return new Date(value).toLocaleTimeString('zh-CN', { hour12: false });
}

function logKey(entry) { return `${entry.time}|${entry.level}|${entry.message}`; }

function renderLogs() {
  const container = byId('log-list');
  const entries = current.logs.filter(entry => !hiddenLogs.has(logKey(entry)));
  container.replaceChildren();
  if (!entries.length) {
    const empty = document.createElement('p');
    empty.className = 'log-empty';
    empty.textContent = '暂无连接记录。启动连接后，这里会显示线路活动。';
    container.append(empty);
    return;
  }
  for (const entry of entries) {
    const row = document.createElement('div');
    row.className = entry.level === 'error' ? 'log-entry error' : 'log-entry';
    const time = document.createElement('time');
    time.dateTime = entry.time;
    time.textContent = formatTime(entry.time);
    const message = document.createElement('span');
    message.textContent = entry.message;
    row.append(time, message);
    container.append(row);
  }
}

function render() {
  const busy = current.busy || Boolean(pending);
  const running = current.running;
  const checking = pending === 'check';
  const status = byId('connection-status');
  status.classList.toggle('connected', running);
  byId('connection-status-text').textContent = running ? current.exitIp ? '美国出口监测中' : '出口核对中' : '未连接';
  byId('local-address').textContent = running ? `127.0.0.1:${current.port}` : '未启动';
  byId('toggle-connection').textContent = running ? '停止连接' : pending === 'start' ? '正在启动…' : '启动连接 →';
  // Stop stays available while a network check is pending.
  byId('toggle-connection').disabled = (busy && !running) || pending === 'stop';
  byId('test-connection').disabled = !running || busy;
  byId('test-connection').textContent = checking ? '检测中…' : '检测出口';
  byId('config-fields').disabled = running || busy;
  byId('save-config').disabled = running || busy;
  byId('save-config').textContent = pending === 'save' ? '保存中…' : '保存配置';
  byId('config-help').textContent = running ? '停止连接后可修改配置。' : '修改配置后保存，再启动连接。';
  byId('choose-directory').disabled = busy;
  byId('working-directory').value = current.projectFolder || '';
  byId('working-directory').title = current.projectFolder || '';
  byId('launch-help').textContent = current.exitIp ? '出口监测中。须先启用对应程序的直连阻断。' : '填写预期 IP，启动后自动检测美国出口。';
  for (const kind of ['browser', 'desktop', 'code', 'science']) {
    const button = byId(`launch-${kind}`);
    button.disabled = !running || !current.exitIp || busy || !current.apps[kind];
    button.title = current.apps[kind] ? (running ? '' : '请先启动连接') : '未检测到程序，请先安装官方客户端';
  }
  byId('exit-ip').textContent = current.exitIp || '未检测';
  byId('exit-check-status').textContent = checking ? '检测中' : current.exitIp ? '已检测' : exitError ? '检测失败' : '尚未检测';
  byId('exit-latency').textContent = current.exitIp && current.latencyMs != null ? `${current.latencyMs} ms` : '—';
  byId('exit-detail').textContent = checking ? '正通过 VPN 和住宅代理查询出口…'
    : current.exitIp ? `美国 US · ${formatTime(current.lastCheck)} 核对通过。每 30 秒复查，失败断开助手隧道。`
    : exitError || '启动时核对静态 IP + US，通过前拒绝业务流量。每 30 秒复查；单次超时最多 25 秒。';
  updateRoute();
  renderLogs();
  renderGuard(busy);
  const bridge = current.bridge || {};
  byId('bridge-status').textContent = bridge.active ? '进程运行中' : bridge.installed ? `已安装 ${bridge.version || '未知版本'}` : '未检测到';
  byId('bridge-detail').textContent = bridge.status || '未启动';
  byId('bridge-start').disabled = busy || bridge.active || !bridge.compatible || !current.exitIp;
  byId('bridge-stop').disabled = busy || !bridge.active;
  byId('bridge-export').disabled = busy;
  byId('bridge-refresh').disabled = busy;
  const versions = current.appVersions || {};
  byId('version-detail').textContent = `可执行文件版本：Desktop ${versions.desktop || '未读取'} · Science ${versions.science || '未读取'}。每分钟追踪，${current.appScanAt ? `最近扫描 ${formatTime(current.appScanAt)}。` : '等待首次扫描。'}新增路径须补齐保护，并重启 ProxyBridge。`;
  for (const kind of ['desktop', 'science']) byId(`select-${kind}`).disabled = busy || bridge.active;
}

function applyState(next) {
  current = next;
  if (!initialized) {
    fillConfig(next.config);
    initialized = true;
  }
  render();
}

async function perform(name, action, successMessage) {
  pending = name;
  showNotice('');
  render();
  try {
    const result = await action();
    if (!result.ok) throw new Error(result.error || '操作未完成，请查看连接记录。');
    if (name === 'folder') current.projectFolder = result.path;
    if (successMessage || result.message) showNotice(result.message || successMessage);
    return result;
  } catch (error) {
    if (name === 'check') exitError = error.message;
    showNotice(error.message || '操作失败，请重试。', true);
  } finally {
    if (pending === name) pending = '';
    render();
  }
}

byId('config-form').addEventListener('submit', async event => {
  event.preventDefault();
  await perform('save', () => api.saveConfig(readConfig()), '配置已保存，代理凭据已加密。');
});

byId('config-form').addEventListener('input', updateRoute);

byId('toggle-connection').addEventListener('click', async () => {
  exitError = '';
  if (current.running) {
    await perform('stop', () => api.stop(), '已停止连接，使用此代理的客户端连接已断开。');
  } else if (byId('config-form').reportValidity()) {
    await perform('start', () => api.start(readConfig()), '静态美国出口已验证，持续监测已开始。');
  }
});

byId('test-connection').addEventListener('click', async () => {
  exitError = '';
  await perform('check', () => api.check(), '静态 IP 与美国归属核对通过。');
});

byId('toggle-password').addEventListener('click', () => {
  const password = byId('proxy-password');
  const show = password.type === 'password';
  password.type = show ? 'text' : 'password';
  byId('toggle-password').textContent = show ? '隐藏' : '显示';
  byId('toggle-password').setAttribute('aria-label', show ? '隐藏密码' : '显示密码');
  byId('toggle-password').title = show ? '隐藏密码' : '显示密码';
});

byId('choose-directory').addEventListener('click', () => perform('folder', () => api.chooseFolder()));
byId('guard-refresh').addEventListener('click', () => perform('guard', () => api.refreshGuard()));
byId('guard-add').addEventListener('click', () => perform('guard', () => api.addGuardTarget()));
byId('guard-apply').addEventListener('click', () => perform('guard', () => api.applyGuard([...targetChoices].filter(([, enabled]) => enabled).map(([file]) => file))));
byId('guard-remove').addEventListener('click', () => perform('guard', () => api.removeGuard()));
for (const kind of ['browser', 'desktop', 'code', 'science']) {
  byId(`launch-${kind}`).addEventListener('click', () => perform('launch', () => api.launch(kind)));
}

for (const kind of ['desktop', 'science']) byId(`select-${kind}`).addEventListener('click', () => perform('select-app', () => api.selectApp(kind)));
const selectedBridgePaths = () => [...targetChoices].filter(([, enabled]) => enabled).map(([file]) => file);
byId('bridge-refresh').addEventListener('click', () => perform('bridge', () => api.refreshBridge()));
byId('bridge-export').addEventListener('click', () => perform('bridge', () => api.exportBridge(selectedBridgePaths())));
byId('bridge-start').addEventListener('click', () => perform('bridge', () => api.startBridge(selectedBridgePaths())));
byId('bridge-stop').addEventListener('click', () => perform('bridge', () => api.stopBridge()));

byId('clear-logs').addEventListener('click', () => {
  for (const entry of current.logs) hiddenLogs.add(logKey(entry));
  renderLogs();
});

for (const link of document.querySelectorAll('.nav-item')) {
  link.addEventListener('click', event => {
    event.preventDefault();
    for (const item of document.querySelectorAll('.nav-item')) item.classList.remove('active');
    link.classList.add('active');
    document.querySelector(link.getAttribute('href')).scrollIntoView({ behavior: 'smooth', block: 'start' });
  });
}

if (api) {
  api.onState(applyState);
  api.getState().then(applyState).catch(() => {
    showNotice('无法读取应用状态，请关闭并重新启动连接助手。', true);
    byId('config-fields').disabled = true;
    for (const button of document.querySelectorAll('button')) button.disabled = true;
  });
} else {
  showNotice('请通过桌面应用打开此界面，连接功能需要本地主进程。', true);
  byId('config-fields').disabled = true;
  for (const button of document.querySelectorAll('button')) button.disabled = true;
}
