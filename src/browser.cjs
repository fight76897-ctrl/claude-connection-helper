const { BrowserWindow, session, Menu, clipboard, dialog } = require('electron');

let browserWindow;

function proxySettings(port) {
  return {
    mode: 'fixed_servers', proxyRules: `http://127.0.0.1:${port}`,
    proxyBypassRules: 'localhost;127.0.0.1;[::1]',
  };
}

function isDesktopCallback(url, sourceUrl) {
  try {
    if (typeof url !== 'string' || url.length > 8192 || /[\u0000-\u001f\u007f]/.test(url)) return false;
    const callback = new URL(url);
    const source = new URL(sourceUrl);
    return callback.protocol === 'claude:' && Boolean(callback.hostname) && !callback.username && !callback.password &&
      source.protocol === 'https:' && !source.username && !source.password &&
      (source.hostname === 'claude.ai' || source.hostname === 'anthropic.com' || source.hostname.endsWith('.anthropic.com'));
  } catch { return false; }
}

async function openBrowser(port, { onDesktopCallback } = {}) {
  const browserSession = session.fromPartition('persist:claude-residential-browser');
  await browserSession.setProxy(proxySettings(port));
  await browserSession.closeAllConnections();
  browserSession.setPermissionRequestHandler((_, permission, callback) => {
    callback(permission === 'clipboard-sanitized-write');
  });
  if (browserWindow && !browserWindow.isDestroyed()) {
    browserWindow.show(); browserWindow.focus(); return;
  }
  function desktopCallback(url, sourceUrl) {
    if (!onDesktopCallback || !isDesktopCallback(url, sourceUrl)) return;
    Promise.resolve().then(() => onDesktopCallback(url)).catch(() => {
      if (browserWindow && !browserWindow.isDestroyed()) {
        dialog.showMessageBox(browserWindow, { type: 'warning', message: '无法完成 Claude 桌面版登录回调。', detail: '请先通过连接助手启动 Claude 桌面版，并确认住宅出口检测通过，再重新登录。' });
      }
    });
  }
  function configure(contents) {
    contents.setWebRTCIPHandlingPolicy('disable_non_proxied_udp');
    const navigation = event => {
      if (/^https?:\/\//i.test(event.url)) return;
      event.preventDefault();
      let sourceUrl;
      try { sourceUrl = (event.initiator || event.frame)?.url; } catch { return; }
      desktopCallback(event.url, sourceUrl);
    };
    contents.on('will-frame-navigate', navigation);
    contents.on('will-redirect', navigation);
    contents.setWindowOpenHandler(({ url, referrer }) => {
      if (!/^https?:\/\//i.test(url)) {
        desktopCallback(url, referrer?.url);
        return { action: 'deny' };
      }
      return { action: 'allow', overrideBrowserWindowOptions: {
        width: 1120, height: 850,
        webPreferences: { session: browserSession, sandbox: true, nodeIntegration: false, contextIsolation: true },
      } };
    });
    contents.on('did-create-window', child => configure(child.webContents));
  }
  browserWindow = new BrowserWindow({
    width: 1180, height: 900, title: 'Claude · 专用住宅线路',
    backgroundColor: '#f7f6f2',
    webPreferences: { session: browserSession, sandbox: true, nodeIntegration: false, contextIsolation: true },
  });
  configure(browserWindow.webContents);
  const navigate = async url => {
    try { await browserWindow.loadURL(url); }
    catch {
      if (!browserWindow.isDestroyed()) dialog.showMessageBox(browserWindow, { type: 'warning', message: '页面连接失败。', detail: '请在连接助手中检测住宅出口。此窗口不会自动切换为直连。' });
    }
  };
  const menu = Menu.buildFromTemplate([
    { label: '导航', submenu: [
      { label: 'Claude 首页', click: () => navigate('https://claude.ai/') },
      { label: '后退', accelerator: 'Alt+Left', click: () => { if (browserWindow.webContents.navigationHistory.canGoBack()) browserWindow.webContents.navigationHistory.goBack(); } },
      { label: '刷新', accelerator: 'CmdOrCtrl+R', click: () => browserWindow.webContents.reload() },
      { type: 'separator' },
      { label: '粘贴并打开登录链接', click: () => {
        const url = clipboard.readText().trim();
        try {
          const parsed = new URL(url);
          if (!['https:', 'http:'].includes(parsed.protocol) || parsed.username || parsed.password) throw new Error();
          navigate(parsed.href);
        } catch { dialog.showMessageBox(browserWindow, { type: 'info', message: '请先复制完整的 http:// 或 https:// 登录链接。' }); }
      } },
      { label: '复制当前网址', click: () => clipboard.writeText(browserWindow.webContents.getURL()) },
      { type: 'separator' }, { role: 'close', label: '关闭窗口' },
    ] },
    { label: '编辑', submenu: [{ role: 'undo', label: '撤销' }, { role: 'cut', label: '剪切' }, { role: 'copy', label: '复制' }, { role: 'paste', label: '粘贴' }, { role: 'selectAll', label: '全选' }] },
    { label: '视图', submenu: [{ role: 'zoomIn', label: '放大' }, { role: 'zoomOut', label: '缩小' }, { role: 'resetZoom', label: '实际大小' }] },
  ]);
  browserWindow.setMenu(menu);
  browserWindow.webContents.on('page-title-updated', event => {
    event.preventDefault(); browserWindow.setTitle('Claude · 专用住宅线路');
  });
  await navigate('https://claude.ai/');
}

module.exports = { proxySettings, isDesktopCallback, openBrowser };
