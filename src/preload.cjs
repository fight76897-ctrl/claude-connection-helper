const { contextBridge, ipcRenderer } = require('electron');

contextBridge.exposeInMainWorld('helper', {
  getState: () => ipcRenderer.invoke('helper:state'),
  saveConfig: config => ipcRenderer.invoke('helper:save', config),
  start: config => ipcRenderer.invoke('helper:start', config),
  stop: () => ipcRenderer.invoke('helper:stop'),
  check: () => ipcRenderer.invoke('helper:check'),
  launch: kind => ipcRenderer.invoke('helper:launch', kind),
  selectApp: kind => ipcRenderer.invoke('helper:select-app', kind),
  refreshBridge: () => ipcRenderer.invoke('helper:bridge-refresh'),
  exportBridge: paths => ipcRenderer.invoke('helper:bridge-export', paths),
  startBridge: paths => ipcRenderer.invoke('helper:bridge-start', paths),
  stopBridge: () => ipcRenderer.invoke('helper:bridge-stop'),
  chooseFolder: () => ipcRenderer.invoke('helper:folder'),
  refreshGuard: () => ipcRenderer.invoke('helper:guard-refresh'),
  addGuardTarget: () => ipcRenderer.invoke('helper:guard-add'),
  applyGuard: paths => ipcRenderer.invoke('helper:guard-apply', paths),
  removeGuard: () => ipcRenderer.invoke('helper:guard-remove'),
  onState: callback => {
    const listener = (_, state) => callback(state);
    ipcRenderer.on('helper:changed', listener);
    return () => ipcRenderer.removeListener('helper:changed', listener);
  },
});
