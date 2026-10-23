!macro customUnInit
  IfSilent +2
    MessageBox MB_OK|MB_ICONINFORMATION "Before uninstalling, stop the helper and ProxyBridge and use Restore direct connection in the app (or restore-network.cmd) if you want to remove its firewall rules. Uninstall keeps your settings and existing firewall rules."
!macroend
