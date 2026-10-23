param([switch]$Elevated, [string]$ResultFile)

$ErrorActionPreference = 'Stop'
$group = 'ClaudeConnectionHelper.OutboundGuard.v1'

if (-not $Elevated) {
    $resultPath = Join-Path ([IO.Path]::GetTempPath()) ('cch-restore-' + [guid]::NewGuid() + '.json')
    try {
        $scriptLiteral = "'" + $PSCommandPath.Replace("'", "''") + "'"
        $resultLiteral = "'" + $resultPath.Replace("'", "''") + "'"
        $command = "& $scriptLiteral -Elevated -ResultFile $resultLiteral"
        $encoded = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($command))
        Write-Host 'Requesting administrator access to remove only Claude Connection Helper rules...'
        Start-Process -FilePath (Join-Path $PSHOME 'powershell.exe') -Verb RunAs -WindowStyle Hidden -Wait -ArgumentList @('-NoLogo', '-NoProfile', '-ExecutionPolicy', 'Bypass', '-EncodedCommand', $encoded)
        if (-not (Test-Path -LiteralPath $resultPath)) { throw 'No result received. Check the Windows administrator prompt.' }
        $result = Get-Content -LiteralPath $resultPath -Raw | ConvertFrom-Json
        if (-not $result.ok) { throw $result.error }
        Write-Host 'Helper rules removed. Other firewall rules were not changed.' -ForegroundColor Green
        Write-Host 'Quit apps started by the helper and reopen normally to clear their proxy settings.'
    } catch {
        Write-Host ('Restore failed or cancelled: ' + $_.Exception.Message) -ForegroundColor Red
        exit 1
    } finally {
        if (Test-Path -LiteralPath $resultPath) { Remove-Item -LiteralPath $resultPath -Force }
    }
    exit 0
}

try {
    Get-NetFirewallRule -Group $group -ErrorAction SilentlyContinue | Remove-NetFirewallRule
    $remaining = @(Get-NetFirewallRule -Group $group -ErrorAction SilentlyContinue)
    if ($remaining.Count -gt 0) { throw 'Some helper rules remain. Check your organization policy.' }
    @{ ok = $true } | ConvertTo-Json -Compress | Set-Content -LiteralPath $ResultFile -Encoding UTF8
} catch {
    @{ ok = $false; error = $_.Exception.Message } | ConvertTo-Json -Compress | Set-Content -LiteralPath $ResultFile -Encoding UTF8
    exit 1
}
