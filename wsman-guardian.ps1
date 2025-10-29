# DMZ Security Posture Validation – WMI/WS-Man/WSUS focused (Windows Server 2025)
# NIST refs: SC-7 (Boundary Protection), CM-6/CM-7 (Config/Least Functionality), IA-2/IA-5, SC-12 (TLS), SI-4 (Monitoring)

$ErrorActionPreference = 'SilentlyContinue'
$Host.UI.RawUI.WindowTitle = "DMZ Security Posture Validation - $(hostname)"

$DMZServerName   = $env:COMPUTERNAME
$TargetPorts     = @(135, 5985, 5986, 8530, 8531)
$DynamicPortLow  = 49152
$DynamicPortHigh = 65535

Write-Host "--- DMZ Security Posture Validation (WMI/WS-Man/WSUS Focus) ---" -ForegroundColor Yellow
Write-Host ("Host: {0} | Time: {1}" -f $DMZServerName,(Get-Date)) -ForegroundColor DarkGray

# Utility: quick table
function Show-Table([Parameter(ValueFromPipeline=$true)]$InputObject) {
  $InputObject | Format-Table -AutoSize | Out-String | Write-Host
}

# Utility: ensure host firewall block exists for a port
function Ensure-BlockRule {
  param([int]$Port,[string]$NamePrefix="DMZ-BLOCK")
  $ruleName = "$NamePrefix-TCP-$Port"
  $existing = Get-NetFirewallRule -DisplayName $ruleName -ErrorAction SilentlyContinue
  if (-not $existing) {
    New-NetFirewallRule -DisplayName $ruleName -Direction Inbound -Protocol TCP -LocalPort $Port -Action Block -Profile Domain,Private,Public | Out-Null
    Write-Host ("  + Created host firewall BLOCK rule for TCP/{0}" -f $Port) -ForegroundColor Green
  } else {
    if ($existing.Enabled -ne 'True') { Enable-NetFirewallRule -DisplayName $ruleName | Out-Null }
    Write-Host ("  = BLOCK rule already present for TCP/{0}" -f $Port) -ForegroundColor Cyan
  }
}

# --- [1] DCOM/WMI exposure (135 + dynamic) ---
Write-Host "`n[1] Checking WMI/DCOM Endpoints (Port 135 & Dynamic Range)" -ForegroundColor Cyan

$DCOMListener = Get-NetTCPConnection | Where-Object { $_.State -eq 'Listen' -and $_.LocalPort -eq 135 }
if ($DCOMListener) {
  Write-Host "CRITICAL RISK: TCP/135 (DCOM/RPC) is LISTENING." -ForegroundColor Red
  $DCOMListener | Select-Object LocalAddress,LocalPort,OwningProcess | Show-Table
} else {
  Write-Host "DCOM Port 135 is securely closed or not listening." -ForegroundColor Green
}

# Summarize any listeners in the IANA dynamic range (commonly used by RPC/DCOM allocation)
$DynListeners = Get-NetTCPConnection | Where-Object { $_.State -eq 'Listen' -and $_.LocalPort -ge $DynamicPortLow -and $_.LocalPort -le $DynamicPortHigh }
if ($DynListeners) {
  Write-Host ("WARNING: {0} dynamic TCP listeners found in {1}-{2} (inspect for RPC/DCOM/WMI usage)." -f $DynListeners.Count,$DynamicPortLow,$DynamicPortHigh) -ForegroundColor Yellow
  $DynListeners | Select-Object LocalAddress,LocalPort,OwningProcess | Sort-Object LocalPort | Select-Object -First 20 | Show-Table
} else {
  Write-Host "No dynamic-range listeners detected (49152-65535)." -ForegroundColor Green
}

# --- [2] WS-Man / WinRM listeners (5985/5986) ---
Write-Host "`n[2] Checking WinRM Listeners (5985/5986)" -ForegroundColor Cyan

# Service and listener/auth snapshot
$winrmSvc = Get-Service -Name WinRM -ErrorAction SilentlyContinue
if ($winrmSvc -and $winrmSvc.Status -eq 'Running') {
  Write-Host "WinRM service is RUNNING." -ForegroundColor Yellow
  try {
    $listeners = Get-Item WSMan:\LocalHost\Listener\* 
    $auth      = (winrm get winrm/config/service/auth) 2>$null
    $svc       = (winrm get winrm/config/service) 2>$null

    $listenerView = $listeners | Select-Object Transport, @{N='Port';E={$_.Keys['Port']}}, @{N='Enabled';E={$_.Keys['Enabled']}}, @{N='Hostname';E={$_.Keys['Hostname']}}
    $listenerView | Show-Table

    # Flag Anonymous/Basic or AllowUnencrypted
    $badAuth = ($auth -match "Basic\s*=\s*true") -or ($auth -match "Anonymous\s*=\s*true")
    $unencrypted = ($svc -match "AllowUnencrypted\s*=\s*true")

    if ($badAuth)     { Write-Host "CRITICAL RISK: Basic and/or Anonymous authentication is enabled for WinRM." -ForegroundColor Red }
    if ($unencrypted) { Write-Host "CRITICAL RISK: WinRM 'AllowUnencrypted' is enabled." -ForegroundColor Red }
    if (-not $badAuth -and -not $unencrypted) {
      Write-Host "WinRM listeners enforce Kerberos/Negotiate over encrypted transport (expected)." -ForegroundColor Green
    }
  } catch {
    Write-Host "WinRM configuration could not be enumerated (permissions or WSMan provider issue)." -ForegroundColor Yellow
  }
} else {
  Write-Host "WinRM service is Stopped/Not Present (preferred in DMZ unless strictly required)." -ForegroundColor Green
}

# --- [3] TLS posture (deny TLS 1.0/1.1 for WinHTTP/WinRM) ---
Write-Host "`n[3] Checking TLS Configuration for WinRM (SC-12/IA-2)" -ForegroundColor Cyan

$TLSCheck = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\WinHttp\DefaultSecureProtocols' -ErrorAction SilentlyContinue
if ($TLSCheck) {
  # 0x80 = SSL3/TLS1.0 flags, 0x200 = TLS1.1 (per WinHTTP DefaultSecureProtocols bitmask)
  if (($TLSCheck.DefaultSecureProtocols -band 0x00000080) -or ($TLSCheck.DefaultSecureProtocols -band 0x00000200)) {
    Write-Host "WARNING: Older TLS (1.0/1.1) appear enabled for WinHTTP, tighten to TLS 1.2/1.3." -ForegroundColor Red
  } else {
    Write-Host "TLS config denies legacy protocols for WinHTTP (good)." -ForegroundColor Green
  }
} else {
  Write-Host "No WinHTTP DefaultSecureProtocols override found. Ensure system SCHANNEL disables TLS 1.0/1.1." -ForegroundColor Yellow
}

# --- [4] Host firewall enforcement (SC-7) on WMI/WinRM ports ---
Write-Host "`n[4] Validating Host Firewall for DMZ (SC-7 Enforcement)" -ForegroundColor Cyan

$needBlock = @()
foreach ($p in (135,5985,5986)) {
  $hasBlock = Get-NetFirewallRule -Action Block | Where-Object { $_.Enabled -eq $True -and (($_ | Get-NetFirewallPortFilter).LocalPort -contains "$p") }
  if (-not $hasBlock) { $needBlock += $p }
}
if ($needBlock.Count -gt 0) {
  Write-Host ("CRITICAL: Missing explicit BLOCK rule(s) for: {0}" -f ($needBlock -join ", ")) -ForegroundColor Red
  Write-Host "Tip: run remediation at the end to add host-level BLOCK rules." -ForegroundColor Yellow
} else {
  Write-Host "Host firewall explicitly blocks 135/5985/5986 (good boundary enforcement)." -ForegroundColor Green
}

# --- [5] WSUS/UpdateServices (CVE-2025-59287) exposure & workaround checks ---
Write-Host "`n[5] Checking WSUS/UpdateServices Role & CVE-2025-59287 Status" -ForegroundColor Cyan

# Detect WSUS role (works on Server 2025 w/ ServerManager module)
$wsusFeature = try { Import-Module ServerManager -ErrorAction SilentlyContinue; Get-WindowsFeature -Name UpdateServices* } catch { $null }
$wsusInstalled = $false
if ($wsusFeature) { $wsusInstalled = ($wsusFeature | Where-Object {$_.Installed}).Count -gt 0 }

# Listener check for 8530/8531
$wsusListeners = Get-NetTCPConnection | Where-Object { $_.State -eq 'Listen' -and ($_.LocalPort -in 8530,8531) }
if ($wsusInstalled) { Write-Host "WSUS role detected on this server." -ForegroundColor Yellow }

if ($wsusListeners) {
  Write-Host "WSUS HTTP/S listeners detected (8530/8531)." -ForegroundColor Yellow
  $wsusListeners | Select-Object LocalAddress,LocalPort,OwningProcess | Show-Table
}

# Check if OOB security updates for CVE-2025-59287 are installed (KB5070881 or KB5070893 on Server 2025 per MSRC)
$kbOK = $false
$installedKbs = (Get-HotFix | Select-Object -ExpandProperty HotFixID)
if ($installedKbs) {
  $kbOK = @('KB5070881','KB5070893') | ForEach-Object { $installedKbs -contains $_ } | Where-Object {$_} | Measure-Object | Select-Object -ExpandProperty Count
  $kbOK = $kbOK -gt 0
}

if ($wsusInstalled -or $wsusListeners) {
  if (-not $kbOK) {
    Write-Host "CRITICAL: WSUS present/listening but required out-of-band fix for CVE-2025-59287 not found." -ForegroundColor Red
    Write-Host "-> Immediate safe workaround: BLOCK inbound 8530/8531 at the HOST firewall (not only perimeter) OR disable WSUS until patched." -ForegroundColor Red
  } else {
    Write-Host "WSUS appears patched with the relevant OOB update(s). Verify end-to-end before re-opening ports." -ForegroundColor Green
  }
} else {
  Write-Host "No WSUS role/listeners detected." -ForegroundColor Green
}

# --- [6] Optional one-click remediation (host-level blocks for risky ports) ---
Write-Host "`n[6] Optional Remediation – Add Host BLOCK rules (SC-7) for risky ports" -ForegroundColor Cyan
Write-Host "Choose:  [B]lock 135/5985/5986   [W]SUS Block 8530/8531   [A]ll   [S]kip" -ForegroundColor DarkCyan
$choice = 'S'  # <-- set to 'A' to auto-apply in unattended runs
switch ($choice.ToUpper()) {
  'B' { 135,5985,5986 | ForEach-Object { Ensure-BlockRule -Port $_ } }
  'W' { 8530,8531     | ForEach-Object { Ensure-BlockRule -Port $_ -NamePrefix 'DMZ-WSUS-BLOCK' } }
  'A' { (135,5985,5986,8530,8531) | ForEach-Object { Ensure-BlockRule -Port $_ } }
  Default { Write-Host "No remediation applied." -ForegroundColor DarkGray }
}

# --- [7] Summary / Exit codes ---
Write-Host "`n--- Summary ---" -ForegroundColor Yellow
if ($DCOMListener) { Write-Host "• DCOM/RPC 135 LISTENING -> HIGH RISK" -ForegroundColor Red }
if ($DynListeners) { Write-Host "• Dynamic-range listeners present -> REVIEW" -ForegroundColor Yellow }
if ($winrmSvc -and $winrmSvc.Status -eq 'Running') {
  Write-Host "• WinRM service running – ensure strong auth & encryption only" -ForegroundColor Yellow
}
if ($needBlock.Count -gt 0) { Write-Host "• Missing host BLOCK rule(s): $($needBlock -join ', ')" -ForegroundColor Red }
if ($wsusInstalled -or $wsusListeners) {
  if (-not $kbOK) { Write-Host "• WSUS present and likely vulnerable (apply OOB update; keep 8530/8531 blocked)" -ForegroundColor Red }
  else            { Write-Host "• WSUS appears patched; confirm before exposing 8530/8531" -ForegroundColor Green }
}
Write-Host "`nDone." -ForegroundColor Green
