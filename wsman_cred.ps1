# Assumed environment: DMZ Windows Server 2025
$DMZServerName = $env:COMPUTERNAME
$TargetPorts = @(135, 5985, 5986, 8530, 8531)
$DynamicPortRange = 49152..65535 # WMI DCOM dynamic range

Write-Host "--- DMZ Security Posture Validation (WMI/WS-Man Focus) ---" -ForegroundColor Yellow

# --- DEFENSE 1: Check DCOM/WMI Exposure (Port 135) ---
Write-Host "`n[1] Checking WMI/DCOM Endpoints (Port 135 & Dynamic Range)" -ForegroundColor Cyan
$DCOMListener = Get-NetTCPConnection | Where-Object { 
    $_.State -eq 'Listen' -and $_.LocalPort -eq 135 
}

if ($DCOMListener) {
    Write-Host "CRITICAL RISK: TCP/135 (DCOM/RPC) is LISTENING." -ForegroundColor Red
    Write-Host "This is a direct violation of SC-7/CM-6 and enables potential unauthenticated WMI/DCOM access."
} else {
    Write-Host "DCOM Port 135 is securely closed or not listening." -ForegroundColor Green
}

# --- DEFENSE 2: Check WS-Man/CIM Listener Configuration (5985/5986) ---
Write-Host "`n[2] Checking WinRM Listeners (5985/5986)" -ForegroundColor Cyan
# Check for anonymous/unauthenticated WinRM listeners
$AnonWinRM = Get-Item WSMan:\LocalHost\Listener\* -ErrorAction SilentlyContinue | Where-Object { 
    $_.URLPrefix -match 'HTTP' -and ($_.Auth.Anonymous -eq $true -or $_.Auth.Basic -eq $true) 
}

if ($AnonWinRM) {
    Write-Host "CRITICAL RISK: Anonymous/Basic Authentication enabled on WinRM listener(s)." -ForegroundColor Red
    $AnonWinRM | Select-Object Transport, Port, Enabled, URLPrefix, @{N='AuthMethods'; E={$_.Auth.PSObject.Properties | Where-Object {$_.Value -eq $true} | Select-Object -ExpandProperty Name}}
} else {
    Write-Host "WinRM listeners configured, but appear to enforce NTLM/Kerberos (good, but requires SC-7 block if not used)." -ForegroundColor Green
}

# --- DEFENSE 3: Protocol Whitelisting Check (TLS Version - IA-2/SC-12) ---
Write-Host "`n[3] Checking TLS Configuration for WinRM (SC-12/IA-2)" -ForegroundColor Cyan
$TLSCheck = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\WinHttp\DefaultSecureProtocols' -ErrorAction SilentlyContinue

if ($TLSCheck) {
    # Check if TLS 1.0 or 1.1 are enabled (non-compliant)
    if (($TLSCheck.DefaultSecureProtocols -band 0x00000080) -or ($TLSCheck.DefaultSecureProtocols -band 0x00000200)) {
        Write-Host "WARNING: Older TLS versions (1.0 or 1.1) appear enabled for WinRM/CIM, exposing vulnerability." -ForegroundColor Red
    } else {
        Write-Host "TLS configuration is set to deny older protocols (good IA practice)." -ForegroundColor Green
    }
}

# --- MITIGATION VALIDATION: Check DMZ Firewall Rules (SC-7) ---
Write-Host "`n[4] Validating Host Firewall for DMZ (SC-7 Enforcement)" -ForegroundColor Cyan

$InboundBlockDCOM = Get-NetFirewallRule -Action Block | Where-Object {
    $_.Enabled -eq $True -and $_.LocalPort -match "(135|5985|5986)"
}

if ($InboundBlockDCOM.Count -lt 3) {
    Write-Host "CRITICAL: Missing specific BLOCK rules for WMI (135), WinRM HTTP (5985), or HTTPS (5986)." -ForegroundColor Red
    Write-Host "Immediate action needed to fully implement SC-7 boundary protection."
} else {
    Write-Host "Host firewall explicitly blocks common WMI/WinRM ports. Good boundary enforcement." -ForegroundColor Green
}