# Assumed DMZ Host details (Target)
$TargetDMZ = "localhost" # Assuming loopback for testing
$TargetPort = 5986
$ChirpCount = 8
$ChirpInterval = 0.5 # Rapid chirp interval to trigger defender

# --- Attacker Chirp Payload ---
$ChirpPayload = {
    # Simple, low-privilege, minimal-response WMI query
    (Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop).LastBootUpTime
}

Write-Host "`n--- Starting PowerShell Attacker Simulation (Unauthenticated Chirp) ---" -ForegroundColor Cyan

# Use Invoke-Command to simulate the connection (assuming listener is running)
try {
    # Establish a temporary, non-persistent connection for each chirp (simulating stateless burst)
    for ($i = 1; $i -le $ChirpCount; $i++) {
        $StartTime = Get-Date

        # Simulate the execution attempt
        $Result = Invoke-Command -ComputerName $TargetDMZ -ScriptBlock $ChirpPayload -ErrorAction SilentlyContinue

        $ElapsedTime = (New-TimeSpan -Start $StartTime -End (Get-Date)).TotalSeconds

        if ($Result) {
            Write-Host "Chirp $i: SUCCESS. Time: $($ElapsedTime.ToString('N2'))s. Result: $($Result.Substring(0, 10))." -ForegroundColor DarkGreen
        } else {
            # This is the expected result when the Python defender injects the error.
            Write-Host "Chirp $i: FAILED/DISRUPTED. Time: $($ElapsedTime.ToString('N2'))s. Pipe broken." -ForegroundColor Red
        }
        
        Start-Sleep -Seconds $ChirpInterval
    }
} catch {
    Write-Host "CRITICAL ERROR: Initial connection attempt failed completely." -ForegroundColor Red
}

Write-Host "PowerShell client chirp simulation complete."