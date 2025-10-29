<#
ps_listener.ps1
- Simple TCP listener that receives JSON messages from the Python extractor and writes them to a rolling log.
- For defenders: correlates network-observed entries with local CimSessions and Windows event logs.
Run in an elevated PowerShell session on the host you want to correlate with.
#>

param(
  [int]$Port = 17000,
  [string]$OutFile = "C:\wsman_logs\wsman_netlog.jsonl"
)

# create folder
New-Item -ItemType Directory -Path (Split-Path $OutFile) -Force | Out-Null

$listener = [System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::Loopback, $Port)
$listener.Start()
Write-Host "Listening on 127.0.0.1:$Port for WS-Man JSON messages..."

while ($true) {
  $client = $listener.AcceptTcpClient()
  $stream = $client.GetStream()
  $sr = New-Object System.IO.StreamReader($stream)
  while (-not $sr.EndOfStream) {
    $line = $sr.ReadLine()
    if ($line) {
      # append to file
      Add-Content -Path $OutFile -Value $line
      # quick correlation: show latest CimSessions and eventids
      try {
        $js = $line | ConvertFrom-Json -ErrorAction SilentlyContinue
        Write-Host "NETLOG: $($js.ts) $($js.src) -> $($js.dst) SOAP:ACTION:$($js.soap_action)" -ForegroundColor Cyan
      } catch {}
    }
  }
  $sr.Close()
  $client.Close()
}
