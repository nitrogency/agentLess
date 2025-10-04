# enlist-windows.ps1
param(
  [Parameter(Mandatory=$true)][string]$ServerIP,
  [string]$MonitoringUser="ids-monitor",
  [string]$SysmonConfigURL="https://raw.githubusercontent.com/SwiftOnSecurity/sysmon-config/master/sysmonconfig-export.xml",
  [string]$SysmonDownloadURL="https://download.sysinternals.com/files/Sysmon.zip"
)

# --- guard: admin ---
if(-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)){
  Write-Error "Run as Administrator"; exit 1
}

# --- basics ---
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
Write-Host "=== AgentLess IDS - Windows Enrollment ===" -ForegroundColor Cyan
Write-Host "Server: $ServerIP" -ForegroundColor Green
Write-Host "Monitoring User: $MonitoringUser" -ForegroundColor Green
Write-Host ""

# --- [1/6] user + group ---
Write-Host "[1/6] Creating monitoring user..." -ForegroundColor Yellow
try{
  $user = Get-LocalUser -Name $MonitoringUser -ErrorAction SilentlyContinue
  if(-not $user){
    $pw = -join ((48..57+65..90+97..122) | Get-Random -Count 24 | % {[char]$_})
    $spw = ConvertTo-SecureString $pw -AsPlainText -Force
    New-LocalUser -Name $MonitoringUser -Password $spw -Description "AgentLess IDS Monitoring Account" -PasswordNeverExpires | Out-Null
    Write-Host "  ✓ User created: $MonitoringUser" -ForegroundColor Green
  } else {
    Write-Host "  ✓ User exists: $MonitoringUser" -ForegroundColor Green
  }
  # Add to Event Log Readers via SID (S-1-5-32-573)
  $elr = (Get-LocalGroup -SID 'S-1-5-32-573').Name
  Add-LocalGroupMember -Group $elr -Member $MonitoringUser -ErrorAction SilentlyContinue
  Write-Host "  ✓ Added to Event Log Readers" -ForegroundColor Green
}catch{ Write-Error "User setup failed: $_"; exit 1 }

# --- [2/6] OpenSSH server ---
Write-Host "[2/6] Configuring OpenSSH Server..." -ForegroundColor Yellow
try{
  $sshCap = Get-WindowsCapability -Online | ? Name -like 'OpenSSH.Server*' | Select-Object -First 1
  if($sshCap.State -ne 'Installed'){ Write-Host "  Installing OpenSSH..." -ForegroundColor Cyan; Add-WindowsCapability -Online -Name $sshCap.Name | Out-Null }
  Start-Service sshd -ErrorAction SilentlyContinue
  Set-Service sshd -StartupType Automatic
  if(-not (Get-NetFirewallRule -Name "OpenSSH-Server-In-TCP" -ErrorAction SilentlyContinue)){
    New-NetFirewallRule -Name 'OpenSSH-Server-In-TCP' -DisplayName 'OpenSSH Server (sshd)' -Enabled True -Direction Inbound -Protocol TCP -Action Allow -LocalPort 22 | Out-Null
  }
  # harden: disable password auth
  $cfg = 'C:\ProgramData\ssh\sshd_config'
  if(Test-Path $cfg){
    $c = Get-Content $cfg
    if($c -match '^\s*PasswordAuthentication\s+'){
      $c = ($c -replace '^\s*#?\s*PasswordAuthentication\s+\w+','PasswordAuthentication no')
    } else {
      $c += 'PasswordAuthentication no'
    }
    $c | Set-Content $cfg -Encoding ascii
    Restart-Service sshd
  }
  Write-Host "  ✓ SSH server ready" -ForegroundColor Green
}catch{ Write-Error "OpenSSH setup failed: $_"; exit 1 }

# --- [3/6] SSH key auth (strict ACLs) ---
Write-Host "[3/6] Setting up SSH key authentication..." -ForegroundColor Yellow
try{
  $prof = Join-Path 'C:\Users' $MonitoringUser
  $sshDir = Join-Path $prof '.ssh'
  New-Item $sshDir -ItemType Directory -Force | Out-Null
  $authorized = Join-Path $sshDir 'authorized_keys'
  Write-Host "  Paste the SSH public key (single line) and press Enter:" -ForegroundColor Cyan
  $pub = Read-Host
  if($pub){
    Set-Content $authorized $pub -Encoding utf8NoBOM
    $acct = "$env:COMPUTERNAME\$MonitoringUser"
    icacls $sshDir /inheritance:r /grant "$acct:(OI)(CI)F" "SYSTEM:(OI)(CI)F" | Out-Null
    icacls $authorized /inheritance:r /grant "$acct:F" "SYSTEM:F" | Out-Null
    icacls $sshDir /setowner $acct /T | Out-Null
    Write-Host "  ✓ SSH key configured" -ForegroundColor Green
  } else {
    Write-Warning "  No key provided; configure later."
  }
}catch{ Write-Warning "SSH key setup warning: $_" }

# --- [4/6] Sysmon install/update ---
Write-Host "[4/6] Installing Sysmon..." -ForegroundColor Yellow
try{
  $temp = Join-Path $env:TEMP 'sysmon-install'
  $zip  = Join-Path $temp 'Sysmon.zip'
  $cfgf = Join-Path $temp 'sysmonconfig.xml'
  New-Item $temp -ItemType Directory -Force | Out-Null

  $svc = Get-Service -Name 'Sysmon64','Sysmon' -ErrorAction SilentlyContinue | Select-Object -First 1
  if(-not $svc){
    Write-Host "  Downloading Sysmon..." -ForegroundColor Cyan
    Invoke-WebRequest $SysmonDownloadURL -OutFile $zip
    Expand-Archive $zip $temp -Force
    Write-Host "  Downloading Sysmon configuration..." -ForegroundColor Cyan
    Invoke-WebRequest $SysmonConfigURL -OutFile $cfgf
    $exe = Get-ChildItem $temp -Recurse -Filter 'Sysmon*.exe' | Select-Object -First 1
    if(-not $exe){ throw "Sysmon executable not found" }
    Write-Host "  Installing Sysmon with configuration..." -ForegroundColor Cyan
    & $exe.FullName -accepteula -i $cfgf
    Write-Host "  ✓ Sysmon installed" -ForegroundColor Green
  } else {
    Write-Host "  ✓ Sysmon already installed" -ForegroundColor Green
    Write-Host "  Updating Sysmon configuration..." -ForegroundColor Cyan
    Invoke-WebRequest $SysmonConfigURL -OutFile $cfgf
    $installedExe = @('C:\Windows\Sysmon64.exe','C:\Windows\Sysmon.exe') | ? { Test-Path $_ } | Select-Object -First 1
    if($installedExe){ & $installedExe -c $cfgf; Write-Host "  ✓ Config updated" -ForegroundColor Green } else { Write-Warning "  Sysmon exe not found" }
  }
}catch{ Write-Error "Sysmon step failed: $_"; exit 1 }
finally{
  Remove-Item $temp -Recurse -Force -ErrorAction SilentlyContinue
}

# --- [5/6] Sysmon event log size ---
Write-Host "[5/6] Configuring Sysmon event log..." -ForegroundColor Yellow
try{
  $log = Get-WinEvent -ListLog 'Microsoft-Windows-Sysmon/Operational' -ErrorAction Stop
  $log.MaximumSizeInBytes = 1GB
  $log.SaveChanges()
  Write-Host "  ✓ Event log set to 1GB" -ForegroundColor Green
}catch{ Write-Warning "Event log size not set: $_" }

# --- [6/6] Connection info ---
Write-Host "[6/6] Enrollment complete!" -ForegroundColor Yellow
$defRouteIf = (Get-NetRoute -DestinationPrefix '0.0.0.0/0' | Sort-Object RouteMetric | Select-Object -First 1).InterfaceIndex
$ip = (Get-NetIPAddress -AddressFamily IPv4 -InterfaceIndex $defRouteIf -ErrorAction SilentlyContinue).IPAddress
Write-Host ""
Write-Host "=== Connection Information ===" -ForegroundColor Cyan
Write-Host "Hostname: $env:COMPUTERNAME"
Write-Host "IP Address: $ip"
Write-Host "SSH User: $MonitoringUser"
Write-Host "SSH Port: 22"
Write-Host ""
Write-Host "To add this device to AgentLess IDS:" -ForegroundColor Green
Write-Host "1. Log in to the IDS web interface"
Write-Host "2. Go to Devices > Add Device"
Write-Host "3. Enter the information above"
Write-Host "4. Select OS Type: Windows"
Write-Host "5. Upload the SSH private key matching the public key you provided"
Write-Host ""
Write-Host "Sysmon is now monitoring system events!" -ForegroundColor Green
Write-Host "Event log: Microsoft-Windows-Sysmon/Operational" -ForegroundColor Cyan
