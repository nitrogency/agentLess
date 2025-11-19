# enlist-windows.ps1
# Windows Device Enrollment Script for Agent<
# This script must be run with Administrator privileges on the target Windows machine
#
# Usage: .\enlist-windows.ps1 -ServerIP <ids_server_ip> -MonitoringUser <username>

param(
    [Parameter(Mandatory=$true)]
    [string]$ServerIP,
    
    [Parameter(Mandatory=$false)]
    [string]$MonitoringUser = "monitor",
    
    [Parameter(Mandatory=$false)]
    [string]$SysmonConfigURL = "https://raw.githubusercontent.com/SwiftOnSecurity/sysmon-config/master/sysmonconfig-export.xml",
    
    [Parameter(Mandatory=$false)]
    [string]$SysmonDownloadURL = "https://download.sysinternals.com/files/Sysmon.zip"
)

# Require Administrator privileges
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Error "This script must be run as Administrator"
    exit 1
}

Write-Host "=== Agent< Windows Enrollment ===" -ForegroundColor Cyan
Write-Host "Server: $ServerIP" -ForegroundColor Green
Write-Host "Monitoring User: $MonitoringUser" -ForegroundColor Green
Write-Host ""

# Setup SSH for Windows
Write-Host "[1/5] Configuring OpenSSH Server..." -ForegroundColor Yellow
try {
    # Check if OpenSSH Server is installed
    $sshServer = Get-WindowsCapability -Online | Where-Object Name -like 'OpenSSH.Server*'
    
    if ($sshServer.State -ne "Installed") {
        Write-Host "  Installing OpenSSH Server..." -ForegroundColor Cyan
        Add-WindowsCapability -Online -Name OpenSSH.Server~~~~0.0.1.0
    }
    
    # Start and enable SSH service
    Start-Service sshd
    Set-Service -Name sshd -StartupType 'Automatic'
    Write-Host "  [OK] SSH server configured and running" -ForegroundColor Green
    
    # Configure firewall
    $firewallRule = Get-NetFirewallRule -Name "OpenSSH-Server-In-TCP" -ErrorAction SilentlyContinue
    if (-not $firewallRule) {
        New-NetFirewallRule -Name 'OpenSSH-Server-In-TCP' -DisplayName 'OpenSSH Server (sshd)' -Enabled True -Direction Inbound -Protocol TCP -Action Allow -LocalPort 22
        Write-Host "  [OK] Firewall rule created" -ForegroundColor Green
    }
    
} catch {
    Write-Error "Failed to configure SSH: $_"
    exit 1
}

# Create monitoring user if doesn't exist
Write-Host "[2/5] Creating monitoring user and setting up SSH..." -ForegroundColor Yellow
try {
    Write-Host "  Please provide the SSH public key from the IDS server:" -ForegroundColor Cyan
    Write-Host "  (You can find it at the /etc/agentless/.ssh/ directory on the server)" -ForegroundColor Cyan
    Write-Host "  Paste the public key you wish to use and press Enter:" -ForegroundColor Cyan
    $pub = Read-Host

    if (-not (Get-LocalUser -Name $MonitoringUser -ErrorAction SilentlyContinue)) { net user $MonitoringUser (New-Guid).Guid /add | Out-Null }
    Write-Host "  Setting up user. This may take a while... (press ENTER if script hangs)" -ForegroundColor Cyan
    $uh="C:\Users\$MonitoringUser"; $ssh="$uh\.ssh"
    New-Item -Force -ItemType Directory -Path $ssh | Out-Null
    Set-Content "$ssh\authorized_keys" $pub -Encoding Ascii
    Add-Content "$ssh\authorized_keys" ""
    icacls $uh /inheritance:r | Out-Null
    icacls $uh /grant "${MonitoringUser}:(OI)(CI)M" "Administrators:(OI)(CI)F" "SYSTEM:(OI)(CI)F" "NT SERVICE\sshd:(OI)(CI)(RX)" | Out-Null
    icacls $ssh /inheritance:r | Out-Null
    icacls $ssh /grant "${MonitoringUser}:(OI)(CI)F" "Administrators:(OI)(CI)F" "SYSTEM:(OI)(CI)F" "NT SERVICE\sshd:(OI)(CI)(RX)" | Out-Null
    icacls "$ssh\authorized_keys" /inheritance:r | Out-Null
    icacls "$ssh\authorized_keys" /grant "${MonitoringUser}:R" "Administrators:F" "SYSTEM:F" "NT SERVICE\sshd:(R)" | Out-Null
    Restart-Service sshd

    # Ensure directory exists and owned
    $uh="C:\Users\$MonitoringUser"
    mkdir $uh -Force | Out-Null
    icacls $uh /setowner $MonitoringUser | Out-Null

    # (Optional) set ProfileImagePath in registry to C:\Users\ids-monitor if missing
    $SID = (Get-LocalUser $MonitoringUser).Sid.Value
    $k = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\$SID"
    if (-not (Test-Path $k)) { New-Item $k | Out-Null }
    Set-ItemProperty $k ProfileImagePath $uh

    # Add user to Event Log Readers group for Sysmon access
    Write-Host "  Adding user to Event Log Readers group..." -ForegroundColor Cyan
    try {
        Add-LocalGroupMember -Group "Event Log Readers" -Member $MonitoringUser -ErrorAction SilentlyContinue
        Write-Host "  [OK] User added to Event Log Readers group" -ForegroundColor Green
    } catch {
        # User might already be in the group
        if ($_.CategoryInfo.Category -ne 'ResourceExists') {
            Write-Warning "Could not add user to Event Log Readers: $_"
        }
    }

    
} catch {
    Write-Error "Failed to create monitoring user: $_"
    exit 1
}

# Download and install Sysmon
Write-Host "[3/5] Installing Sysmon..." -ForegroundColor Yellow
try {
    $tempDir = "$env:TEMP\sysmon-install"
    New-Item -ItemType Directory -Path $tempDir -Force | Out-Null
    
    $sysmonZip = "$tempDir\Sysmon.zip"
    $sysmonConfig = "$tempDir\sysmonconfig.xml"
    
    # Check if Sysmon is already installed
    $sysmonService = Get-Service -Name "Sysmon64" -ErrorAction SilentlyContinue
    
    if (-not $sysmonService) {
        # Download Sysmon
        Write-Host "  Downloading Sysmon..." -ForegroundColor Cyan
        Invoke-WebRequest -Uri $SysmonDownloadURL -OutFile $sysmonZip
        
        # Extract
        Expand-Archive -Path $sysmonZip -DestinationPath $tempDir -Force
        
        # Download Sysmon config
        Write-Host "  Downloading Sysmon configuration..." -ForegroundColor Cyan
        Invoke-WebRequest -Uri $SysmonConfigURL -OutFile $sysmonConfig
        
        # Install Sysmon
        Write-Host "  Installing Sysmon with configuration..." -ForegroundColor Cyan
        $sysmonExe = Get-ChildItem -Path $tempDir -Filter "Sysmon64.exe" -Recurse | Select-Object -First 1
        
        if ($sysmonExe) {
            & $sysmonExe.FullName -accepteula -i $sysmonConfig
            Write-Host "  [OK] Sysmon installed successfully" -ForegroundColor Green
        } else {
            throw "Sysmon executable not found"
        }
    } else {
        Write-Host "  [OK] Sysmon already installed" -ForegroundColor Green
        
        # Update configuration
        Write-Host "  Updating Sysmon configuration..." -ForegroundColor Cyan
        Invoke-WebRequest -Uri $SysmonConfigURL -OutFile $sysmonConfig
        
        $sysmonPath = "C:\Windows\Sysmon64.exe"
        if (Test-Path $sysmonPath) {
            & $sysmonPath -c $sysmonConfig
            Write-Host "  [OK] Sysmon configuration updated" -ForegroundColor Green
        }
    }
    
    # Cleanup
    Remove-Item -Path $tempDir -Recurse -Force -ErrorAction SilentlyContinue
    
} catch {
    Write-Error "Failed to install Sysmon: $_"
    exit 1
}

# Configure event log size
Write-Host "[4/5] Configuring Sysmon event log..." -ForegroundColor Yellow
try {
    $logName = "Microsoft-Windows-Sysmon/Operational"
    $log = Get-WinEvent -ListLog $logName -ErrorAction Stop
    
    # Set log size to 1GB
    $log.MaximumSizeInBytes = 1GB
    $log.SaveChanges()
    
    Write-Host "  [OK] Event log configured (1GB max size)" -ForegroundColor Green
    
} catch {
    Write-Warning "Failed to configure event log size: $_"
}

# Display connection information
Write-Host "[5/5] Enrollment complete!" -ForegroundColor Yellow
Write-Host "Sysmon is now monitoring system events!" -ForegroundColor Green
Write-Host "Event log: Microsoft-Windows-Sysmon/Operational" -ForegroundColor Cyan
Write-Host ""
Write-Host "=== Connection Information ===" -ForegroundColor Cyan
Write-Host "Hostname: $env:COMPUTERNAME" -ForegroundColor White
Write-Host "IP Address: $(Get-NetIPAddress -AddressFamily IPv4 | Where-Object {$_.InterfaceAlias -notlike '*Loopback*'} | Select-Object -First 1 -ExpandProperty IPAddress)" -ForegroundColor White
Write-Host "SSH User: $MonitoringUser" -ForegroundColor White
Write-Host "SSH Port: 22" -ForegroundColor White
Write-Host ""
