# enlist-windows.ps1
# Windows Device Enrollment Script for AgentLess IDS
# This script must be run with Administrator privileges on the target Windows machine
#
# Usage: .\enlist-windows.ps1 -ServerIP <ids_server_ip> -MonitoringUser <username>

param(
    [Parameter(Mandatory=$true)]
    [string]$ServerIP,
    
    [Parameter(Mandatory=$false)]
    [string]$MonitoringUser = "ids-monitor",
    
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

Write-Host "=== AgentLess IDS - Windows Enrollment ===" -ForegroundColor Cyan
Write-Host "Server: $ServerIP" -ForegroundColor Green
Write-Host "Monitoring User: $MonitoringUser" -ForegroundColor Green
Write-Host ""

# Create monitoring user if doesn't exist
Write-Host "[1/6] Creating monitoring user..." -ForegroundColor Yellow
$script:userPassword = $null
try {
    $userExists = Get-LocalUser -Name $MonitoringUser -ErrorAction SilentlyContinue
    
    if (-not $userExists) {
        # Generate random password
        $password = -join ((48..57) + (65..90) + (97..122) | Get-Random -Count 24 | ForEach-Object {[char]$_})
        $securePassword = ConvertTo-SecureString $password -AsPlainText -Force
        $script:userPassword = $password
        
        New-LocalUser -Name $MonitoringUser -Password $securePassword -Description "AgentLess IDS Monitoring Account" -PasswordNeverExpires
        Write-Host "  [OK] User created: $MonitoringUser" -ForegroundColor Green
        Write-Host "  [INFO] Password: $password" -ForegroundColor Cyan
        Write-Host "  [INFO] Save this password! You'll need it in the next step." -ForegroundColor Yellow
    } else {
        Write-Host "  [OK] User already exists: $MonitoringUser" -ForegroundColor Green
        Write-Host "  [INFO] Enter password for ${MonitoringUser} for SSH key setup:" -ForegroundColor Cyan
        $secPass = Read-Host -AsSecureString
        $BSTR = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($secPass)
        $script:userPassword = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTR)
    }
    
    # Add to Event Log Readers group
    Add-LocalGroupMember -Group "Event Log Readers" -Member $MonitoringUser -ErrorAction SilentlyContinue
    Write-Host "  [OK] Added to Event Log Readers group" -ForegroundColor Green
    
} catch {
    Write-Error "Failed to create monitoring user: $_"
    exit 1
}

# Setup SSH for Windows
Write-Host "[2/6] Configuring OpenSSH Server..." -ForegroundColor Yellow
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

# Setup SSH key authentication
Write-Host "[3/6] Setting up SSH key authentication..." -ForegroundColor Yellow
try {
    Write-Host "  Please provide the SSH public key from the IDS server:" -ForegroundColor Cyan
    Write-Host "  (You can find it at: ~/.ssh/id_rsa.pub on the server)" -ForegroundColor Cyan
    Write-Host "  Paste the public key and press Enter:" -ForegroundColor Cyan
    $publicKey = Read-Host
    
    if ($publicKey) {
        # Create .ssh directory and authorized_keys file
        $sshDir = "C:\Users\$MonitoringUser\.ssh"
        $authorizedKeysFile = "$sshDir\authorized_keys"
        
        # Create directory
        New-Item -ItemType Directory -Path $sshDir -Force | Out-Null
        
        # Write public key to authorized_keys
        $publicKey | Out-File -FilePath $authorizedKeysFile -Encoding ASCII -NoNewline
        
        # Change ownership to the monitoring user
        $null = icacls.exe $sshDir /setowner "${MonitoringUser}" /T /C 2>&1
        $null = icacls.exe $authorizedKeysFile /setowner "${MonitoringUser}" /C 2>&1
        
        # Set permissions (only user and SYSTEM)
        $null = icacls.exe $sshDir /inheritance:r /grant "${MonitoringUser}:F" /grant "SYSTEM:F" 2>&1
        $null = icacls.exe $authorizedKeysFile /inheritance:r /grant "${MonitoringUser}:F" /grant "SYSTEM:F" 2>&1
        
        Write-Host "  [OK] SSH key configured" -ForegroundColor Green
    } else {
        Write-Warning "  No SSH key provided. You'll need to configure this manually."
    }
    
} catch {
    Write-Warning "Failed to setup SSH keys: $_"
}

# Download and install Sysmon
Write-Host "[4/6] Installing Sysmon..." -ForegroundColor Yellow
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
Write-Host "[5/6] Configuring Sysmon event log..." -ForegroundColor Yellow
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
Write-Host "[6/6] Enrollment complete!" -ForegroundColor Yellow
Write-Host ""
Write-Host "=== Connection Information ===" -ForegroundColor Cyan
Write-Host "Hostname: $env:COMPUTERNAME" -ForegroundColor White
Write-Host "IP Address: $(Get-NetIPAddress -AddressFamily IPv4 | Where-Object {$_.InterfaceAlias -notlike '*Loopback*'} | Select-Object -First 1 -ExpandProperty IPAddress)" -ForegroundColor White
Write-Host "SSH User: $MonitoringUser" -ForegroundColor White
Write-Host "SSH Port: 22" -ForegroundColor White
Write-Host ""
Write-Host "To add this device to AgentLess IDS:" -ForegroundColor Green
Write-Host "1. Log in to the IDS web interface" -ForegroundColor White
Write-Host "2. Go to Devices > Add Device" -ForegroundColor White
Write-Host "3. Enter the information above" -ForegroundColor White
Write-Host "4. Select OS Type: Windows" -ForegroundColor White
Write-Host "5. Upload the SSH private key that matches the public key you provided" -ForegroundColor White
Write-Host ""
Write-Host "Sysmon is now monitoring system events!" -ForegroundColor Green
Write-Host "Event log: Microsoft-Windows-Sysmon/Operational" -ForegroundColor Cyan
