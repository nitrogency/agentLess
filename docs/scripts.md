# Linux monitoring

# Windows monitoring
Just like with Linux monitoring, log retrieval and device setup is done through SSH. Instead of near real-time log retrieval like with Linux, however, Windows logs are retrieved in intervals (you can change the default value in `scripts/lib/config.sh`, which is 30 seconds). This is done because Get-WinEvent is more optimized for batch queries.

Windows monitoring works through the use of these scripts/binaries:

- `bin/monitor-windows` - responsible for parsing received Sysmon event XML, prevents duplicates, writes to DB.
- `scripts/windows/monitoring-windows.sh` - responsible for connecting to the Windows endpoint. Reads logs, passes them over to the `bin/monitor-windows` binary.
- `scripts/windows/enlist-windows.ps1` - responsible for configuring a Windows endpoint (copies over SSH public key, configures monitoring user, Sysmon, etc.). **This script is required to be copied over manually** (whether using Invoke-WebRequest from the repo in PS on your endpoint or by copying over the file in a simpler way). For Sysmon rules, SwiftOnSecurity's [SysmonConfig](https://github.com/SwiftOnSecurity/SysmonConfig) is used.
- `scripts/start-monitoring.sh` - launcher script that detects OS type and launches appropriate monitoring script (linux or windows).
