# How the system works

The app utilizes systemd services, which are created for each monitored device (agentless-monitor@service). These services are responsible for launching the scripts that connect to the endpoints. These services are created by the `setup-monitoring.sh` script, which is launched at the end of the `enlist.sh` script.

On Linux endpoints, ClamAV is installed and logs are also gathered alongside audit logs. Windows monitoring does not support this.


# Linux monitoring

The Linux endpoint monitoring workflow looks like this:

1. Device is added through the Web interface.
2. Run the `/scripts/linux/enroll-device.sh` script (the exact command is displayed in the UI). This single script:
   - Copies the server's SSH key to the endpoint (you'll be prompted for the password once)
   - Sets up the monitoring user with appropriate permissions
   - Configures audit rules and installs dependencies
   - Registers the device in the database
3. Logs are then retrieved from the endpoint using the created systemd service (agentless-monitor@service). This service calls the `/scripts/start-monitoring.sh` script, which connects to the endpoint, reads the logs, and passes them over to the `/bin/monitor` binary, where the logs are parsed and written to DB.
4. Logs are then displayed in the Web UI for the user to see.

Log retrieval and device setup is done through SSH. Once the connection is established, two `tail -F` commands run in parallel on the endpoint - one for the `/var/log/audit/audit.log` file, and one for the `/var/log/clamav/clamav.log` file. Their output is combined and piped back over SSH to the monitoring server. If the connection gets interrupted, the service will attempt to reconnect. 

`tail` is also run with the `-n` flag to prevent the loss of logs during this downtime. The last amount of lines specified (default is `-n 1000`) is sent over to the server, where they are parsed and de-duplicated if necessary. If you suspect that the number of logs generated during interruptions can be higher, you can change this number in `scripts/lib/config.sh`.

Linux monitoring is done through the use of these scripts/binaries:

- `/scripts/linux/enroll-device.sh` - one-step enrollment script (copies SSH key + device setup).
- `/scripts/linux/enlist.sh` - responsible for setting up the endpoint
- `/scripts/start-monitoring.sh` - launcher script that detects OS type and launches appropriate monitoring script (linux or windows). Launched by the systemd service.
- `/scripts/linux/monitoring.sh` - responsible for connecting to the Linux endpoint. Reads logs, passes them over to the `/bin/monitor` binary.
- `/bin/monitor` - responsible for parsing received audit logs, prevents duplicates, writes to DB.

# Windows monitoring

The Windows endpoint monitoring workflow, while similar, is a bit different:

1. Device is added through the Web interface.
2. The `enlist-windows.ps1` script is copied over manually to the endpoint and launched. This script configures SSH access and creates the monitoring user with appropriate permissions.
3. Every 30 seconds (or the interval described in `scripts/lib/config.sh`), the `/scripts/windows/monitoring-windows.sh`. This script connects to the endpoint, reads the logs, and passes them over to the `/bin/monitor-windows` binary, where the sysmon XML is parsed and written to DB.
4. Logs are then displayed in the Web UI for the user to see.

Just like with Linux monitoring, log retrieval and device setup is done through SSH. Instead of near real-time log retrieval like with Linux, however, Windows logs are retrieved in intervals (you can change the default value in `scripts/lib/config.sh`, which is 30 seconds). This is done because Get-WinEvent is more optimized for batch queries.

Windows monitoring works through the use of these scripts/binaries:

- `scripts/windows/enlist-windows.ps1` - responsible for configuring a Windows endpoint (sets up SSH pubkey, configures monitoring user, Sysmon, etc.). **This script is required to be copied over manually** (whether using Invoke-WebRequest from the repo in PS on your endpoint or by copying over the file in a simpler way). For Sysmon rules, SwiftOnSecurity's [SysmonConfig](https://github.com/SwiftOnSecurity/SysmonConfig) is used.
- `scripts/start-monitoring.sh` - launcher script that detects OS type and launches appropriate monitoring script (linux or windows). Launched by the systemd service.
- `bin/monitor-windows` - responsible for parsing received Sysmon event XML, prevents duplicates, writes to DB.
- `scripts/windows/monitoring-windows.sh` - responsible for connecting to the Windows endpoint. Reads logs, passes them over to the `bin/monitor-windows` binary. 


