# Configuration

The app uses various places for configuration. These are:

- `/scripts/lib/config.sh` - default config, which is used for scripts and endpoint configuration.
- `/scripts/systemd/` - systemd template directory. These templates are used for systemd service setup, and can be changed.
- `/scripts/cron/` - cron ClamAV config template. This template is used for endpoint ClamAV configuration.
- `/audit_priorities.conf` and `sysmon_priorities.conf` - audit and sysmon classification priorities configuration.
- `/config/config.go` - web app configuration.
- `/rulesets/` - audit ruleset directory. This is split into `x32` and `x64` folders, for 32-bit and 64-bit endpoints respectively. Any custom rulesets added here will appear in the Web UI.
- `.env` - environment variables file. Used for mostly Web app related configuration.
- `/etc/agentless/secrets.env` - secrets file. 