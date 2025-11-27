# Log exporter

This is an optional feature that you can choose to use during setup, if you select not to do so, all related files with this feature are deleted.

The exporter is a standalone service that exports audit logs from the database to a file in JSON Lines format. The export interval can be configured in the `/scripts/systemd/agentless-exporter.timer` file. These exported logs can then be ingested by other tools. You can install an agent on the monitoring server which forwards these logs to your platform of choice. You can also send logs using local scripts or whatever-else. It's your decision.

You only need to make sure the directory is correct (logs are exported to `/var/log/agentless-export/` by default, this can be changed in the .env file). And that your agent of choice has access to it (the directory is owned by the `agentless` user).

Tested with OpenSearch.