# Agentless IDS Web Interface

This is a web-based interface for an agentless Intrusion Detection System (IDS) that can monitor remote devices via SSH.

## Features

- User Management: Create, edit, and delete users with admin privileges
- Device Management: Add, edit, and delete devices to be monitored
- SSH-based Monitoring: Securely monitor remote devices without installing agents
- Dashboard: View device status and monitoring results

## Security Features

- Password hashing with bcrypt
- Session-based authentication
- Role-based access control
- SSH key-based authentication for device monitoring

## Installation

1. Clone the repository
2. Run `go build` to compile the application
3. Run `./go-website-example` to start the server

## SSH Monitoring Setup

The system uses a dedicated user account on target machines for monitoring. The `enlist.sh` script automates the setup process:

```bash
./scripts/enlist.sh <target_ip>
```

This script will:
1. Create a dedicated user (ids-monitor) on the target machine
2. Set up SSH key-based authentication
3. Configure appropriate permissions for monitoring
4. Register the device with the IDS server

## Security Best Practices

1. **Dedicated User Account**: Always use a dedicated user with limited privileges
2. **SSH Key Authentication**: Never use password authentication for automated monitoring
3. **Restricted Commands**: Limit the commands the monitoring user can execute
4. **Regular Key Rotation**: Periodically update SSH keys
5. **Secure Key Storage**: Store SSH private keys with appropriate permissions (600)

## Monitoring Capabilities

The system can monitor:
- Network connections and open ports
- Running processes
- System resource usage
- User login activity
- File system changes

## License

MIT
