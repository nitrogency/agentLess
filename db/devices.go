package db

import (
	"database/sql"
	"errors"
	"fmt"
	"log"
	"net"
	"os/exec"
	"sync"
	"time"
)

type Device struct {
	ID                 int64
	Name               string
	Type               string
	Status             string
	LastUpdated        time.Time
	IPAddress          string
	SSHUser            string
	SSHKeyPath         string
	SSHPort            int
	Hostname           string
	OSInfo             string
	OSType             string // "linux" or "windows"
	SSHGroup           string
	SetupUser          string
	FirewallMode       string // "disabled", "ssh_all", "ssh_restricted"
	FirewallAllowedIPs string // Comma-separated IPs for ssh_restricted mode
	AuditArch          string // "x32" or "x64"
	AuditRuleset       string // e.g., "audit_default.rules", "audit_high.rules", "audit_min.rules"
	NeedsReenrollment  bool   // Flag indicating configuration changes require re-running enlist script
	ICMPStatus         string // "ok", "none", or "unknown"
	SSHStatus          string // "ok", "failed", or "unknown"
}

// InitDeviceTable initializes the devices table
func InitDeviceTable() error {
	_, err := db.Exec(`
		CREATE TABLE IF NOT EXISTS devices (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			name TEXT NOT NULL,
			type TEXT NOT NULL,
			status TEXT NOT NULL DEFAULT 'unknown',
			last_updated DATETIME DEFAULT CURRENT_TIMESTAMP,
			ip_address TEXT,
			ssh_user TEXT,
			ssh_key_path TEXT,
			ssh_port INTEGER DEFAULT 22,
			hostname TEXT,
			os_info TEXT,
			os_type TEXT DEFAULT 'linux',
			ssh_group TEXT,
			setup_user TEXT DEFAULT 'root',
			firewall_mode TEXT DEFAULT 'disabled',
			firewall_allowed_ips TEXT
		)
	`)
	if err != nil {
		return err
	}


	return nil
}

// CreateDevice creates a new device
func CreateDevice(name, deviceType string) error {
	_, err := db.Exec(`
		INSERT INTO devices (name, type, status, last_updated)
		VALUES (?, ?, 'unknown', CURRENT_TIMESTAMP)
	`, name, deviceType)
	return err
}

// CreateMonitoredDeviceWithOS creates a new device with SSH monitoring details and OS type
func CreateMonitoredDeviceWithOS(name, deviceType, ipAddress, sshUser, sshKeyPath string, sshPort int, hostname, osInfo, osType string, sshGroup string, setupUser, auditArch, auditRuleset string) error {
	_, err := db.Exec(`
		INSERT INTO devices (
			name, type, status, last_updated, 
			ip_address, ssh_user, ssh_key_path, ssh_port, 
			hostname, os_info, os_type, ssh_group,
			setup_user, firewall_mode, firewall_allowed_ips,
			audit_arch, audit_ruleset
		)
		VALUES (?, ?, 'unknown', CURRENT_TIMESTAMP, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'disabled', '', ?, ?)
	`, name, deviceType, ipAddress, sshUser, sshKeyPath, sshPort, hostname, osInfo, osType, sshGroup, setupUser, auditArch, auditRuleset)
	return err
}

// Helper function to convert bool to int for SQLite
func boolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

// GetAllDevices returns all devices
func GetAllDevices() ([]Device, error) {
	rows, err := db.Query(`
		SELECT id, name, type, status, last_updated, 
		       ip_address, ssh_user, ssh_key_path, ssh_port, hostname, os_info, os_type,
		       ssh_group, setup_user,
		       firewall_mode, firewall_allowed_ips, audit_arch, audit_ruleset, needs_reenrollment,
		       COALESCE(icmp_status, 'unknown'), COALESCE(ssh_status, 'unknown')
		FROM devices
		ORDER BY id DESC
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var devices []Device
	for rows.Next() {
		var d Device
		var ipAddress, sshUser, sshKeyPath, hostname, osInfo, osType, sshGroup, setupUser, firewallMode, firewallAllowedIPs, auditArch, auditRuleset sql.NullString
		var sshPort, needsReenrollment sql.NullInt64

		err := rows.Scan(
			&d.ID, &d.Name, &d.Type, &d.Status, &d.LastUpdated,
			&ipAddress, &sshUser, &sshKeyPath, &sshPort, &hostname, &osInfo, &osType,
			&sshGroup, &setupUser,
			&firewallMode, &firewallAllowedIPs, &auditArch, &auditRuleset, &needsReenrollment,
			&d.ICMPStatus, &d.SSHStatus,
		)
		if err != nil {
			return nil, err
		}

		// Handle nullable fields
		if ipAddress.Valid {
			d.IPAddress = ipAddress.String
		}
		if sshUser.Valid {
			d.SSHUser = sshUser.String
		}
		if sshKeyPath.Valid {
			d.SSHKeyPath = sshKeyPath.String
		}
		if sshPort.Valid {
			d.SSHPort = int(sshPort.Int64)
		} else {
			d.SSHPort = 22 // Default SSH port
		}
		if hostname.Valid {
			d.Hostname = hostname.String
		}
		if osInfo.Valid {
			d.OSInfo = osInfo.String
		}
		if osType.Valid {
			d.OSType = osType.String
		} else {
			d.OSType = "linux" // Default to Linux
		}
		if sshGroup.Valid {
			d.SSHGroup = sshGroup.String
		}
		if setupUser.Valid {
			d.SetupUser = setupUser.String
		}
		if firewallMode.Valid {
			d.FirewallMode = firewallMode.String
		} else {
			d.FirewallMode = "disabled" // Default
		}
		if firewallAllowedIPs.Valid {
			d.FirewallAllowedIPs = firewallAllowedIPs.String
		}
		if auditArch.Valid {
			d.AuditArch = auditArch.String
		} else {
			d.AuditArch = "x64" // Default
		}
		if auditRuleset.Valid {
			d.AuditRuleset = auditRuleset.String
		} else {
			d.AuditRuleset = "audit_default.rules" // Default
		}
		if needsReenrollment.Valid {
			d.NeedsReenrollment = needsReenrollment.Int64 == 1
		}

		devices = append(devices, d)
	}
	return devices, nil
}

// GetDeviceByID returns a device by its ID
func GetDeviceByID(id int64) (*Device, error) {
	var d Device
	var ipAddress, sshUser, sshKeyPath, hostname, osInfo, osType, sshGroup, setupUser, firewallMode, firewallAllowedIPs, auditArch, auditRuleset sql.NullString
	var sshPort, needsReenrollment sql.NullInt64

	err := db.QueryRow(`
		SELECT id, name, type, status, last_updated,
		       ip_address, ssh_user, ssh_key_path, ssh_port, hostname, os_info, os_type,
		       ssh_group, setup_user,
		       firewall_mode, firewall_allowed_ips, audit_arch, audit_ruleset, needs_reenrollment,
		       COALESCE(icmp_status, 'unknown'), COALESCE(ssh_status, 'unknown')
		FROM devices
		WHERE id = ?
	`, id).Scan(
		&d.ID, &d.Name, &d.Type, &d.Status, &d.LastUpdated,
		&ipAddress, &sshUser, &sshKeyPath, &sshPort, &hostname, &osInfo, &osType,
		&sshGroup, &setupUser,
		&firewallMode, &firewallAllowedIPs, &auditArch, &auditRuleset, &needsReenrollment,
		&d.ICMPStatus, &d.SSHStatus,
	)

	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}

	// Handle nullable fields
	if ipAddress.Valid {
		d.IPAddress = ipAddress.String
	}
	if sshUser.Valid {
		d.SSHUser = sshUser.String
	}
	if sshKeyPath.Valid {
		d.SSHKeyPath = sshKeyPath.String
	}
	if sshPort.Valid {
		d.SSHPort = int(sshPort.Int64)
	} else {
		d.SSHPort = 22 // Default SSH port
	}
	if hostname.Valid {
		d.Hostname = hostname.String
	}
	if osInfo.Valid {
		d.OSInfo = osInfo.String
	}
	if osType.Valid {
		d.OSType = osType.String
	} else {
		d.OSType = "linux" // Default to Linux
	}
	if sshGroup.Valid {
		d.SSHGroup = sshGroup.String
	}
	if setupUser.Valid {
		d.SetupUser = setupUser.String
	}
	if firewallMode.Valid {
		d.FirewallMode = firewallMode.String
	} else {
		d.FirewallMode = "disabled" // Default
	}
	if firewallAllowedIPs.Valid {
		d.FirewallAllowedIPs = firewallAllowedIPs.String
	}
	if auditArch.Valid {
		d.AuditArch = auditArch.String
	} else {
		d.AuditArch = "x64" // Default
	}
	if auditRuleset.Valid {
		d.AuditRuleset = auditRuleset.String
	} else {
		d.AuditRuleset = "audit_default.rules" // Default
	}
	if needsReenrollment.Valid {
		d.NeedsReenrollment = needsReenrollment.Int64 == 1
	}

	return &d, nil
}

// deviceNameCache is a simple cache to avoid frequent database lookups for device names
var deviceNameCache = struct {
	sync.RWMutex
	names map[int64]string
}{
	names: make(map[int64]string),
}

// GetDeviceNameByID returns the name of a device by its ID
// Uses a cache to avoid frequent database lookups
func GetDeviceNameByID(id int64) string {
	// Check cache first
	deviceNameCache.RLock()
	name, found := deviceNameCache.names[id]
	deviceNameCache.RUnlock()

	if found {
		return name
	}

	// Not in cache, look up in database
	var deviceName string
	err := db.QueryRow("SELECT name FROM devices WHERE id = ?", id).Scan(&deviceName)
	if err != nil {
		// If error, return a formatted string with the ID
		return fmt.Sprintf("Device %d", id)
	}

	// Store in cache for future lookups
	deviceNameCache.Lock()
	deviceNameCache.names[id] = deviceName
	deviceNameCache.Unlock()

	return deviceName
}

// UpdateMonitoredDeviceWithOSAndReenrollment updates a monitored device's information including OS type and reenrollment flag
func UpdateMonitoredDeviceWithOSAndReenrollment(id int64, name, deviceType, status, ipAddress, sshUser, sshKeyPath string, sshPort int, hostname, osInfo, osType, sshGroup string, setupUser, auditArch, auditRuleset string, needsReenrollment bool) error {
	_, err := db.Exec(`
		UPDATE devices
		SET name = ?, type = ?, status = ?, last_updated = CURRENT_TIMESTAMP,
		    ip_address = ?, ssh_user = ?, ssh_key_path = ?, ssh_port = ?,
		    hostname = ?, os_info = ?, os_type = ?, ssh_group = ?,
		    setup_user = ?,
		    audit_arch = ?, audit_ruleset = ?, needs_reenrollment = ?
		WHERE id = ?
	`, name, deviceType, status, ipAddress, sshUser, sshKeyPath, sshPort, hostname, osInfo, osType, sshGroup, setupUser, auditArch, auditRuleset, boolToInt(needsReenrollment), id)
	return err
}

// CheckDeviceStatus attempts to ping the device and returns true if online
func CheckDeviceStatus(ipAddress string) (bool, error) {
	// Validate IP address before executing command
	if net.ParseIP(ipAddress) == nil {
		return false, errors.New("invalid IP address format")
	}

	// Execute a ping command with a short timeout
	// This is a simple implementation - in a production environment,
	// you might want to use a more sophisticated check
	cmd := exec.Command("ping", "-c", "1", "-W", "2", ipAddress)

	// Capture output but don't display it
	cmd.Stdout = nil
	cmd.Stderr = nil

	err := cmd.Run()

	// If the command executed successfully, the device is reachable
	return err == nil, nil
}

// CheckSSHConnection attempts to establish an SSH connection to verify connectivity
func CheckSSHConnection(ipAddress, sshUser, sshKeyPath string, sshPort int) (bool, error) {
	// Validate inputs
	if net.ParseIP(ipAddress) == nil {
		return false, errors.New("invalid IP address format")
	}
	if sshUser == "" || sshKeyPath == "" {
		return false, errors.New("SSH user and key path are required")
	}

	// Build SSH command with timeout and connection options
	// We use SSH's built-in timeout and connection test
	portStr := fmt.Sprintf("%d", sshPort)
	cmd := exec.Command(
		"ssh",
		"-i", sshKeyPath,
		"-p", portStr,
		"-o", "ConnectTimeout=5",
		"-o", "BatchMode=yes",
		"-o", "StrictHostKeyChecking=no",
		"-o", "UserKnownHostsFile=/dev/null",
		"-o", "LogLevel=ERROR",
		fmt.Sprintf("%s@%s", sshUser, ipAddress),
		"exit 0",
	)

	// Capture output but don't display it
	cmd.Stdout = nil
	cmd.Stderr = nil

	err := cmd.Run()

	// If the command executed successfully, SSH connection is working
	return err == nil, nil
}

// UpdateAllDeviceStatuses checks and updates the status of all devices with IP addresses
func UpdateAllDeviceStatuses() error {
	// Get all devices with IP addresses and SSH configuration
	rows, err := db.Query(`
		SELECT id, ip_address, ssh_user, ssh_key_path, ssh_port
		FROM devices 
		WHERE ip_address IS NOT NULL AND ip_address != '' AND status != 'deleted'
	`)
	if err != nil {
		return err
	}
	defer rows.Close()

	for rows.Next() {
		var id int64
		var ipAddress string
		var sshUser, sshKeyPath sql.NullString
		var sshPort sql.NullInt64

		if err := rows.Scan(&id, &ipAddress, &sshUser, &sshKeyPath, &sshPort); err != nil {
			return err
		}

		// Check ICMP (ping) status
		icmpStatus := "none"
		if pingOk, err := CheckDeviceStatus(ipAddress); err == nil && pingOk {
			icmpStatus = "ok"
		} else if err != nil {
			log.Printf("Error checking ICMP for device %d: %v", id, err)
			icmpStatus = "unknown"
		}

		// Check SSH status if SSH is configured
		sshStatus := "unknown"
		if sshUser.Valid && sshKeyPath.Valid && sshUser.String != "" && sshKeyPath.String != "" {
			port := 22
			if sshPort.Valid {
				port = int(sshPort.Int64)
			}
			if sshOk, err := CheckSSHConnection(ipAddress, sshUser.String, sshKeyPath.String, port); err == nil && sshOk {
				sshStatus = "ok"
			} else {
				if err != nil {
					log.Printf("Error checking SSH for device %d: %v", id, err)
				}
				sshStatus = "failed"
			}
		}

		// Determine overall device status based on SSH (primary) or ICMP (fallback)
		status := "offline"
		if sshStatus == "ok" {
			status = "online"
		} else if sshStatus == "unknown" && icmpStatus == "ok" {
			// If SSH not configured, fall back to ICMP
			status = "online"
		}

		// Update the device status with both ICMP and SSH status
		if err := UpdateDeviceStatusWithDetails(id, status, icmpStatus, sshStatus); err != nil {
			// Log the error but continue with other devices
			log.Printf("Error updating status for device %d: %v", id, err)
		}
	}

	return rows.Err()
}

// UpdateDeviceStatusWithDetails updates device status along with ICMP and SSH status details
func UpdateDeviceStatusWithDetails(id int64, status, icmpStatus, sshStatus string) error {
	_, err := db.Exec(`
		UPDATE devices 
		SET status = ?, icmp_status = ?, ssh_status = ?, last_updated = CURRENT_TIMESTAMP
		WHERE id = ? AND status != 'deleted'
	`, status, icmpStatus, sshStatus, id)
	return err
}

// DeleteDevice performs a HARD delete of a device and its related data.
// This removes:
//   - notifications for the device (and those tied to its logs)
//   - notification_rules scoped to this device
//   - audit_logs for the device
//   - the device row itself
//
// All operations are executed within a single transaction for consistency.
func DeleteDevice(id int64) error {
	tx, err := db.Begin()
	if err != nil {
		return err
	}

	// 1) Delete notifications referencing this device or its logs
	//    We delete by device_id first, then by log_id just in case there
	//    exist notifications tied to logs for this device.
	if _, err := tx.Exec(`DELETE FROM notifications WHERE device_id = ?`, id); err != nil {
		tx.Rollback()
		return err
	}
	if _, err := tx.Exec(`DELETE FROM notifications WHERE log_id IN (SELECT id FROM audit_logs WHERE device_id = ?)`, id); err != nil {
		tx.Rollback()
		return err
	}

	// 2) Delete notification rules scoped to this device
	if _, err := tx.Exec(`DELETE FROM notification_rules WHERE device_id = ?`, id); err != nil {
		tx.Rollback()
		return err
	}

	// 3) Delete audit logs for this device
	if _, err := tx.Exec(`DELETE FROM audit_logs WHERE device_id = ?`, id); err != nil {
		tx.Rollback()
		return err
	}

	// 4) Delete the device itself
	if _, err := tx.Exec(`DELETE FROM devices WHERE id = ?`, id); err != nil {
		tx.Rollback()
		return err
	}

	if err := tx.Commit(); err != nil {
		return err
	}

	// Remove from device name cache if present
	deviceNameCache.Lock()
	delete(deviceNameCache.names, id)
	deviceNameCache.Unlock()

	return nil
}

// DeviceExistsByName checks if a device with the given name already exists
func DeviceExistsByName(name string, excludeID int64) (bool, error) {
	query := "SELECT COUNT(*) FROM devices WHERE name = ?"
	args := []interface{}{name}

	// If excludeID is provided, exclude that device from the check (for updates)
	if excludeID > 0 {
		query += " AND id != ?"
		args = append(args, excludeID)
	}

	var count int
	err := db.QueryRow(query, args...).Scan(&count)
	if err != nil {
		return false, err
	}

	return count > 0, nil
}

// DeviceExistsByIP checks if a device with the given IP address already exists
func DeviceExistsByIP(ipAddress string, excludeID int64) (bool, error) {
	if ipAddress == "" {
		return false, nil // Empty IP addresses are allowed (e.g., for non-monitored devices)
	}

	query := "SELECT COUNT(*) FROM devices WHERE ip_address = ? AND status != 'deleted'"
	args := []interface{}{ipAddress}

	// If excludeID is provided, exclude that device from the check (for updates)
	if excludeID > 0 {
		query += " AND id != ?"
		args = append(args, excludeID)
	}

	var count int
	err := db.QueryRow(query, args...).Scan(&count)
	if err != nil {
		return false, err
	}

	return count > 0, nil
}

// ClearReenrollmentFlag clears the needs_reenrollment flag for a device
func ClearReenrollmentFlag(id int64) error {
	_, err := db.Exec(`
		UPDATE devices 
		SET needs_reenrollment = 0, last_updated = CURRENT_TIMESTAMP
		WHERE id = ?
	`, id)
	return err
}

// NeedsReenrollmentChanged checks if enrollment-sensitive fields have changed
// Returns true if any field that requires re-enrollment has been modified
func NeedsReenrollmentChanged(oldDevice, newDevice *Device) bool {
	// Check enrollment-sensitive fields
	if oldDevice.SSHPort != newDevice.SSHPort {
		return true
	}
	if oldDevice.SSHUser != newDevice.SSHUser {
		return true
	}
	if oldDevice.SSHKeyPath != newDevice.SSHKeyPath {
		return true
	}
	if oldDevice.SSHGroup != newDevice.SSHGroup {
		return true
	}
	if oldDevice.AuditArch != newDevice.AuditArch {
		return true
	}
	if oldDevice.AuditRuleset != newDevice.AuditRuleset {
		return true
	}
	if oldDevice.FirewallMode != newDevice.FirewallMode {
		return true
	}
	if oldDevice.FirewallAllowedIPs != newDevice.FirewallAllowedIPs {
		return true
	}
	if oldDevice.SetupUser != newDevice.SetupUser {
		return true
	}
	return false
}
