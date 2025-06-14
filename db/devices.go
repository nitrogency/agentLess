package db

import (
	"database/sql"
	"errors"
	"log"
	"net"
	"os/exec"
	"time"
)

type Device struct {
	ID            int64
	Name          string
	Type          string
	Status        string
	LastUpdated   time.Time
	IPAddress     string
	SSHUser       string
	SSHKeyPath    string
	SSHPort       int
	Hostname      string
	OSInfo        string
	SSHGroup      string
	RandomUser    bool
	RandomKey     bool
	SetupUser     string
	SetupPassword string
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
			ssh_group TEXT,
			random_user INTEGER DEFAULT 0,
			random_key INTEGER DEFAULT 0,
			setup_user TEXT DEFAULT 'root',
			setup_password TEXT
		)
	`)
	return err
}

// CreateDevice creates a new device
func CreateDevice(name, deviceType string) error {
	_, err := db.Exec(`
		INSERT INTO devices (name, type, status, last_updated)
		VALUES (?, ?, 'unknown', CURRENT_TIMESTAMP)
	`, name, deviceType)
	return err
}

// CreateMonitoredDevice creates a new device with SSH monitoring details
func CreateMonitoredDevice(name, deviceType, ipAddress, sshUser, sshKeyPath string, sshPort int, hostname, osInfo string, sshGroup string, randomUser bool, randomKey bool, setupUser, setupPassword string) error {
	_, err := db.Exec(`
		INSERT INTO devices (
			name, type, status, last_updated, 
			ip_address, ssh_user, ssh_key_path, ssh_port, 
			hostname, os_info, ssh_group, random_user, random_key,
			setup_user, setup_password
		)
		VALUES (?, ?, 'unknown', CURRENT_TIMESTAMP, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`, name, deviceType, ipAddress, sshUser, sshKeyPath, sshPort, hostname, osInfo, sshGroup, boolToInt(randomUser), boolToInt(randomKey), setupUser, setupPassword)
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
		       ip_address, ssh_user, ssh_key_path, ssh_port, hostname, os_info,
		       ssh_group, random_user, random_key, setup_user, setup_password
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
		var ipAddress, sshUser, sshKeyPath, hostname, osInfo, sshGroup, setupUser, setupPassword sql.NullString
		var sshPort, randomUser, randomKey sql.NullInt64

		err := rows.Scan(
			&d.ID, &d.Name, &d.Type, &d.Status, &d.LastUpdated,
			&ipAddress, &sshUser, &sshKeyPath, &sshPort, &hostname, &osInfo,
			&sshGroup, &randomUser, &randomKey, &setupUser, &setupPassword,
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
		if sshGroup.Valid {
			d.SSHGroup = sshGroup.String
		}
		if randomUser.Valid {
			d.RandomUser = randomUser.Int64 == 1
		}
		if randomKey.Valid {
			d.RandomKey = randomKey.Int64 == 1
		}
		if setupUser.Valid {
			d.SetupUser = setupUser.String
		}
		if setupPassword.Valid {
			d.SetupPassword = setupPassword.String
		}

		devices = append(devices, d)
	}
	return devices, nil
}

// GetDeviceByID returns a device by its ID
func GetDeviceByID(id int64) (*Device, error) {
	var d Device
	var ipAddress, sshUser, sshKeyPath, hostname, osInfo, sshGroup, setupUser, setupPassword sql.NullString
	var sshPort, randomUser, randomKey sql.NullInt64

	err := db.QueryRow(`
		SELECT id, name, type, status, last_updated,
		       ip_address, ssh_user, ssh_key_path, ssh_port, hostname, os_info,
		       ssh_group, random_user, random_key, setup_user, setup_password
		FROM devices
		WHERE id = ?
	`, id).Scan(
		&d.ID, &d.Name, &d.Type, &d.Status, &d.LastUpdated,
		&ipAddress, &sshUser, &sshKeyPath, &sshPort, &hostname, &osInfo,
		&sshGroup, &randomUser, &randomKey, &setupUser, &setupPassword,
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
	if sshGroup.Valid {
		d.SSHGroup = sshGroup.String
	}
	if randomUser.Valid {
		d.RandomUser = randomUser.Int64 == 1
	}
	if randomKey.Valid {
		d.RandomKey = randomKey.Int64 == 1
	}
	if setupUser.Valid {
		d.SetupUser = setupUser.String
	}
	if setupPassword.Valid {
		d.SetupPassword = setupPassword.String
	}

	return &d, nil
}

// UpdateDevice updates a device's information
func UpdateDevice(id int64, name, deviceType, status string) error {
	_, err := db.Exec(`
		UPDATE devices
		SET name = ?, type = ?, status = ?, last_updated = CURRENT_TIMESTAMP
		WHERE id = ?
	`, name, deviceType, status, id)
	return err
}

// UpdateMonitoredDevice updates a monitored device's information
func UpdateMonitoredDevice(id int64, name, deviceType, status, ipAddress, sshUser, sshKeyPath string, sshPort int, hostname, osInfo, sshGroup string, randomUser bool, randomKey bool, setupUser, setupPassword string) error {
	_, err := db.Exec(`
		UPDATE devices
		SET name = ?, type = ?, status = ?, last_updated = CURRENT_TIMESTAMP,
		    ip_address = ?, ssh_user = ?, ssh_key_path = ?, ssh_port = ?,
		    hostname = ?, os_info = ?, ssh_group = ?, random_user = ?, random_key = ?,
		    setup_user = ?, setup_password = ?
		WHERE id = ?
	`, name, deviceType, status, ipAddress, sshUser, sshKeyPath, sshPort, hostname, osInfo, sshGroup, boolToInt(randomUser), boolToInt(randomKey), setupUser, setupPassword, id)
	return err
}

// UpdateDeviceStatus updates just the status of a device
func UpdateDeviceStatus(id int64, status string) error {
	_, err := db.Exec(`
		UPDATE devices 
		SET status = ?, last_updated = CURRENT_TIMESTAMP
		WHERE id = ?
	`, status, id)
	return err
}

// UpdateDeviceSSHKey updates just the SSH key path for a device
func UpdateDeviceSSHKey(id int64, sshKeyPath string) error {
	_, err := db.Exec(`
		UPDATE devices 
		SET ssh_key_path = ?, last_updated = CURRENT_TIMESTAMP
		WHERE id = ?
	`, sshKeyPath, id)
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

// UpdateAllDeviceStatuses checks and updates the status of all devices with IP addresses
func UpdateAllDeviceStatuses() error {
	// Get all devices with IP addresses
	rows, err := db.Query(`
		SELECT id, ip_address 
		FROM devices 
		WHERE ip_address IS NOT NULL AND ip_address != ''
	`)
	if err != nil {
		return err
	}
	defer rows.Close()

	for rows.Next() {
		var id int64
		var ipAddress string

		if err := rows.Scan(&id, &ipAddress); err != nil {
			return err
		}

		// Check if the device is online
		online, err := CheckDeviceStatus(ipAddress)
		if err != nil {
			// Log the error but continue with other devices
			log.Printf("Error checking status for device %d: %v", id, err)
			continue
		}

		// Update the device status
		status := "offline"
		if online {
			status = "online"
		}

		if err := UpdateDeviceStatus(id, status); err != nil {
			// Log the error but continue with other devices
			log.Printf("Error updating status for device %d: %v", id, err)
		}
	}

	return rows.Err()
}

// DeleteDevice deletes a device
func DeleteDevice(id int64) error {
	_, err := db.Exec("DELETE FROM devices WHERE id = ?", id)
	return err
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

	query := "SELECT COUNT(*) FROM devices WHERE ip_address = ?"
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
