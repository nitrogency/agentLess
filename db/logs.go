package db

import (
	"time"
)

// AuditLog represents an audit log entry from a monitored device
type AuditLog struct {
	ID        int64
	DeviceID  int64
	Timestamp time.Time
	EventTime string
	Type      string
	Key       string
	Message   string
	RawLog    string
}

// InitAuditLogTable initializes the audit_logs table
func InitAuditLogTable() error {
	_, err := db.Exec(`
		CREATE TABLE IF NOT EXISTS audit_logs (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			device_id INTEGER NOT NULL,
			timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
			event_time TEXT,
			type TEXT,
			key TEXT,
			message TEXT,
			raw_log TEXT,
			FOREIGN KEY (device_id) REFERENCES devices(id)
		)
	`)

	if err != nil {
		return err
	}

	// Create index on device_id and timestamp
	_, err = db.Exec(`
		CREATE INDEX IF NOT EXISTS idx_audit_logs_device_time ON audit_logs(device_id, timestamp)
	`)

	return err
}

// GetAllAuditLogs returns all audit logs
func GetAllAuditLogs() ([]AuditLog, error) {
	rows, err := db.Query(`
		SELECT id, device_id, timestamp, event_time, type, key, message, raw_log
		FROM audit_logs
		ORDER BY timestamp DESC
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var logs []AuditLog
	for rows.Next() {
		var log AuditLog
		var timestamp string

		err := rows.Scan(
			&log.ID,
			&log.DeviceID,
			&timestamp,
			&log.EventTime,
			&log.Type,
			&log.Key,
			&log.Message,
			&log.RawLog,
		)
		if err != nil {
			return nil, err
		}

		// Parse the timestamp
		log.Timestamp, _ = time.Parse("2006-01-02 15:04:05", timestamp)
		logs = append(logs, log)
	}

	return logs, nil
}

// GetAuditLogsByDeviceID returns audit logs for a specific device
func GetAuditLogsByDeviceID(deviceID int64, page, pageSize int, searchTerm string) ([]AuditLog, int, error) {
	// Calculate offset
	offset := (page - 1) * pageSize

	// Build the query
	var query string
	var args []interface{}
	var countQuery string

	if searchTerm != "" {
		// If search term is provided, filter by it
		query = `
			SELECT id, device_id, timestamp, event_time, type, key, message, raw_log
			FROM audit_logs
			WHERE device_id = ? AND (
				type LIKE ? OR 
				key LIKE ? OR 
				message LIKE ? OR 
				raw_log LIKE ?
			)
			ORDER BY timestamp DESC
			LIMIT ? OFFSET ?
		`
		searchPattern := "%" + searchTerm + "%"
		args = []interface{}{deviceID, searchPattern, searchPattern, searchPattern, searchPattern, pageSize, offset}
		
		countQuery = `
			SELECT COUNT(*)
			FROM audit_logs
			WHERE device_id = ? AND (
				type LIKE ? OR 
				key LIKE ? OR 
				message LIKE ? OR 
				raw_log LIKE ?
			)
		`
	} else {
		// If no search term, get all logs for the device
		query = `
			SELECT id, device_id, timestamp, event_time, type, key, message, raw_log
			FROM audit_logs
			WHERE device_id = ?
			ORDER BY timestamp DESC
			LIMIT ? OFFSET ?
		`
		args = []interface{}{deviceID, pageSize, offset}
		
		countQuery = `
			SELECT COUNT(*)
			FROM audit_logs
			WHERE device_id = ?
		`
	}

	// Get total count for pagination
	var totalCount int
	var countArgs []interface{}
	
	if searchTerm != "" {
		searchPattern := "%" + searchTerm + "%"
		countArgs = []interface{}{deviceID, searchPattern, searchPattern, searchPattern, searchPattern}
	} else {
		countArgs = []interface{}{deviceID}
	}
	
	err := db.QueryRow(countQuery, countArgs...).Scan(&totalCount)
	if err != nil {
		return nil, 0, err
	}

	// Execute the main query
	rows, err := db.Query(query, args...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	var logs []AuditLog
	for rows.Next() {
		var log AuditLog
		var timestamp string

		err := rows.Scan(
			&log.ID,
			&log.DeviceID,
			&timestamp,
			&log.EventTime,
			&log.Type,
			&log.Key,
			&log.Message,
			&log.RawLog,
		)
		if err != nil {
			return nil, 0, err
		}

		// Parse the timestamp
		log.Timestamp, _ = time.Parse("2006-01-02 15:04:05", timestamp)
		logs = append(logs, log)
	}

	return logs, totalCount, nil
}

// DeleteOldAuditLogs deletes audit logs older than the specified number of days
func DeleteOldAuditLogs(retentionDays int) (int64, error) {
	result, err := db.Exec(`
		DELETE FROM audit_logs 
		WHERE timestamp < datetime('now', '-? day')
	`, retentionDays)

	if err != nil {
		return 0, err
	}

	return result.RowsAffected()
}
