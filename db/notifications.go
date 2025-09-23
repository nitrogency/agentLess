package db

import (
	"database/sql"
	"fmt"
	"strings"
	"time"
)

// NotificationSecurityLevel mirrors AuditLog SecurityLevel
// Values: "low", "medium", "high"
type NotificationSecurityLevel string

const (
	NotificationLow    NotificationSecurityLevel = "low"
	NotificationMedium NotificationSecurityLevel = "medium"
	NotificationHigh   NotificationSecurityLevel = "high"
)

// Notification represents a generated notification from an audit log
// It is linked to a specific audit log and the rule that produced it (if any)
type Notification struct {
	ID            int64
	LogID         int64
	DeviceID      int64
	CreatedAt     time.Time
	SecurityLevel NotificationSecurityLevel
	RuleID        sql.NullInt64
	Title         string
	Message       string
	Seen          bool
}

// CountUnseenNotifications returns the number of notifications where seen = 0
func CountUnseenNotifications() (int64, error) {
    row := db.QueryRow(`SELECT COUNT(*) FROM notifications WHERE seen = 0`)
    var count int64
    if err := row.Scan(&count); err != nil {
        return 0, err
    }
    return count, nil
}

// CountNotificationsByLevel returns counts grouped by security_level.
// If onlyUnseen is true, only includes seen = 0
func CountNotificationsByLevel(onlyUnseen bool) (map[NotificationSecurityLevel]int64, error) {
    query := `SELECT security_level, COUNT(*) FROM notifications`
    if onlyUnseen {
        query += ` WHERE seen = 0`
    }
    query += ` GROUP BY security_level`

    rows, err := db.Query(query)
    if err != nil {
        return nil, err
    }
    defer rows.Close()

    out := map[NotificationSecurityLevel]int64{
        NotificationLow:    0,
        NotificationMedium: 0,
        NotificationHigh:   0,
    }
    for rows.Next() {
        var level string
        var cnt int64
        if err := rows.Scan(&level, &cnt); err != nil {
            return nil, err
        }
        out[NotificationSecurityLevel(strings.ToLower(level))] = cnt
    }
    return out, nil
}

// MarkAllNotificationsSeen sets seen = 1 for all unseen notifications
func MarkAllNotificationsSeen() error {
    _, err := db.Exec(`UPDATE notifications SET seen = 1 WHERE seen = 0`)
    return err
}

// NotificationRule defines criteria to create notifications from audit logs
// match_type determines which field is used:
//   - security_level: matches on security_level field
//   - audit_type: matches on audit "type" field
//   - search_term: matches on substring match in raw_log/message
// Optionally filter by device_id.
type NotificationRule struct {
	ID            int64
	Name          string
	Enabled       bool
	MatchType     string // security_level | audit_type | search_term
	SecurityLevel string // used when MatchType == security_level
	AuditType     string // used when MatchType == audit_type
	SearchTerm    string // used when MatchType == search_term
	DeviceID      sql.NullInt64
	CreatedAt     time.Time
}

// InitNotificationTables creates notifications and notification_rules tables
func InitNotificationTables() error {
	// notifications table
	_, err := db.Exec(`
		CREATE TABLE IF NOT EXISTS notifications (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			log_id INTEGER NOT NULL,
			device_id INTEGER NOT NULL,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			security_level TEXT NOT NULL,
			rule_id INTEGER,
			title TEXT,
			message TEXT,
			seen INTEGER NOT NULL DEFAULT 0,
			FOREIGN KEY (log_id) REFERENCES audit_logs(id),
			FOREIGN KEY (device_id) REFERENCES devices(id),
			FOREIGN KEY (rule_id) REFERENCES notification_rules(id)
		);
		CREATE INDEX IF NOT EXISTS idx_notifications_device_id ON notifications(device_id);
		CREATE INDEX IF NOT EXISTS idx_notifications_seen ON notifications(seen);
	`)
	if err != nil {
		return err
	}

	// notification rules table
	_, err = db.Exec(`
		CREATE TABLE IF NOT EXISTS notification_rules (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			name TEXT NOT NULL,
			enabled INTEGER NOT NULL DEFAULT 1,
			match_type TEXT NOT NULL,
			security_level TEXT,
			audit_type TEXT,
			search_term TEXT,
			device_id INTEGER,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			FOREIGN KEY (device_id) REFERENCES devices(id)
		);
		CREATE INDEX IF NOT EXISTS idx_notification_rules_enabled ON notification_rules(enabled);
		CREATE INDEX IF NOT EXISTS idx_notification_rules_device ON notification_rules(device_id);
	`)
	if err != nil {
		return err
	}

	return nil
}

// CreateNotification inserts a notification row
func CreateNotification(logID, deviceID int64, level NotificationSecurityLevel, ruleID sql.NullInt64, title, message string) (int64, error) {
	res, err := db.Exec(`
		INSERT INTO notifications (log_id, device_id, security_level, rule_id, title, message)
		VALUES (?, ?, ?, ?, ?, ?)
	`, logID, deviceID, string(level), nullableID(ruleID), title, message)
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

func nullableID(id sql.NullInt64) interface{} {
	if id.Valid {
		return id.Int64
	}
	return nil
}

// ListNotifications returns recent notifications with optional seen filter
func ListNotifications(limit int, onlyUnseen bool) ([]Notification, error) {
	if limit <= 0 {
		limit = 100
	}
	query := `SELECT id, log_id, device_id, created_at, security_level, rule_id, title, message, seen
		FROM notifications`
	var where []string
	var args []interface{}
	if onlyUnseen {
		where = append(where, "seen = 0")
	}
	if len(where) > 0 {
		query += " WHERE " + strings.Join(where, " AND ")
	}
	query += " ORDER BY created_at DESC LIMIT ?"
	args = append(args, limit)

	rows, err := db.Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []Notification
	for rows.Next() {
		var n Notification
		var created string
		var level string
		if err := rows.Scan(&n.ID, &n.LogID, &n.DeviceID, &created, &level, &n.RuleID, &n.Title, &n.Message, &n.Seen); err != nil {
			return nil, err
		}
		n.CreatedAt = parseTimestamp(created)
		n.SecurityLevel = NotificationSecurityLevel(level)
		out = append(out, n)
	}
	return out, nil
}

// CreateNotificationRule inserts a rule
func CreateNotificationRule(name, matchType, securityLevel, auditType, searchTerm string, deviceID sql.NullInt64, enabled bool) (int64, error) {
	enabledInt := 0
	if enabled {
		enabledInt = 1
	}
	res, err := db.Exec(`
		INSERT INTO notification_rules (name, enabled, match_type, security_level, audit_type, search_term, device_id)
		VALUES (?, ?, ?, ?, ?, ?, ?)
	`, name, enabledInt, matchType, nullIfEmpty(securityLevel), nullIfEmpty(auditType), nullIfEmpty(searchTerm), nullableID(deviceID))
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

func nullIfEmpty(s string) interface{} {
	if strings.TrimSpace(s) == "" {
		return nil
	}
	return s
}

// evaluateRulesAndCreateNotifications checks all enabled rules against a log and creates notifications when matched
func evaluateRulesAndCreateNotifications(log AuditLog, insertedLogID int64) error {
	rows, err := db.Query(`SELECT id, name, enabled, match_type, security_level, audit_type, search_term, device_id FROM notification_rules WHERE enabled = 1`)
	if err != nil {
		return err
	}
	defer rows.Close()

	for rows.Next() {
		var r NotificationRule
		var enabledInt int
		var deviceID sql.NullInt64
		if err := rows.Scan(&r.ID, &r.Name, &enabledInt, &r.MatchType, &r.SecurityLevel, &r.AuditType, &r.SearchTerm, &deviceID); err != nil {
			return err
		}
		r.Enabled = enabledInt == 1
		r.DeviceID = deviceID

		// Optional device filter
		if r.DeviceID.Valid && r.DeviceID.Int64 != log.DeviceID {
			continue
		}

		matched := false
		title := ""
		message := ""

		switch strings.ToLower(r.MatchType) {
		case "security_level":
			if r.SecurityLevel != "" && strings.EqualFold(r.SecurityLevel, string(log.SecurityLevel)) {
				matched = true
				title = fmt.Sprintf("%s security event", strings.Title(string(log.SecurityLevel)))
				message = log.Message
			}
		case "audit_type":
			if r.AuditType != "" && strings.EqualFold(r.AuditType, log.Type) {
				matched = true
				title = fmt.Sprintf("Audit type match: %s", log.Type)
				message = log.Message
			}
		case "search_term":
			term := strings.TrimSpace(r.SearchTerm)
			if term != "" {
				lcTerm := strings.ToLower(term)
				if strings.Contains(strings.ToLower(log.RawLog), lcTerm) || strings.Contains(strings.ToLower(log.Message), lcTerm) {
					matched = true
					title = fmt.Sprintf("Matched term: %s", term)
					message = log.Message
				}
			}
		}

		if matched {
			var rid sql.NullInt64
			rid.Valid = true
			rid.Int64 = r.ID
			_, err := CreateNotification(insertedLogID, log.DeviceID, NotificationSecurityLevel(strings.ToLower(string(log.SecurityLevel))), rid, title, message)
			if err != nil {
				return err
			}
		}
	}
	return nil
}

// UpdateUserNotificationRules creates or updates notification rules for a user based on their search terms
func UpdateUserNotificationRules(userID int64, searchTerms string) error {
	// First, delete existing rules for this user (rules with names starting with "User-[userID]-")
	_, err := db.Exec(`DELETE FROM notification_rules WHERE name LIKE ?`, fmt.Sprintf("User-%d-%%", userID))
	if err != nil {
		return fmt.Errorf("failed to delete existing user rules: %v", err)
	}

	// If search terms are empty, we're done
	if strings.TrimSpace(searchTerms) == "" {
		return nil
	}

	// Parse search terms (comma-separated)
	terms := strings.Split(searchTerms, ",")
	for i, term := range terms {
		term = strings.TrimSpace(term)
		if term == "" {
			continue
		}

		// Create a notification rule for this search term
		ruleName := fmt.Sprintf("User-%d-Term-%d", userID, i+1)
		_, err := CreateNotificationRule(
			ruleName,
			"search_term", // match type
			"",            // security level (not used for search_term)
			"",            // audit type (not used for search_term)
			term,          // search term
			sql.NullInt64{}, // device_id (null = all devices)
			true,          // enabled
		)
		if err != nil {
			return fmt.Errorf("failed to create notification rule for term '%s': %v", term, err)
		}
	}

	return nil
}
