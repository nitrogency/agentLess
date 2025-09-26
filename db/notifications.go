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
	ID            int64                     `json:"id"`
	LogID         int64                     `json:"log_id"`
	DeviceID      int64                     `json:"device_id"`
	UserID        int64                     `json:"user_id"`
	CreatedAt     time.Time                 `json:"created_at"`
	SecurityLevel NotificationSecurityLevel `json:"security_level"`
	RuleID        sql.NullInt64             `json:"rule_id"`
	Title         string                    `json:"title"`
	Message       string                    `json:"message"`
	Seen          bool                      `json:"seen"`
	SearchTerm    string                    `json:"search_term"` // From the rule that generated this notification
}

// CountUnseenNotifications returns the number of notifications where seen = 0 for a specific user
func CountUnseenNotifications(userID int64) (int64, error) {
	row := db.QueryRow(`SELECT COUNT(*) FROM notifications WHERE seen = 0 AND user_id = ?`, userID)
	var count int64
	if err := row.Scan(&count); err != nil {
		return 0, err
	}
	return count, nil
}

// CountNotificationsByLevel returns counts grouped by security_level for a specific user.
// If onlyUnseen is true, only includes seen = 0
func CountNotificationsByLevel(userID int64, onlyUnseen bool) (map[NotificationSecurityLevel]int64, error) {
	query := `SELECT security_level, COUNT(*) FROM notifications WHERE user_id = ?`
	args := []interface{}{userID}
	if onlyUnseen {
		query += " AND seen = 0"
	}
	query += " GROUP BY security_level"
	
	rows, err := db.Query(query, args...)
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

// MarkAllNotificationsSeen sets seen = 1 for all unseen notifications for a specific user
func MarkAllNotificationsSeen(userID int64) error {
	_, err := db.Exec(`UPDATE notifications SET seen = 1 WHERE seen = 0 AND user_id = ?`, userID)
	return err
}

// MarkNotificationSeen sets seen = 1 for a specific notification by ID
func MarkNotificationSeen(notificationID int64) error {
	_, err := db.Exec(`UPDATE notifications SET seen = 1 WHERE id = ?`, notificationID)
	return err
}

// MarkNotificationSeenByUser sets seen = 1 for a specific notification by ID, but only if it belongs to the specified user
func MarkNotificationSeenByUser(notificationID, userID int64) error {
	result, err := db.Exec(`UPDATE notifications SET seen = 1 WHERE id = ? AND user_id = ?`, notificationID, userID)
	if err != nil {
		return err
	}
	
	// Check if any rows were affected (notification exists and belongs to user)
	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return err
	}
	
	if rowsAffected == 0 {
		return fmt.Errorf("notification not found or access denied")
	}
	
	return nil
}

// NotificationRule defines criteria to create notifications from audit logs
// match_type determines which field is used:
//   - security_level: matches on security_level field
//   - audit_type: matches on audit "type" field
//   - search_term: matches on substring match in raw_log/message
//
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
	_, err := db.Exec(`
		CREATE TABLE IF NOT EXISTS notifications (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			log_id INTEGER NOT NULL,
			device_id INTEGER NOT NULL,
			user_id INTEGER NOT NULL,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			security_level TEXT NOT NULL,
			rule_id INTEGER,
			title TEXT,
			message TEXT,
			seen INTEGER DEFAULT 0,
			FOREIGN KEY (log_id) REFERENCES audit_logs(id),
			FOREIGN KEY (device_id) REFERENCES devices(id),
			FOREIGN KEY (user_id) REFERENCES users(id),
			FOREIGN KEY (rule_id) REFERENCES notification_rules(id)
		);
		CREATE INDEX IF NOT EXISTS idx_notifications_seen ON notifications(seen);
		CREATE INDEX IF NOT EXISTS idx_notifications_created ON notifications(created_at);
		CREATE INDEX IF NOT EXISTS idx_notifications_level ON notifications(security_level);
		CREATE INDEX IF NOT EXISTS idx_notifications_device ON notifications(device_id);
		CREATE INDEX IF NOT EXISTS idx_notifications_user ON notifications(user_id);
	`)
	if err != nil {
		return err
	}

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

// CreateNotification inserts or updates a new notification with duplicate prevention
func CreateNotification(logID, deviceID, userID int64, level NotificationSecurityLevel, ruleID sql.NullInt64, title, message string) (int64, error) {
	// Check for recent duplicate notifications (same rule, same title within last hour)
	// This prevents notification spam from repeated events
	var count int
	err := db.QueryRow(`
		SELECT COUNT(*) FROM notifications 
		WHERE rule_id = ? AND title = ? AND created_at > datetime('now', '-1 hour')
	`, nullableID(ruleID), title).Scan(&count)
	
	if err == nil && count >= 5 { // Max 5 notifications per hour per rule+title
		return 0, nil // Silently ignore to prevent spam
	}
	
	res, err := db.Exec(`
		INSERT INTO notifications (log_id, device_id, user_id, security_level, rule_id, title, message, seen)
		VALUES (?, ?, ?, ?, ?, ?, ?, 0)
	`, logID, deviceID, userID, string(level), nullableID(ruleID), title, message)
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

// ListNotifications returns recent notifications with optional seen filter for a specific user
func ListNotifications(userID int64, limit int, onlyUnseen bool) ([]Notification, error) {
	if limit <= 0 {
		limit = 100
	}
	query := `SELECT n.id, n.log_id, n.device_id, n.user_id, n.created_at, n.security_level, n.rule_id, n.title, n.message, n.seen, COALESCE(nr.search_term, '') as search_term
		FROM notifications n
		LEFT JOIN notification_rules nr ON n.rule_id = nr.id`
	var where []string
	var args []interface{}
	
	// Always filter by user_id
	where = append(where, "n.user_id = ?")
	args = append(args, userID)
	
	if onlyUnseen {
		where = append(where, "n.seen = 0")
	}
	if len(where) > 0 {
		query += " WHERE " + strings.Join(where, " AND ")
	}
	query += " ORDER BY n.created_at DESC LIMIT ?"
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
		if err := rows.Scan(&n.ID, &n.LogID, &n.DeviceID, &n.UserID, &created, &level, &n.RuleID, &n.Title, &n.Message, &n.Seen, &n.SearchTerm); err != nil {
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
		var securityLevel sql.NullString
		var auditType sql.NullString
		var searchTerm sql.NullString
		if err := rows.Scan(&r.ID, &r.Name, &enabledInt, &r.MatchType, &securityLevel, &auditType, &searchTerm, &deviceID); err != nil {
			return err
		}
		r.Enabled = enabledInt == 1
		r.DeviceID = deviceID
		r.SecurityLevel = securityLevel.String
		r.AuditType = auditType.String
		r.SearchTerm = searchTerm.String

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
			
			// Determine which users should receive this notification
			var userIDs []int64
			
			if r.MatchType == "search_term" {
				// For custom search terms, find the user who created this rule
				var userID sql.NullInt64
				err := db.QueryRow(`
					SELECT CAST(SUBSTR(name, 6, INSTR(SUBSTR(name, 6), '-') - 1) AS INTEGER) as user_id
					FROM notification_rules 
					WHERE id = ? AND name LIKE 'User-%'
				`, r.ID).Scan(&userID)
				if err == nil && userID.Valid {
					userIDs = append(userIDs, userID.Int64)
				}
			} else {
				// For system-level notifications, send to all users with appropriate flicker preferences
				var level string
				switch strings.ToLower(string(log.SecurityLevel)) {
				case "high":
					level = "flicker_high = 1"
				case "medium":
					level = "flicker_medium = 1"
				case "low":
					level = "flicker_low = 1"
				default:
					level = "1=1" // Send to all users if security level unknown
				}
				
				rows, err := db.Query(fmt.Sprintf("SELECT id FROM users WHERE %s", level))
				if err == nil {
					defer rows.Close()
					for rows.Next() {
						var userID int64
						if err := rows.Scan(&userID); err == nil {
							userIDs = append(userIDs, userID)
						}
					}
				}
			}
			
			// Create notification for each relevant user
			for _, userID := range userIDs {
				_, err := CreateNotification(insertedLogID, log.DeviceID, userID, NotificationSecurityLevel(strings.ToLower(string(log.SecurityLevel))), rid, title, message)
				if err != nil {
					return err
				}
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
			"search_term",   // match type
			"",              // security level (not used for search_term)
			"",              // audit type (not used for search_term)
			term,            // search term
			sql.NullInt64{}, // device_id (null = all devices)
			true,            // enabled
		)
		if err != nil {
			return fmt.Errorf("failed to create notification rule for term '%s': %v", term, err)
		}
	}

	return nil
}
