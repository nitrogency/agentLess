package main

import (
	"database/sql"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/joho/godotenv"
	_ "github.com/mutecomm/go-sqlcipher/v4"
)

// ExportLog represents an audit log entry enriched with device information for export
type ExportLog struct {
	// Event metadata
	EventID          int64     `json:"event_id"`
	EventTimestamp   time.Time `json:"@timestamp"`
	CollectionTime   time.Time `json:"collection_timestamp"`
	
	// Device information
	DeviceID         int64  `json:"device_id"`
	DeviceName       string `json:"device_name"`
	DeviceType       string `json:"device_type"`
	DeviceIP         string `json:"device_ip"`
	DeviceHostname   string `json:"device_hostname"`
	DeviceOS         string `json:"device_os"`
	DeviceOSType     string `json:"device_os_type"`
	
	// Event details
	EventType        string `json:"event_type"`
	EventKey         string `json:"event_key"`
	EventMessage     string `json:"event_message"`
	SecurityLevel    string `json:"security_level"`
	AuditID          string `json:"audit_id,omitempty"`
	RawLog           string `json:"raw_log"`
	
	// Source identifier
	Source           string `json:"source"`
	SourceSystem     string `json:"source_system"`
}

// Config holds exporter configuration
type Config struct {
	DatabasePath      string
	EncryptionKey     string
	OutputDir         string
	StateFile         string
	BatchSize         int
	MaxFileSize       int64  // in bytes
	IncludeRawLog     bool
	ExportDeviceInfo  bool
}

var (
	config Config
	db     *sql.DB
)

func main() {
	// Parse command line flags
	configFile := flag.String("config", ".env", "Path to .env configuration file")
	dryRun := flag.Bool("dry-run", false, "Dry run mode - show what would be exported without writing")
	verbose := flag.Bool("verbose", false, "Verbose output")
	flag.Parse()

	// Load environment variables
	if *configFile != "" {
		if err := godotenv.Load(*configFile); err != nil {
			log.Printf("Warning: Could not load config file %s: %v", *configFile, err)
		}
	}

	// Load configuration
	if err := loadConfig(); err != nil {
		log.Fatalf("Failed to load configuration: %v", err)
	}

	// Initialize database connection
	if err := initDatabase(); err != nil {
		log.Fatalf("Failed to initialize database: %v", err)
	}
	defer db.Close()

	// Get last exported log ID from state file
	lastExportedID, err := readStateFile()
	if err != nil {
		log.Printf("Warning: Could not read state file, starting from beginning: %v", err)
		lastExportedID = 0
	}

	if *verbose {
		log.Printf("Starting export from log ID %d", lastExportedID)
	}

	// Export logs
	newLastID, exported, err := exportLogs(lastExportedID, *dryRun, *verbose)
	if err != nil {
		log.Fatalf("Export failed: %v", err)
	}

	if *dryRun {
		log.Printf("Dry run complete: Would export %d logs", exported)
		return
	}

	// Update state file with new last exported ID
	if newLastID > lastExportedID {
		if err := writeStateFile(newLastID); err != nil {
			log.Fatalf("Failed to update state file: %v", err)
		}
	}

	if *verbose || exported > 0 {
		log.Printf("Export complete: %d logs exported, last ID: %d", exported, newLastID)
	}
}

// loadConfig loads configuration from environment variables
func loadConfig() error {
	config = Config{
		DatabasePath:     getEnv("DATABASE_PATH", "data/site.db"),
		EncryptionKey:    getEnv("DB_ENCRYPTION_KEY", ""),
		OutputDir:        getEnv("EXPORT_OUTPUT_DIR", "/var/log/agentless-export"),
		StateFile:        getEnv("EXPORT_STATE_FILE", "/var/lib/agentless/exporter.state"),
		BatchSize:        getEnvInt("EXPORT_BATCH_SIZE", 1000),
		MaxFileSize:      getEnvInt64("EXPORT_MAX_FILE_SIZE", 10*1024*1024), // 10MB default
		IncludeRawLog:    getEnv("EXPORT_INCLUDE_RAW_LOG", "true") == "true",
		ExportDeviceInfo: getEnv("EXPORT_DEVICE_INFO", "true") == "true",
	}

	if config.EncryptionKey == "" {
		return fmt.Errorf("DB_ENCRYPTION_KEY environment variable is required")
	}

	// Ensure output directory exists
	if err := os.MkdirAll(config.OutputDir, 0755); err != nil {
		return fmt.Errorf("failed to create output directory: %w", err)
	}

	// Ensure state file directory exists
	stateDir := filepath.Dir(config.StateFile)
	if err := os.MkdirAll(stateDir, 0755); err != nil {
		return fmt.Errorf("failed to create state directory: %w", err)
	}

	return nil
}

// initDatabase initializes the SQLite database connection with encryption
func initDatabase() error {
	connectionString := fmt.Sprintf("%s?_pragma_key=%s",
		config.DatabasePath, config.EncryptionKey)

	var err error
	db, err = sql.Open("sqlite3", connectionString)
	if err != nil {
		return fmt.Errorf("failed to open database: %w", err)
	}

	// Test connection
	if err := db.Ping(); err != nil {
		return fmt.Errorf("failed to connect to database: %w", err)
	}

	return nil
}

// exportLogs exports logs since the last exported ID
func exportLogs(lastID int64, dryRun bool, verbose bool) (int64, int, error) {
	// Query for new logs with device information joined
	query := `
		SELECT 
			l.id,
			l.device_id,
			l.timestamp,
			l.event_time,
			l.type,
			l.key,
			l.message,
			l.raw_log,
			l.security_level,
			l.audit_id,
			d.name,
			d.type,
			d.ip_address,
			d.hostname,
			d.os_info,
			d.os_type
		FROM audit_logs l
		LEFT JOIN devices d ON l.device_id = d.id
		WHERE l.id > ?
		ORDER BY l.id ASC
		LIMIT ?
	`

	rows, err := db.Query(query, lastID, config.BatchSize)
	if err != nil {
		return lastID, 0, fmt.Errorf("failed to query logs: %w", err)
	}
	defer rows.Close()

	var logs []ExportLog
	var newLastID int64 = lastID

	for rows.Next() {
		var log ExportLog
		var timestamp, eventTime string
		var deviceIP, hostname, osInfo, osType, auditID sql.NullString
		var deviceType string

		err := rows.Scan(
			&log.EventID,
			&log.DeviceID,
			&timestamp,
			&eventTime,
			&log.EventType,
			&log.EventKey,
			&log.EventMessage,
			&log.RawLog,
			&log.SecurityLevel,
			&auditID,
			&log.DeviceName,
			&deviceType,
			&deviceIP,
			&hostname,
			&osInfo,
			&osType,
		)
		if err != nil {
			return newLastID, len(logs), fmt.Errorf("failed to scan log row: %w", err)
		}

		// Parse timestamps
		log.EventTimestamp = parseTimestamp(eventTime, timestamp)
		log.CollectionTime = parseTimestamp(timestamp, timestamp)

		// Set device information
		log.DeviceType = deviceType
		if deviceIP.Valid {
			log.DeviceIP = deviceIP.String
		}
		if hostname.Valid {
			log.DeviceHostname = hostname.String
		}
		if osInfo.Valid {
			log.DeviceOS = osInfo.String
		}
		if osType.Valid {
			log.DeviceOSType = osType.String
		} else {
			log.DeviceOSType = "linux" // default
		}
		if auditID.Valid {
			log.AuditID = auditID.String
		}

		// Add source metadata
		log.Source = "agentless-ids"
		log.SourceSystem = fmt.Sprintf("agentless-%s", log.DeviceOSType)

		// Remove raw log if not configured to include
		if !config.IncludeRawLog {
			log.RawLog = ""
		}

		logs = append(logs, log)
		newLastID = log.EventID
	}

	if err := rows.Err(); err != nil {
		return newLastID, len(logs), fmt.Errorf("error iterating logs: %w", err)
	}

	if len(logs) == 0 {
		return lastID, 0, nil
	}

	if dryRun {
		if verbose {
			for _, log := range logs {
				fmt.Printf("[DRY RUN] Would export log ID %d: %s/%s - %s\n",
					log.EventID, log.DeviceName, log.DeviceOSType, log.EventMessage)
			}
		}
		return newLastID, len(logs), nil
	}

	// Write logs to JSON Lines file
	if err := writeLogs(logs); err != nil {
		return newLastID, len(logs), fmt.Errorf("failed to write logs: %w", err)
	}

	return newLastID, len(logs), nil
}

// writeLogs writes logs to a JSON Lines file
func writeLogs(logs []ExportLog) error {
	// Generate filename with timestamp
	filename := fmt.Sprintf("agentless-audit-%s.jsonl", time.Now().Format("2006-01-02-15"))
	filepath := filepath.Join(config.OutputDir, filename)

	// Open file in append mode
	file, err := os.OpenFile(filepath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		return fmt.Errorf("failed to open output file: %w", err)
	}
	defer file.Close()

	// Check if file size exceeds limit
	fileInfo, err := file.Stat()
	if err == nil && fileInfo.Size() >= config.MaxFileSize {
		// Rotate file by adding sequence number
		file.Close()
		rotatedPath := strings.TrimSuffix(filepath, ".jsonl") + "-" + 
			time.Now().Format("150405") + ".jsonl"
		if err := os.Rename(filepath, rotatedPath); err != nil {
			log.Printf("Warning: Failed to rotate file: %v", err)
		}
		// Open new file
		file, err = os.OpenFile(filepath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
		if err != nil {
			return fmt.Errorf("failed to open new output file: %w", err)
		}
		defer file.Close()
	}

	// Write each log as a JSON line
	encoder := json.NewEncoder(file)
	for _, log := range logs {
		if err := encoder.Encode(log); err != nil {
			return fmt.Errorf("failed to encode log %d: %w", log.EventID, err)
		}
	}

	return nil
}

// readStateFile reads the last exported log ID from state file
func readStateFile() (int64, error) {
	data, err := os.ReadFile(config.StateFile)
	if err != nil {
		if os.IsNotExist(err) {
			return 0, nil
		}
		return 0, err
	}

	lastID, err := strconv.ParseInt(strings.TrimSpace(string(data)), 10, 64)
	if err != nil {
		return 0, fmt.Errorf("invalid state file content: %w", err)
	}

	return lastID, nil
}

// writeStateFile writes the last exported log ID to state file
func writeStateFile(lastID int64) error {
	data := []byte(fmt.Sprintf("%d\n", lastID))
	if err := os.WriteFile(config.StateFile, data, 0644); err != nil {
		return fmt.Errorf("failed to write state file: %w", err)
	}
	return nil
}

// parseTimestamp attempts to parse a timestamp string using multiple formats
func parseTimestamp(primary, fallback string) time.Time {
	// Try to parse primary timestamp
	for _, format := range []string{
		time.RFC3339,
		"2006-01-02 15:04:05",
		"2006-01-02T15:04:05Z",
		"2006-01-02T15:04:05",
	} {
		if t, err := time.Parse(format, primary); err == nil {
			return t
		}
	}

	// Try fallback
	for _, format := range []string{
		time.RFC3339,
		"2006-01-02 15:04:05",
		"2006-01-02T15:04:05Z",
		"2006-01-02T15:04:05",
	} {
		if t, err := time.Parse(format, fallback); err == nil {
			return t
		}
	}

	// Return current time if all parsing fails
	return time.Now()
}

// getEnv gets an environment variable with a default value
func getEnv(key, defaultValue string) string {
	if value, exists := os.LookupEnv(key); exists {
		return value
	}
	return defaultValue
}

// getEnvInt gets an environment variable as int with a default value
func getEnvInt(key string, defaultValue int) int {
	if value, exists := os.LookupEnv(key); exists {
		if intValue, err := strconv.Atoi(value); err == nil {
			return intValue
		}
	}
	return defaultValue
}

// getEnvInt64 gets an environment variable as int64 with a default value
func getEnvInt64(key string, defaultValue int64) int64 {
	if value, exists := os.LookupEnv(key); exists {
		if intValue, err := strconv.ParseInt(value, 10, 64); err == nil {
			return intValue
		}
	}
	return defaultValue
}
