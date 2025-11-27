package main

import (
	"bufio"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"agentless/db"
)

var (
	reMsgID   = regexp.MustCompile(`msg=audit\(([^)]+)\)`)
	reKey     = regexp.MustCompile(`key="?([A-Za-z0-9_-]+)"?`)
	reComm    = regexp.MustCompile(`comm="([^"]+)"`)
	reExe     = regexp.MustCompile(`exe="([^"]+)"`)
	reAuid    = regexp.MustCompile(`\bauid=([0-9]+)\b`)
	reSuccess = regexp.MustCompile(`\bsuccess=(yes|no)\b`)
	reArg     = regexp.MustCompile(`a[0-9]+="([^"]*)"`)

	reClam = regexp.MustCompile(`\s*(/[^:]+):\s+([A-Za-z0-9._-]+)\s+(FOUND|OK)\b`)
)

type Event struct {
	ID      string   `json:"id"`
	Key     string   `json:"key,omitempty"`
	Host    string   `json:"host,omitempty"`
	Comm    string   `json:"comm,omitempty"`
	Exe     string   `json:"exe,omitempty"`
	Auid    *int64   `json:"auid,omitempty"`
	Success string   `json:"success,omitempty"`
	Argv    []string `json:"argv,omitempty"`
	Level   string   `json:"level"`
	Raw     []string `json:"raw"`
}

func inSet(s string, set map[string]struct{}) bool {
	_, ok := set[s]
	return ok
}

var (
	// These will be populated from config file or defaults
	highKeys   = make(map[string]struct{})
	mediumKeys = make(map[string]struct{})
	lowKeys    = make(map[string]struct{})
)

// loadPriorities reads the audit priority configuration file
// Format: [section] headers followed by keys, one per line
// Sections: [high], [medium], [low]
func loadPriorities(configPath string) error {
	// Clear any existing priorities
	highKeys = make(map[string]struct{})
	mediumKeys = make(map[string]struct{})
	lowKeys = make(map[string]struct{})

	file, err := os.Open(configPath)
	if err != nil {
		return fmt.Errorf("failed to open config file: %w", err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	var currentSection string

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		// Skip empty lines and comments
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// Check for section headers
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			currentSection = strings.ToLower(strings.Trim(line, "[]"))
			continue
		}

		// Add key to current section
		key := strings.ToLower(line)
		switch currentSection {
		case "high":
			highKeys[key] = struct{}{}
		case "medium":
			mediumKeys[key] = struct{}{}
		case "low":
			lowKeys[key] = struct{}{}
		}
	}

	if err := scanner.Err(); err != nil {
		return fmt.Errorf("failed to read config: %w", err)
	}

	return nil
}

// classify determines the security level of an audit event based purely on the audit rule key
// The audit rules assign keys to events at the kernel level:
// - High keys: SUID execution, root key access, network connections, 32-bit ABI, anonymous files
// - Medium keys: system modifications, reconnaissance, suspicious tools, audit config changes
// - Low keys: general command execution (exec_all)
// Events without keys are not stored to reduce noise
func classify(ev *Event) string {
	key := strings.ToLower(ev.Key)

	// Key-based classification
	if inSet(key, highKeys) {
		return "high"
	}
	if inSet(key, mediumKeys) {
		return "medium"
	}
	if inSet(key, lowKeys) {
		return "low"
	}

	// Default to low for any remaining events with keys
	return "low"
}

func flush(curID string, raw []string, host string, deviceID int64) {
	if len(raw) == 0 {
		return
	}
	buf := strings.Join(raw, "\n")
	ev := Event{ID: curID, Host: host, Raw: append([]string{}, raw...)}

	if m := reKey.FindStringSubmatch(buf); len(m) == 2 {
		ev.Key = m[1]
	}
	if m := reComm.FindStringSubmatch(buf); len(m) == 2 {
		ev.Comm = strings.ToLower(m[1])
	}
	if m := reExe.FindStringSubmatch(buf); len(m) == 2 {
		ev.Exe = m[1]
	}
	if m := reAuid.FindStringSubmatch(buf); len(m) == 2 {
		// simple Atoi
		var v int64
		for i := 0; i < len(m[1]); i++ {
			v = v*10 + int64(m[1][i]-'0')
		}
		ev.Auid = &v
	}
	if m := reSuccess.FindStringSubmatch(buf); len(m) == 2 {
		ev.Success = m[1]
	}

	// collect argv from EXECVE lines
	for _, line := range raw {
		if !strings.HasPrefix(line, "type=EXECVE") {
			continue
		}
		matches := reArg.FindAllStringSubmatch(line, -1)
		for _, a := range matches {
			ev.Argv = append(ev.Argv, a[1])
		}
	}

	ev.Level = classify(&ev)

	// Derive event_time from audit msg id (epoch seconds before '.')
	eventTime := ""
	if ev.ID != "" {
		idPart := ev.ID
		// ev.ID format typically: 1727027892.123:456
		if colonIdx := strings.IndexByte(idPart, ':'); colonIdx >= 0 {
			idPart = idPart[:colonIdx]
		}
		if dotIdx := strings.IndexByte(idPart, '.'); dotIdx >= 0 {
			idPart = idPart[:dotIdx]
		}
		if sec, err := strconv.ParseInt(idPart, 10, 64); err == nil {
			eventTime = time.Unix(sec, 0).UTC().Format("2006-01-02 15:04:05")
		}
	}

	// Construct a human-friendly message
	message := "Raw entry"
	if len(ev.Argv) > 0 {
		message = "Command Line: " + strings.Join(ev.Argv, " ")
	} else if ev.Comm != "" && ev.Exe != "" {
		message = "Command: " + ev.Comm + " (" + ev.Exe + ")"
	} else if ev.Comm != "" {
		message = "Command: " + ev.Comm
	}

	// Skip logs without assigned keys (reduces noise from generic system activity)
	if strings.TrimSpace(ev.Key) == "" {
		return // Don't store logs without specific audit rule keys
	}

	// Use comm as the type for display/filtering consistency
	logType := ev.Comm

	// Insert directly into DB; ignore duplicate via unique index (device_id, audit_id)
	if _, err := db.InsertAuditLog(deviceID, eventTime, logType, ev.Key, message, buf, ev.Level, ev.ID); err != nil {
		fmt.Fprintln(os.Stderr, "insert error:", err)
	}
}

func ingestClam(line, host string, deviceID int64) bool {
	m := reClam.FindStringSubmatch(line)
	if len(m) != 4 {
		return false
	}
	path, sig, status := m[1], m[2], m[3]
	key, level := "clam_ok", "low"
	msg := "ClamAV OK: " + path
	if status == "FOUND" {
		key, level = "clam_found", "high"
		msg = "ClamAV FOUND " + sig + " in " + path
	}
	id := fmt.Sprintf("clamav:%d", time.Now().UnixNano())
	eventTime := time.Now().UTC().Format("2006-01-02 15:04:05")
	raw := line
	if _, err := db.InsertAuditLog(deviceID, eventTime, "clamav", key, msg, raw, level, id); err != nil {
		fmt.Fprintln(os.Stderr, "insert error:", err)
	}
	return true
}

func main() {
	host := os.Getenv("HOSTNAME")
	if host == "" {
		host = "unknown"
	}

	// Flags
	deviceFlag := flag.Int64("device", 0, "Device ID to attribute logs to (required)")
	configFlag := flag.String("config", "", "Path to audit priorities config file")
	flag.Parse()

	if *deviceFlag <= 0 {
		fmt.Fprintln(os.Stderr, "error: -device <id> is required")
		os.Exit(2)
	}

	// Initialize encrypted database using shared app settings
	if err := db.InitDB(); err != nil {
		fmt.Fprintln(os.Stderr, "db init error:", err)
		os.Exit(1)
	}
	defer db.Close()

	// Load priority configuration
	configPath := *configFlag
	if configPath == "" {
		// Default to config/audit_priorities.conf relative to project root
		if repoRoot := os.Getenv("REPO_ROOT"); repoRoot != "" {
			configPath = filepath.Join(repoRoot, "config", "audit_priorities.conf")
		} else {
			configPath = "/opt/agentless/config/audit_priorities.conf"
		}
	}

	if err := loadPriorities(configPath); err != nil {
		fmt.Fprintf(os.Stderr, "error: failed to load priorities from %s: %v\n", configPath, err)
		fmt.Fprintln(os.Stderr, "Priority configuration file is required. Please ensure config/audit_priorities.conf exists.")
		os.Exit(1)
	}

	// Initialize encrypted database using shared app settings
	if err := db.InitDB(); err != nil {
		fmt.Fprintln(os.Stderr, "db init error:", err)
		os.Exit(1)
	}
	defer db.Close()

	sc := bufio.NewScanner(os.Stdin)
	// allow long lines
	const maxCap = 1024 * 1024
	buf := make([]byte, 0, 64*1024)
	sc.Buffer(buf, maxCap)

	var curID string
	var raw []string

	for sc.Scan() {
		line := sc.Text()
		if !strings.Contains(line, "msg=audit(") {
			_ = ingestClam(line, host, *deviceFlag)
			continue
		}
		m := reMsgID.FindStringSubmatch(line)
		if len(m) != 2 {
			continue
		}
		id := m[1]
		if curID == "" {
			curID = id
		}
		if id != curID {
			flush(curID, raw, host, *deviceFlag)
			curID = id
			raw = raw[:0]
		}
		raw = append(raw, line)
	}
	flush(curID, raw, host, *deviceFlag)

	if err := sc.Err(); err != nil {
		fmt.Fprintln(os.Stderr, "scan error:", err)
		os.Exit(1)
	}
}
