package main

import (
	"bufio"
	"flag"
	"fmt"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"

	"example/go-website/db"
)

var (
	reMsgID   = regexp.MustCompile(`msg=audit\(([^)]+)\)`)
	reKey     = regexp.MustCompile(`key="?([A-Za-z0-9_-]+)"?`)
	reComm    = regexp.MustCompile(`comm="([^"]+)"`)
	reExe     = regexp.MustCompile(`exe="([^"]+)"`)
	reAuid    = regexp.MustCompile(`\bauid=([0-9]+)\b`)
	reSuccess = regexp.MustCompile(`\bsuccess=(yes|no)\b`)
	reArg     = regexp.MustCompile(`a[0-9]+="([^"]*)"`)
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
	highKeys = map[string]struct{}{
		"suspicious":     {},
		"reconnaissance": {},
	}
	mediumKeys = map[string]struct{}{
		"privilege_esc":      {},
		"user_pass":          {},
		"sudoers_change":     {},
		"authentication":     {},
		"failed_login":       {},
		"user_del":           {},
		"mac_policy":         {},
		"audit_tools":        {},
		"audit_logs":         {},
		"user_add":           {},
		"user_modification":  {},
		"group_add":          {},
		"group_modification": {},
		"user_list":          {},
		"user_group":         {},
		"group_accounts":     {},
		"passwd_change":      {},
		"passwd_history":     {},
		"kernel_module":      {},
		"kernel_param":       {},
		"systemd_monitoring": {},
		"startup_scripts":    {},
		"perm_mod":           {},
		"mount_operations":   {},
	}
	lowKeys = map[string]struct{}{
		"root_commands":       {},
		"user_list":           {}, // overlaps allowed
		"user_group":          {},
		"group_accounts":      {},
		"time_change":         {},
		"net_environment_exe": {},
		"cron_events":         {},
		"software_mgmt":       {},
		"user_delete_files":   {},
		"command_execution":   {},
	}
)

func classify(ev *Event) string {
	key := ev.Key
	comm := strings.ToLower(ev.Comm)
	exe := ev.Exe
	success := strings.ToLower(ev.Success)

	// ---- Safelist: your monitoring actions reading audit logs (near real-time/SSH backfill)
	argvJoined := strings.ToLower(strings.Join(ev.Argv, " "))
	if (comm == "tail" || comm == "cat" || comm == "ausearch" || comm == "ssh" || comm == "sudo") &&
		(strings.Contains(argvJoined, "/var/log/audit") || strings.Contains(argvJoined, "audit.log")) {
		return "low"
	}

	// ---- Key-based classification (fast paths)
	if inSet(key, highKeys) {
		// soften if clearly a system mgmt binary path
		if strings.HasPrefix(exe, "/usr/lib/") || strings.HasPrefix(exe, "/usr/sbin/") {
			return "medium"
		}
		return "high"
	}
	if inSet(key, mediumKeys) {
		return "medium"
	}
	if inSet(key, lowKeys) {
		return "low"
	}

	// ---- Additional heuristics similar to your shell script fallbacks

	// High auth failures
	if strings.Contains(argvJoined, "failed password") ||
		strings.Contains(argvJoined, "authentication failure") ||
		strings.Contains(argvJoined, "invalid user") {
		return "high"
	}

	// Syscall-like hints from raw (when key missing)
	// We don't parse syscall names here, but argv may carry commands indicative of risk.
	if strings.Contains(argvJoined, "execve") || strings.Contains(argvJoined, "unlink") ||
		strings.Contains(argvJoined, "rmdir") || strings.Contains(argvJoined, "delete") {
		return "medium"
	}

	// Generic high patterns
	if strings.Contains(argvJoined, "unauthorized") ||
		strings.Contains(argvJoined, "privilege escalation") ||
		strings.Contains(argvJoined, "user not in sudoers") {
		return "high"
	}

	// Generic medium patterns
	if strings.Contains(argvJoined, "kernel module") ||
		strings.Contains(argvJoined, "chmod +x") ||
		strings.Contains(argvJoined, "new user") ||
		strings.Contains(argvJoined, "password change") ||
		strings.Contains(argvJoined, "sudo command") ||
		strings.Contains(argvJoined, "insmod") ||
		strings.Contains(argvJoined, "modprobe") {
		return "medium"
	}

	// If sudo failed
	if success == "no" && comm == "sudo" {
		return "high"
	}

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

	// Use comm as the type for display/filtering consistency
	logType := ev.Comm

	// Insert directly into DB; ignore duplicate via unique index (device_id, audit_id)
	if _, err := db.InsertAuditLog(deviceID, eventTime, logType, ev.Key, message, buf, ev.Level, ev.ID); err != nil {
		fmt.Fprintln(os.Stderr, "insert error:", err)
	}
}

func main() {
	host := os.Getenv("HOSTNAME")
	if host == "" {
		host = "unknown"
	}

	// Flags
	deviceFlag := flag.Int64("device", 0, "Device ID to attribute logs to (required)")
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
