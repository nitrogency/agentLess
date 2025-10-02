package main

import (
	"bufio"
	"encoding/xml"
	"flag"
	"fmt"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"

	"example/go-website/db"
)

// SysmonEvent represents a Windows Sysmon event in XML format
type SysmonEvent struct {
	XMLName xml.Name `xml:"Event"`
	System  struct {
		EventID     int    `xml:"EventID"`
		TimeCreated string `xml:"TimeCreated>SystemTime,attr"`
		Computer    string `xml:"Computer"`
		Channel     string `xml:"Channel"`
		Provider    string `xml:"Provider>Name,attr"`
	} `xml:"System"`
	EventData struct {
		Data []struct {
			Name  string `xml:"Name,attr"`
			Value string `xml:",chardata"`
		} `xml:"Data"`
	} `xml:"EventData"`
}

var (
	reRecordID = regexp.MustCompile(`RecordId>(\d+)</RecordId`)
)

// getSysmonDataField extracts a specific field from Sysmon EventData
func getSysmonDataField(event *SysmonEvent, fieldName string) string {
	for _, data := range event.EventData.Data {
		if data.Name == fieldName {
			return data.Value
		}
	}
	return ""
}

// classifySysmonEvent determines security level for Sysmon events
func classifySysmonEvent(event *SysmonEvent) string {
	eventID := event.System.EventID

	// Extract key fields
	image := strings.ToLower(getSysmonDataField(event, "Image"))
	commandLine := strings.ToLower(getSysmonDataField(event, "CommandLine"))
	targetFilename := strings.ToLower(getSysmonDataField(event, "TargetFilename"))

	// High-risk patterns
	highRiskPatterns := []string{
		"powershell -enc",          // Encoded PowerShell commands
		"invoke-expression",        // IEX execution
		"downloadstring",           // Web downloads
		"invoke-webrequest",        // Web requests
		"net user",                 // User management
		"net localgroup",           // Group management
		"mimikatz",                 // Credential dumping
		"procdump",                 // Process dumping
		"psexec",                   // Remote execution
		"wmic process call create", // Remote execution via WMIC
		"schtasks /create",         // Task scheduling
		"at.exe",                   // Legacy task scheduling
		"reg add",                  // Registry modification
		"vssadmin delete shadows",  // Shadow copy deletion (ransomware)
		"bcdedit",                  // Boot configuration (ransomware)
		"certutil -decode",         // File decoding
		"bitsadmin /transfer",      // Background file transfer
		"mshta http",               // HTML application execution
		"rundll32",                 // DLL execution
		"regsvr32 /s /u /i:http",   // Squiblydoo technique
		"base64",                   // Base64 encoding/decoding
	}

	for _, pattern := range highRiskPatterns {
		if strings.Contains(commandLine, pattern) || strings.Contains(image, pattern) {
			return "high"
		}
	}

	// Medium-risk patterns
	mediumRiskPatterns := []string{
		"whoami",
		"net view",
		"net share",
		"ipconfig",
		"tasklist",
		"systeminfo",
		"netstat",
		"nslookup",
		"ping",
		"tracert",
		"nbtstat",
		"arp",
		"route print",
		"powershell.exe",
		"cmd.exe /c",
		"wscript",
		"cscript",
		"regsvr32",
	}

	for _, pattern := range mediumRiskPatterns {
		if strings.Contains(commandLine, pattern) || strings.Contains(image, pattern) {
			return "medium"
		}
	}

	// Event ID based classification
	switch eventID {
	case 1: // Process creation
		// Check for suspicious parent processes
		parentImage := strings.ToLower(getSysmonDataField(event, "ParentImage"))
		if strings.Contains(parentImage, "excel") || strings.Contains(parentImage, "word") ||
			strings.Contains(parentImage, "outlook") || strings.Contains(parentImage, "acrobat") {
			// Office apps spawning processes is suspicious
			return "high"
		}
		return "medium"

	case 3: // Network connection
		destinationPort := getSysmonDataField(event, "DestinationPort")
		// Check for unusual ports
		if port, err := strconv.Atoi(destinationPort); err == nil {
			// Common suspicious ports
			suspiciousPorts := []int{4444, 5555, 6666, 7777, 8888, 31337, 1337}
			for _, sp := range suspiciousPorts {
				if port == sp {
					return "high"
				}
			}
		}
		return "low"

	case 5: // Process terminated
		return "low"

	case 7: // Image/DLL loaded
		// Check for suspicious DLLs
		if strings.Contains(image, "inject") || strings.Contains(image, "reflective") {
			return "high"
		}
		return "low"

	case 8: // CreateRemoteThread (injection)
		return "high"

	case 10: // ProcessAccess (credential dumping)
		targetImage := strings.ToLower(getSysmonDataField(event, "TargetImage"))
		if strings.Contains(targetImage, "lsass.exe") || strings.Contains(targetImage, "csrss.exe") {
			return "high"
		}
		return "medium"

	case 11: // FileCreate
		// Check for suspicious file locations
		if strings.Contains(targetFilename, "\\appdata\\roaming") ||
			strings.Contains(targetFilename, "\\temp\\") ||
			strings.Contains(targetFilename, "\\startup\\") {
			return "medium"
		}
		return "low"

	case 12, 13, 14: // Registry events
		targetObject := strings.ToLower(getSysmonDataField(event, "TargetObject"))
		// Check for persistence registry keys
		if strings.Contains(targetObject, "\\run") ||
			strings.Contains(targetObject, "\\currentversion\\windows\\run") ||
			strings.Contains(targetObject, "\\winlogon") {
			return "high"
		}
		return "medium"

	case 15: // FileCreateStreamHash (Alternate Data Stream)
		return "medium"

	case 17, 18: // Pipe events
		return "medium"

	case 19, 20, 21: // WMI events
		return "high"

	case 22: // DNS query
		queryName := strings.ToLower(getSysmonDataField(event, "QueryName"))
		// Check for suspicious domains
		suspiciousDomains := []string{"pastebin", "raw.githubusercontent", "ngrok", "duckdns"}
		for _, domain := range suspiciousDomains {
			if strings.Contains(queryName, domain) {
				return "high"
			}
		}
		return "low"

	case 23: // FileDelete
		return "medium"

	case 25: // ProcessTampering
		return "high"

	case 26: // FileDeleteDetected
		return "medium"
	}

	return "low"
}

func parseSysmonEvent(xmlData string, deviceID int64) {
	var event SysmonEvent

	if err := xml.Unmarshal([]byte(xmlData), &event); err != nil {
		// Skip malformed XML
		return
	}

	// Skip if not a Sysmon event
	if event.System.Provider != "Microsoft-Windows-Sysmon" {
		return
	}

	// Extract record ID for deduplication
	recordID := ""
	if matches := reRecordID.FindStringSubmatch(xmlData); len(matches) > 1 {
		recordID = matches[1]
	}

	// Skip if no record ID (shouldn't happen)
	if recordID == "" {
		return
	}

	// Parse timestamp
	eventTime := ""
	if t, err := time.Parse(time.RFC3339Nano, event.System.TimeCreated); err == nil {
		eventTime = t.Format("2006-01-02 15:04:05")
	}

	// Build human-readable message
	message := buildSysmonMessage(&event)

	// Determine security level
	level := classifySysmonEvent(&event)

	// Event type (Sysmon Event ID + description)
	eventType := fmt.Sprintf("Sysmon-%d", event.System.EventID)

	// Key for filtering (event name)
	key := getSysmonEventName(event.System.EventID)

	// Insert into database with record ID as audit_id
	auditID := fmt.Sprintf("sysmon-%s-%s", event.System.Computer, recordID)
	if _, err := db.InsertAuditLog(deviceID, eventTime, eventType, key, message, xmlData, level, auditID); err != nil {
		fmt.Fprintf(os.Stderr, "insert error: %v\n", err)
	}
}

func buildSysmonMessage(event *SysmonEvent) string {
	switch event.System.EventID {
	case 1: // Process creation
		image := getSysmonDataField(event, "Image")
		commandLine := getSysmonDataField(event, "CommandLine")
		user := getSysmonDataField(event, "User")
		if commandLine != "" {
			return fmt.Sprintf("Process created: %s (User: %s, Command: %s)", image, user, commandLine)
		}
		return fmt.Sprintf("Process created: %s (User: %s)", image, user)

	case 3: // Network connection
		image := getSysmonDataField(event, "Image")
		destIP := getSysmonDataField(event, "DestinationIp")
		destPort := getSysmonDataField(event, "DestinationPort")
		return fmt.Sprintf("Network connection: %s -> %s:%s", image, destIP, destPort)

	case 5: // Process terminated
		image := getSysmonDataField(event, "Image")
		return fmt.Sprintf("Process terminated: %s", image)

	case 7: // Image loaded
		image := getSysmonDataField(event, "Image")
		imageLoaded := getSysmonDataField(event, "ImageLoaded")
		return fmt.Sprintf("DLL loaded: %s loaded %s", image, imageLoaded)

	case 8: // CreateRemoteThread
		sourceImage := getSysmonDataField(event, "SourceImage")
		targetImage := getSysmonDataField(event, "TargetImage")
		return fmt.Sprintf("Remote thread: %s -> %s", sourceImage, targetImage)

	case 10: // ProcessAccess
		sourceImage := getSysmonDataField(event, "SourceImage")
		targetImage := getSysmonDataField(event, "TargetImage")
		return fmt.Sprintf("Process access: %s -> %s", sourceImage, targetImage)

	case 11: // FileCreate
		image := getSysmonDataField(event, "Image")
		targetFilename := getSysmonDataField(event, "TargetFilename")
		return fmt.Sprintf("File created: %s created %s", image, targetFilename)

	case 12, 13, 14: // Registry events
		image := getSysmonDataField(event, "Image")
		targetObject := getSysmonDataField(event, "TargetObject")
		eventName := getSysmonEventName(event.System.EventID)
		return fmt.Sprintf("Registry %s: %s modified %s", eventName, image, targetObject)

	case 15: // FileCreateStreamHash
		image := getSysmonDataField(event, "Image")
		targetFilename := getSysmonDataField(event, "TargetFilename")
		return fmt.Sprintf("Alternate data stream: %s created stream on %s", image, targetFilename)

	case 22: // DNS query
		image := getSysmonDataField(event, "Image")
		queryName := getSysmonDataField(event, "QueryName")
		return fmt.Sprintf("DNS query: %s queried %s", image, queryName)

	case 23: // FileDelete
		image := getSysmonDataField(event, "Image")
		targetFilename := getSysmonDataField(event, "TargetFilename")
		return fmt.Sprintf("File deleted: %s deleted %s", image, targetFilename)

	default:
		return fmt.Sprintf("Sysmon Event %d", event.System.EventID)
	}
}

func getSysmonEventName(eventID int) string {
	names := map[int]string{
		1:  "ProcessCreate",
		2:  "FileCreationTimeChanged",
		3:  "NetworkConnect",
		4:  "SysmonServiceStateChanged",
		5:  "ProcessTerminate",
		6:  "DriverLoad",
		7:  "ImageLoad",
		8:  "CreateRemoteThread",
		9:  "RawAccessRead",
		10: "ProcessAccess",
		11: "FileCreate",
		12: "RegistryEventObjectCreateDelete",
		13: "RegistryEventValueSet",
		14: "RegistryEventKeyRename",
		15: "FileCreateStreamHash",
		16: "SysmonConfigStateChanged",
		17: "PipeEventCreated",
		18: "PipeEventConnected",
		19: "WmiEventFilter",
		20: "WmiEventConsumer",
		21: "WmiEventConsumerToFilter",
		22: "DnsQuery",
		23: "FileDelete",
		24: "ClipboardChange",
		25: "ProcessTampering",
		26: "FileDeleteDetected",
	}

	if name, ok := names[eventID]; ok {
		return name
	}
	return fmt.Sprintf("Unknown-%d", eventID)
}

func main() {
	// Flags
	deviceFlag := flag.Int64("device", 0, "Device ID to attribute logs to (required)")
	flag.Parse()

	if *deviceFlag <= 0 {
		fmt.Fprintln(os.Stderr, "error: -device <id> is required")
		os.Exit(2)
	}

	// Initialize encrypted database
	if err := db.InitDB(); err != nil {
		fmt.Fprintln(os.Stderr, "db init error:", err)
		os.Exit(1)
	}
	defer db.Close()

	scanner := bufio.NewScanner(os.Stdin)
	scanner.Buffer(make([]byte, 64*1024), 1024*1024) // Allow large XML events

	var currentEvent strings.Builder
	inEvent := false

	for scanner.Scan() {
		line := scanner.Text()

		// Detect start of event
		if strings.Contains(line, "<Event xmlns=") {
			inEvent = true
			currentEvent.Reset()
		}

		if inEvent {
			currentEvent.WriteString(line)
			currentEvent.WriteString("\n")
		}

		// Detect end of event
		if strings.Contains(line, "</Event>") && inEvent {
			parseSysmonEvent(currentEvent.String(), *deviceFlag)
			inEvent = false
			currentEvent.Reset()
		}
	}

	if err := scanner.Err(); err != nil {
		fmt.Fprintln(os.Stderr, "scan error:", err)
		os.Exit(1)
	}
}
