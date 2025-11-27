package main

import (
	"bufio"
	"encoding/xml"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"agentless/db"
)

type SysmonEvent struct {
	XMLName xml.Name `xml:"Event"`
	System  struct {
		EventID       int   `xml:"EventID"`
		EventRecordID int64 `xml:"EventRecordID"`
		TimeCreated   struct {
			SystemTime string `xml:"SystemTime,attr"`
		} `xml:"TimeCreated"`
		Computer string `xml:"Computer"`
		Provider struct {
			Name string `xml:"Name,attr"`
		} `xml:"Provider"`
	} `xml:"System"`
	EventData struct {
		Data []struct {
			Name  string `xml:"Name,attr"`
			Value string `xml:",chardata"`
		} `xml:"Data"`
	} `xml:"EventData"`
}

var (
	names = map[int]string{1: "ProcessCreate", 2: "FileCreationTimeChanged", 3: "NetworkConnect", 4: "SysmonServiceStateChanged", 5: "ProcessTerminate", 6: "DriverLoad", 7: "ImageLoad", 8: "CreateRemoteThread", 9: "RawAccessRead", 10: "ProcessAccess", 11: "FileCreate", 12: "RegistryEventObjectCreateDelete", 13: "RegistryEventValueSet", 14: "RegistryEventKeyRename", 15: "FileCreateStreamHash", 16: "SysmonConfigStateChanged", 17: "PipeEventCreated", 18: "PipeEventConnected", 19: "WmiEventFilter", 20: "WmiEventConsumer", 21: "WmiEventConsumerToFilter", 22: "DnsQuery", 23: "FileDelete", 24: "ClipboardChange", 25: "ProcessTampering", 26: "FileDeleteDetected"}

	// Priority maps loaded from config file
	highEventIDs   = make(map[int]struct{})
	mediumEventIDs = make(map[int]struct{})
	lowEventIDs    = make(map[int]struct{})
)

func dm(e *SysmonEvent) map[string]string {
	m := make(map[string]string, len(e.EventData.Data))
	for _, d := range e.EventData.Data {
		m[d.Name] = d.Value
	}
	return m
}
func g(m map[string]string, k string) string { return m[k] }

// classify determines the security level based purely on Sysmon Event ID
// The priority is determined by the sysmon_priorities.conf configuration file
func classify(eventID int) string {
	if _, ok := highEventIDs[eventID]; ok {
		return "high"
	}
	if _, ok := mediumEventIDs[eventID]; ok {
		return "medium"
	}
	if _, ok := lowEventIDs[eventID]; ok {
		return "low"
	}
	// Default to low for unknown event types
	return "low"
}

// loadPriorities loads event priorities from configuration file
func loadPriorities(path string) error {
	// Clear any existing priorities
	highEventIDs = make(map[int]struct{})
	mediumEventIDs = make(map[int]struct{})
	lowEventIDs = make(map[int]struct{})

	f, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("failed to open config file: %w", err)
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
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

		// Parse event ID (ignore comments after the ID)
		parts := strings.Fields(line)
		if len(parts) == 0 {
			continue
		}

		eventID, err := strconv.Atoi(parts[0])
		if err != nil {
			continue // Skip invalid event IDs
		}

		// Add to appropriate map
		switch currentSection {
		case "high":
			highEventIDs[eventID] = struct{}{}
		case "medium":
			mediumEventIDs[eventID] = struct{}{}
		case "low":
			lowEventIDs[eventID] = struct{}{}
		}
	}

	return scanner.Err()
}

func msg(e *SysmonEvent, m map[string]string) string {
	switch e.System.EventID {
	case 1:
		if c := g(m, "CommandLine"); c != "" {
			return fmt.Sprintf("Process created: %s (User: %s, Command: %s)", g(m, "Image"), g(m, "User"), c)
		}
		return fmt.Sprintf("Process created: %s (User: %s)", g(m, "Image"), g(m, "User"))
	case 3:
		return fmt.Sprintf("Network connection: %s -> %s:%s", g(m, "Image"), g(m, "DestinationIp"), g(m, "DestinationPort"))
	case 5:
		return fmt.Sprintf("Process terminated: %s", g(m, "Image"))
	case 7:
		return fmt.Sprintf("DLL loaded: %s loaded %s", g(m, "Image"), g(m, "ImageLoaded"))
	case 8:
		return fmt.Sprintf("Remote thread: %s -> %s", g(m, "SourceImage"), g(m, "TargetImage"))
	case 10:
		return fmt.Sprintf("Process access: %s -> %s", g(m, "SourceImage"), g(m, "TargetImage"))
	case 11:
		return fmt.Sprintf("File created: %s created %s", g(m, "Image"), g(m, "TargetFilename"))
	case 12, 13, 14:
		return fmt.Sprintf("Registry %s: %s modified %s", getName(e.System.EventID), g(m, "Image"), g(m, "TargetObject"))
	case 15:
		return fmt.Sprintf("Alternate data stream: %s created stream on %s", g(m, "Image"), g(m, "TargetFilename"))
	case 22:
		return fmt.Sprintf("DNS query: %s queried %s", g(m, "Image"), g(m, "QueryName"))
	case 23:
		return fmt.Sprintf("File deleted: %s deleted %s", g(m, "Image"), g(m, "TargetFilename"))
	default:
		return fmt.Sprintf("Sysmon Event %d", e.System.EventID)
	}
}

func getName(id int) string {
	if s, ok := names[id]; ok {
		return s
	}
	return fmt.Sprintf("Unknown-%d", id)
}

func main() {
	device := flag.Int64("device", 0, "Device ID (required)")
	debug := flag.Bool("debug", false, "Enable debug output")
	configPath := flag.String("config", "", "Path to sysmon_priorities.conf")
	flag.Parse()
	if *device <= 0 {
		fmt.Fprintln(os.Stderr, "error: -device <id> is required")
		os.Exit(2)
	}
	if err := db.InitDB(); err != nil {
		fmt.Fprintln(os.Stderr, "db init error:", err)
		os.Exit(1)
	}
	defer db.Close()

	// Load priority configuration
	if *configPath == "" {
		// Default to config/sysmon_priorities.conf relative to project root
		if repoRoot := os.Getenv("REPO_ROOT"); repoRoot != "" {
			*configPath = filepath.Join(repoRoot, "config", "sysmon_priorities.conf")
		} else {
			*configPath = "/opt/agentless/config/sysmon_priorities.conf"
		}
	}

	// Load priorities from config file (required)
	if err := loadPriorities(*configPath); err != nil {
		fmt.Fprintf(os.Stderr, "error: failed to load priorities from %s: %v\n", *configPath, err)
		fmt.Fprintln(os.Stderr, "Priority configuration file is required. Please ensure config/sysmon_priorities.conf exists.")
		os.Exit(1)
	}
	if *debug {
		fmt.Fprintf(os.Stderr, "Loaded priorities from: %s\n", *configPath)
	}

	// PowerShell .ToXml() over SSH outputs UTF-8, not UTF-16
	// Just use stdin directly
	if *debug {
		fmt.Fprintln(os.Stderr, "Reading XML from stdin (expecting UTF-8)")
	}

	dec := xml.NewDecoder(os.Stdin)
	eventCount := 0
	insertCount := 0

	for {
		tok, err := dec.Token()
		if err == io.EOF {
			if *debug {
				fmt.Fprintf(os.Stderr, "EOF reached. Processed %d events, inserted %d\n", eventCount, insertCount)
			}
			break
		}
		if err != nil {
			fmt.Fprintf(os.Stderr, "xml token error: %v\n", err)
			if *debug {
				fmt.Fprintf(os.Stderr, "Hint: Input may have encoding issues. Check PowerShell output encoding.\n")
			}
			break
		}
		if se, ok := tok.(xml.StartElement); ok && se.Name.Local == "Event" {
			eventCount++
			var e SysmonEvent
			if err := dec.DecodeElement(&e, &se); err != nil {
				if *debug {
					fmt.Fprintf(os.Stderr, "decode error on event %d: %v\n", eventCount, err)
				}
				continue
			}

			if *debug {
				fmt.Fprintf(os.Stderr, "Event %d: ID=%d, RecordID=%d, Provider=%s, Computer=%s\n",
					eventCount, e.System.EventID, e.System.EventRecordID, e.System.Provider.Name, e.System.Computer)
			}

			if e.System.Provider.Name != "Microsoft-Windows-Sysmon" || e.System.EventRecordID == 0 {
				if *debug {
					fmt.Fprintf(os.Stderr, "Skipping event %d (provider or recordID check failed)\n", eventCount)
				}
				continue
			}
			m := dm(&e)
			ts := e.System.TimeCreated.SystemTime
			ev := fmt.Sprintf("Sysmon-%d", e.System.EventID)
			key := getName(e.System.EventID)
			audit := fmt.Sprintf("sysmon-%s-%d", e.System.Computer, e.System.EventRecordID)

			// Marshal event back to XML for raw log storage
			rawXML, err := xml.MarshalIndent(&e, "", "  ")
			if err != nil {
				rawXML = []byte(fmt.Sprintf("Error marshaling XML: %v", err))
			}
			rawLog := string(rawXML)

			if *debug {
				fmt.Fprintf(os.Stderr, "Inserting: ts=%s, event=%s, key=%s, audit=%s, msg=%s, level=%s\n",
					ts, ev, key, audit, msg(&e, m), classify(e.System.EventID))
			}

			if rowID, err := db.InsertAuditLog(*device, ts, ev, key, msg(&e, m), rawLog, classify(e.System.EventID), audit); err != nil {
				fmt.Fprintln(os.Stderr, "insert error:", err)
			} else if rowID == 0 {
				if *debug {
					fmt.Fprintf(os.Stderr, "Duplicate event skipped: %s\n", audit)
				}
			} else {
				insertCount++
				if *debug {
					fmt.Fprintf(os.Stderr, "Successfully inserted event %d (rowID=%d)\n", insertCount, rowID)
				}
			}
		}
	}
}
