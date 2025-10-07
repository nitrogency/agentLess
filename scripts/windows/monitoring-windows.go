package main

import (
	"encoding/xml"
	"flag"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"

	"example/go-website/db"
)

type SysmonEvent struct {
	XMLName xml.Name `xml:"Event"`
	System  struct {
		EventID       int    `xml:"EventID"`
		EventRecordID int64  `xml:"EventRecordID"`
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
	high  = []string{"powershell -enc", "invoke-expression", "downloadstring", "invoke-webrequest", "net user", "net localgroup", "mimikatz", "procdump", "psexec", "wmic process call create", "schtasks /create", "at.exe", "reg add", "vssadmin delete shadows", "bcdedit", "certutil -decode", "bitsadmin /transfer", "mshta http", "rundll32", "regsvr32 /s /u /i:http", "base64"}
	med   = []string{"whoami", "net view", "net share", "ipconfig", "tasklist", "systeminfo", "netstat", "nslookup", "ping", "tracert", "nbtstat", "arp", "route print", "powershell.exe", "cmd.exe /c", "wscript", "cscript", "regsvr32"}
	sPort = map[int]struct{}{4444: {}, 5555: {}, 6666: {}, 7777: {}, 8888: {}, 31337: {}, 1337: {}}
)

func dm(e *SysmonEvent) map[string]string {
	m := make(map[string]string, len(e.EventData.Data))
	for _, d := range e.EventData.Data {
		m[d.Name] = d.Value
	}
	return m
}
func g(m map[string]string, k string) string { return m[k] }

func level(e *SysmonEvent, m map[string]string) string {
	id := e.System.EventID
	img := strings.ToLower(g(m, "Image"))
	cmd := strings.ToLower(g(m, "CommandLine"))
	tgt := strings.ToLower(g(m, "TargetFilename"))
	for _, p := range high {
		if strings.Contains(cmd, p) || strings.Contains(img, p) {
			return "high"
		}
	}
	for _, p := range med {
		if strings.Contains(cmd, p) || strings.Contains(img, p) {
			return "medium"
		}
	}
	switch id {
	case 1:
		p := strings.ToLower(g(m, "ParentImage"))
		if strings.Contains(p, "excel") || strings.Contains(p, "word") || strings.Contains(p, "outlook") || strings.Contains(p, "acrobat") {
			return "high"
		}
		return "medium"
	case 3:
		if port, err := strconv.Atoi(g(m, "DestinationPort")); err == nil {
			if _, ok := sPort[port]; ok {
				return "high"
			}
		}
		return "low"
	case 5:
		return "low"
	case 7:
		if strings.Contains(img, "inject") || strings.Contains(img, "reflective") {
			return "high"
		}
		return "low"
	case 8:
		return "high"
	case 10:
		t := strings.ToLower(g(m, "TargetImage"))
		if strings.Contains(t, "lsass.exe") || strings.Contains(t, "csrss.exe") {
			return "high"
		}
		return "medium"
	case 11:
		if strings.Contains(tgt, "\\appdata\\roaming") || strings.Contains(tgt, "\\temp\\") || strings.Contains(tgt, "\\startup\\") {
			return "medium"
		}
		return "low"
	case 12, 13, 14:
		o := strings.ToLower(g(m, "TargetObject"))
		if strings.Contains(o, "\\run") || strings.Contains(o, "\\currentversion\\windows\\run") || strings.Contains(o, "\\winlogon") {
			return "high"
		}
		return "medium"
	case 15:
		return "medium"
	case 17, 18:
		return "medium"
	case 19, 20, 21:
		return "high"
	case 22:
		q := strings.ToLower(g(m, "QueryName"))
		for _, d := range []string{"pastebin", "raw.githubusercontent", "ngrok", "duckdns"} {
			if strings.Contains(q, d) {
				return "high"
			}
		}
		return "low"
	case 23:
		return "medium"
	case 25:
		return "high"
	case 26:
		return "medium"
	}
	return "low"
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
					ts, ev, key, audit, msg(&e, m), level(&e, m))
			}
			
			if rowID, err := db.InsertAuditLog(*device, ts, ev, key, msg(&e, m), rawLog, level(&e, m), audit); err != nil {
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
