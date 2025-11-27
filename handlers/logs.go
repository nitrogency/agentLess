package handlers

import (
	"encoding/csv"
	"fmt"
	"log"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"

	"agentless/db"
	"agentless/templates"
)

// AllLogsHandler handles system audit logs viewing
func AllLogsHandler(c *gin.Context) {
	data := templates.GetPageDataFromGin(c)
	data.Title = "System Audit Logs"

	// Get query parameters
	pageStr := c.DefaultQuery("page", "1")
	pageSizeStr := c.DefaultQuery("pageSize", "50")
	deviceIDStr := c.Query("device_id")
	searchTerm := c.Query("search")
	securityLevel := c.Query("security_level")
	exportFormat := c.Query("export")

	// Parse page number
	page, err := strconv.Atoi(pageStr)
	if err != nil || page < 1 {
		page = 1
	}

	// Parse device ID if provided
	var deviceID int64 = 0
	if deviceIDStr != "" {
		deviceID, err = strconv.ParseInt(deviceIDStr, 10, 64)
		if err != nil {
			log.Printf("Invalid device ID: %v", err)
			deviceID = 0
		}
	}

	// Parse page size with sane defaults
	pageSize, err := strconv.Atoi(pageSizeStr)
	if err != nil {
		pageSize = 50
	}
	switch pageSize {
	case 10, 20, 50:
		// allowed
	default:
		pageSize = 50
	}

	// Handle export requests
	if exportFormat == "csv" {
		exportLogsAsCSV(c, deviceID, searchTerm, securityLevel)
		return
	}

	// Get audit logs from database
	logs, totalCount, err := db.GetAuditLogs(deviceID, page, pageSize, searchTerm, securityLevel)
	if err != nil {
		log.Printf("Error getting audit logs: %v", err)
		data.Error = "Failed to load audit logs"
		logs = []db.AuditLog{}
		totalCount = 0
	}

	// Calculate pagination info
	totalPages := (totalCount + pageSize - 1) / pageSize
	if totalPages == 0 {
		totalPages = 1
	}

	// Build pagination slice for template (0 represents an ellipsis)
	pagination := []int{}
	if totalPages <= 9 {
		for i := 1; i <= totalPages; i++ {
			pagination = append(pagination, i)
		}
	} else {
		// Always show first page
		pagination = append(pagination, 1)
		// Ellipsis before window
		if page > 3 {
			pagination = append(pagination, 0)
		}
		// Window around current page
		start := page - 2
		if start < 2 {
			start = 2
		}
		end := page + 2
		if end > totalPages-1 {
			end = totalPages - 1
		}
		for i := start; i <= end; i++ {
			pagination = append(pagination, i)
		}
		// Ellipsis after window
		if page < totalPages-2 {
			pagination = append(pagination, 0)
		}
		// Always show last page
		pagination = append(pagination, totalPages)
	}

	// Get all devices for filter dropdown
	devices, err := db.GetAllDevices()
	if err != nil {
		log.Printf("Error getting devices for filter: %v", err)
		devices = []db.Device{}
	}

	// Calculate statistics
	stats := calculateLogStatistics(logs)

	// Populate Data map (templates use both Logs and AuditLogs)
	data.Data["Logs"] = logs
	data.Data["AuditLogs"] = logs
	data.Data["CurrentPage"] = page
	data.Data["TotalPages"] = totalPages
	data.Data["PageSize"] = pageSize
	data.Data["TotalLogs"] = totalCount
	data.Data["SearchTerm"] = searchTerm
	data.Data["SecurityLevel"] = securityLevel
	data.Data["DeviceID"] = deviceID
	// Keys used by template filters
	data.Data["FilterDeviceID"] = deviceID
	data.Data["FilterSecurityLevel"] = securityLevel
	data.Data["Devices"] = devices
	data.Data["Stats"] = stats
	data.Data["Pagination"] = pagination

	templates.RenderGinTemplate(c, "logs", data)
}

// exportLogsAsCSV exports audit logs as CSV
func exportLogsAsCSV(c *gin.Context, deviceID int64, searchTerm, securityLevel string) {
	// Get all logs matching criteria (no pagination for export)
	logs, _, err := db.GetAuditLogs(deviceID, 1, 10000, searchTerm, securityLevel)
	if err != nil {
		log.Printf("Error getting logs for export: %v", err)
		c.String(http.StatusInternalServerError, "Error exporting logs")
		return
	}

	// Set headers for CSV download
	filename := fmt.Sprintf("audit_logs_%s.csv", time.Now().Format("2006-01-02_15-04-05"))
	c.Header("Content-Type", "text/csv")
	c.Header("Content-Disposition", fmt.Sprintf("attachment; filename=%s", filename))

	// Create CSV writer
	writer := csv.NewWriter(c.Writer)
	defer writer.Flush()

	// Write CSV header
	header := []string{"ID", "Device", "Timestamp", "Event Time", "Type", "Key", "Message", "Security Level", "Audit ID"}
	if err := writer.Write(header); err != nil {
		log.Printf("Error writing CSV header: %v", err)
		return
	}

	// Write log entries
	for _, logEntry := range logs {
		deviceName := db.GetDeviceNameByID(logEntry.DeviceID)
		row := []string{
			strconv.FormatInt(logEntry.ID, 10),
			deviceName,
			logEntry.Timestamp.Format("2006-01-02 15:04:05"),
			logEntry.EventTime,
			logEntry.Type,
			logEntry.Key,
			logEntry.Message,
			string(logEntry.SecurityLevel),
			logEntry.AuditID,
		}
		if err := writer.Write(row); err != nil {
			log.Printf("Error writing CSV row: %v", err)
			return
		}
	}
}

// calculateLogStatistics calculates statistics for the current log set
func calculateLogStatistics(logs []db.AuditLog) map[string]interface{} {
	stats := make(map[string]interface{})

	// Count by security level
	securityCounts := map[string]int{
		"high":   0,
		"medium": 0,
		"low":    0,
	}

	// Count by device
	deviceCounts := make(map[int64]int)

	// Count by type
	typeCounts := make(map[string]int)

	for _, logEntry := range logs {
		// Security level counts
		securityCounts[string(logEntry.SecurityLevel)]++

		// Device counts
		deviceCounts[logEntry.DeviceID]++

		// Type counts
		typeCounts[logEntry.Type]++
	}

	stats["SecurityCounts"] = securityCounts
	stats["DeviceCounts"] = deviceCounts
	stats["TypeCounts"] = typeCounts
	stats["TotalCount"] = len(logs)

	return stats
}

// DeviceLogsHandler handles audit logs for a specific device
func DeviceLogsHandler(c *gin.Context) {
	data := templates.GetPageDataFromGin(c)
	data.Title = "Device Audit Logs"

	// Get device ID from URL parameter
	deviceIDStr := c.Param("id")
	if deviceIDStr == "" {
		data.Error = "Device ID is required"
		templates.RenderGinTemplate(c, "404", data)
		return
	}

	// Parse device ID
	deviceID, err := strconv.ParseInt(deviceIDStr, 10, 64)
	if err != nil {
		log.Printf("Invalid device ID: %v", err)
		data.Error = "Invalid device ID"
		templates.RenderGinTemplate(c, "404", data)
		return
	}

	// Load device from database
	device, err := db.GetDeviceByID(deviceID)
	if err != nil {
		log.Printf("Error loading device ID %d: %v", deviceID, err)
		data.Error = "Device not found"
		templates.RenderGinTemplate(c, "404", data)
		return
	}

	if device == nil {
		data.Error = "Device not found"
		templates.RenderGinTemplate(c, "404", data)
		return
	}

	// Get query parameters
	pageStr := c.DefaultQuery("page", "1")
	searchTerm := c.Query("search")

	// Parse page number
	page, err := strconv.Atoi(pageStr)
	if err != nil || page < 1 {
		page = 1
	}

	pageSize := 50

	// Get audit logs for this device
	logs, totalCount, err := db.GetAuditLogsByDeviceID(deviceID, page, pageSize, searchTerm)
	if err != nil {
		log.Printf("Error getting audit logs for device %d: %v", deviceID, err)
		data.Error = "Failed to load device logs"
		logs = []db.AuditLog{}
		totalCount = 0
	}

	// Calculate pagination info
	totalPages := (totalCount + pageSize - 1) / pageSize
	if totalPages == 0 {
		totalPages = 1
	}

	// Calculate statistics
	stats := calculateLogStatistics(logs)

	// Populate template data
	data.Data["Device"] = device
	data.Data["Logs"] = logs
	data.Data["CurrentPage"] = page
	data.Data["TotalPages"] = totalPages
	data.Data["PageSize"] = pageSize
	data.Data["TotalLogs"] = totalCount
	data.Data["SearchTerm"] = searchTerm
	data.Data["Stats"] = stats

	templates.RenderGinTemplate(c, "device-logs", data)
}

// LogRetentionHandler handles log retention/cleanup
func LogRetentionHandler(c *gin.Context) {
	data := templates.GetPageDataFromGin(c)
	data.Title = "Log Retention Management"

	// Check if user is admin
	if !data.IsAdmin {
		data.Error = "Access denied. Admin privileges required."
		templates.RenderGinTemplate(c, "404", data)
		return
	}

	if c.Request.Method == "POST" {
		retentionDaysStr := strings.TrimSpace(c.PostForm("retention_days"))
		confirm := c.PostForm("confirm")

		if confirm != "yes" {
			data.Error = "Please confirm the log retention action"
			templates.RenderGinTemplate(c, "log-retention", data)
			return
		}

		retentionDays, err := strconv.Atoi(retentionDaysStr)
		if err != nil || retentionDays < 1 {
			data.Error = "Invalid retention days. Must be a positive number."
			templates.RenderGinTemplate(c, "log-retention", data)
			return
		}

		// Delete old logs
		deletedCount, err := db.DeleteOldAuditLogs(retentionDays)
		if err != nil {
			log.Printf("Error deleting old logs: %v", err)
			data.Error = "Failed to delete old logs"
			templates.RenderGinTemplate(c, "log-retention", data)
			return
		}

		data.Data["Success"] = fmt.Sprintf("Successfully deleted %d old log entries", deletedCount)
	}

	templates.RenderGinTemplate(c, "log-retention", data)
}
