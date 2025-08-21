package handlers

import (
	"log"
	"strconv"

	"github.com/gin-gonic/gin"

	"example/go-website/db"
	"example/go-website/templates"
)

// AllLogsHandler handles system audit logs viewing
func AllLogsHandler(c *gin.Context) {
	data := templates.GetPageDataFromGin(c)
	data.Title = "System Audit Logs"

	// Get query parameters
	pageStr := c.DefaultQuery("page", "1")
	pageSize := 50
	searchTerm := c.Query("search")
	securityLevel := c.Query("security_level")
	deviceIDStr := c.Query("device_id")

	// Parse page number
	page, err := strconv.Atoi(pageStr)
	if err != nil || page < 1 {
		page = 1
	}

	// Parse device ID if provided
	var deviceID int64 = 0
	if deviceIDStr != "" {
		if id, err := strconv.ParseInt(deviceIDStr, 10, 64); err == nil {
			deviceID = id
		}
	}

	// Fetch logs from database
	logs, totalCount, err := db.GetAuditLogs(deviceID, page, pageSize, searchTerm, securityLevel)
	if err != nil {
		log.Printf("Error fetching audit logs: %v", err)
		data.Error = "Failed to load audit logs"
		logs = []db.AuditLog{} // Empty slice to prevent template errors
		totalCount = 0
	}

	// Calculate pagination
	totalPages := (totalCount + pageSize - 1) / pageSize
	if totalPages == 0 {
		totalPages = 1
	}

	// Set template data
	data.Data["Logs"] = logs
	data.Data["CurrentPage"] = page
	data.Data["TotalPages"] = totalPages
	data.Data["PageSize"] = pageSize
	data.Data["TotalLogs"] = totalCount
	data.Data["SearchTerm"] = searchTerm
	data.Data["SecurityLevel"] = securityLevel
	data.Data["DeviceID"] = deviceIDStr

	// Fetch devices for filter dropdown
	devices, err := db.GetAllDevices()
	if err != nil {
		log.Printf("Error fetching devices: %v", err)
		data.Data["Devices"] = []db.Device{}
	} else {
		data.Data["Devices"] = devices
	}

	templates.RenderGinTemplate(c, "logs", data)
}
