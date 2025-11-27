package handlers

import (
	"log"
	"time"

	"github.com/gin-gonic/gin"

	"agentless/db"
	"agentless/templates"
)

// HomeHandler handles the dashboard/home page
func HomeHandler(c *gin.Context) {
	data := templates.GetPageDataFromGin(c)
	data.Title = "Dashboard"

	// Get device statistics
	devices, err := db.GetAllDevices()
	if err != nil {
		log.Printf("Error getting devices for dashboard: %v", err)
		devices = []db.Device{}
	}

	// Count device statistics
	totalDevices := len(devices)
	onlineDevices := 0
	offlineDevices := 0
	unknownDevices := 0

	for _, device := range devices {
		switch device.Status {
		case "online":
			onlineDevices++
		case "offline":
			offlineDevices++
		default:
			unknownDevices++
		}
	}

	// Get recent audit logs (last 24 hours)
	recentLogs, totalRecentLogs, err := db.GetAuditLogs(0, 1, 100, "", "")
	if err != nil {
		log.Printf("Error getting recent logs for dashboard: %v", err)
		recentLogs = []db.AuditLog{}
		totalRecentLogs = 0
	}

	// Filter logs from last 24 hours
	twentyFourHoursAgo := time.Now().Add(-24 * time.Hour)
	recentLogsCount := 0
	highSecurityCount := 0
	mediumSecurityCount := 0
	lowSecurityCount := 0

	for _, logEntry := range recentLogs {
		if logEntry.Timestamp.After(twentyFourHoursAgo) {
			recentLogsCount++
			switch logEntry.SecurityLevel {
			case db.HighSecurity:
				highSecurityCount++
			case db.MediumSecurity:
				mediumSecurityCount++
			case db.LowSecurity:
				lowSecurityCount++
			}
		}
	}

	// Get user statistics (admin only)
	userCount := 0
	if data.IsAdmin {
		users, err := db.GetAllUsers()
		if err != nil {
			log.Printf("Error getting users for dashboard: %v", err)
		} else {
			userCount = len(users)
		}
	}

	// Get latest 5 logs for quick view
	latestLogs := recentLogs
	if len(latestLogs) > 5 {
		latestLogs = latestLogs[:5]
	}

	// Populate dashboard data
	data.Data["TotalDevices"] = totalDevices
	data.Data["OnlineDevices"] = onlineDevices
	data.Data["OfflineDevices"] = offlineDevices
	data.Data["UnknownDevices"] = unknownDevices
	data.Data["RecentLogsCount"] = recentLogsCount
	data.Data["TotalLogsCount"] = totalRecentLogs
	data.Data["HighSecurityCount"] = highSecurityCount
	data.Data["MediumSecurityCount"] = mediumSecurityCount
	data.Data["LowSecurityCount"] = lowSecurityCount
	data.Data["UserCount"] = userCount
	data.Data["LatestLogs"] = latestLogs
	data.Data["RecentDevices"] = devices

	// Calculate uptime percentage
	uptimePercentage := 0.0
	if totalDevices > 0 {
		uptimePercentage = (float64(onlineDevices) / float64(totalDevices)) * 100
	}
	data.Data["UptimePercentage"] = uptimePercentage

	templates.RenderGinTemplate(c, "home", data)
}

// NotFoundHandler handles 404 errors
func NotFoundHandler(c *gin.Context) {
	data := templates.GetPageDataFromGin(c)
	data.Title = "404 - Not Found"
	templates.RenderGinTemplate(c, "404", data)
}
