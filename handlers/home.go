package handlers

import (
	"github.com/gin-gonic/gin"
	"log"

	"example/go-website/db"
	"example/go-website/templates"
)

// HomeHandler handles the dashboard/home page
func HomeHandler(c *gin.Context) {
	data := templates.GetPageDataFromGin(c)
	data.Title = "Dashboard"

	// Get actual statistics from database
	// Device count
	devices, err := db.GetAllDevices()
	if err != nil {
		log.Printf("Error getting devices: %v", err)
		data.Data["DeviceCount"] = 0
	} else {
		data.Data["DeviceCount"] = len(devices)
	}

	// User count
	users, err := db.GetAllUsers()
	if err != nil {
		log.Printf("Error getting users: %v", err)
		data.Data["UserCount"] = 0
	} else {
		data.Data["UserCount"] = len(users)
	}

	// Log count
	logs, err := db.GetAllAuditLogs()
	if err != nil {
		log.Printf("Error getting audit logs: %v", err)
		data.Data["LogCount"] = 0
	} else {
		data.Data["LogCount"] = len(logs)
	}

	templates.RenderGinTemplate(c, "home", data)
}

// NotFoundHandler handles 404 errors
func NotFoundHandler(c *gin.Context) {
	data := templates.GetPageDataFromGin(c)
	data.Title = "404 - Not Found"
	templates.RenderGinTemplate(c, "404", data)
}
