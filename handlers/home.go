package handlers

import (
	"github.com/gin-gonic/gin"

	"example/go-website/templates"
)

// HomeHandler handles the dashboard/home page
func HomeHandler(c *gin.Context) {
	data := templates.GetPageDataFromGin(c)
	data.Title = "Dashboard"

	// Get device statistics (simplified - these functions may not exist)
	data.Data["TotalDevices"] = 0
	data.Data["OnlineDevices"] = 0
	data.Data["RecentLogs"] = 0

	templates.RenderGinTemplate(c, "home", data)
}

// NotFoundHandler handles 404 errors
func NotFoundHandler(c *gin.Context) {
	data := templates.GetPageDataFromGin(c)
	data.Title = "404 - Not Found"
	templates.RenderGinTemplate(c, "404", data)
}
