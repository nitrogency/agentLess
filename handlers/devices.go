package handlers

import (
	"github.com/gin-gonic/gin"

	"example/go-website/templates"
)

// DevicesHandler handles device listing and management
func DevicesHandler(c *gin.Context) {
	data := templates.GetPageDataFromGin(c)
	data.Title = "Devices"
	templates.RenderGinTemplate(c, "devices", data)
}

// AddDeviceHandler handles adding new devices
func AddDeviceHandler(c *gin.Context) {
	data := templates.GetPageDataFromGin(c)
	data.Title = "Add Device"
	templates.RenderGinTemplate(c, "add-device", data)
}

// EditDeviceHandler handles editing existing devices
func EditDeviceHandler(c *gin.Context) {
	data := templates.GetPageDataFromGin(c)
	data.Title = "Edit Device"
	templates.RenderGinTemplate(c, "edit-device", data)
}

// DeleteDeviceHandler handles device deletion confirmation
func DeleteDeviceHandler(c *gin.Context) {
	data := templates.GetPageDataFromGin(c)
	data.Title = "Delete Device"
	templates.RenderGinTemplate(c, "delete-device-confirm", data)
}

// MonitorDeviceHandler handles device monitoring interface
func MonitorDeviceHandler(c *gin.Context) {
	data := templates.GetPageDataFromGin(c)
	data.Title = "Monitor Device"
	templates.RenderGinTemplate(c, "monitor-device", data)
}
