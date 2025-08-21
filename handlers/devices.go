package handlers

import (
	"log"
	"strconv"

	"github.com/gin-gonic/gin"

	"example/go-website/db"
	"example/go-website/templates"
)

// DevicesHandler handles device listing and management
func DevicesHandler(c *gin.Context) {
	data := templates.GetPageDataFromGin(c)
	data.Title = "Devices"

	// Fetch all devices from database
	devices, err := db.GetAllDevices()
	if err != nil {
		log.Printf("Error fetching devices: %v", err)
		data.Error = "Failed to load devices"
		data.Devices = []db.Device{} // Empty slice to prevent template errors
	} else {
		data.Devices = devices
	}

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

	// Populate device data
	data.Device = *device

	templates.RenderGinTemplate(c, "edit-device", data)
}

// DeleteDeviceHandler handles device deletion confirmation
func DeleteDeviceHandler(c *gin.Context) {
	data := templates.GetPageDataFromGin(c)
	data.Title = "Delete Device"

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

	// Populate device data
	data.Device = *device

	templates.RenderGinTemplate(c, "delete-device-confirm", data)
}

// MonitorDeviceHandler handles device monitoring interface
func MonitorDeviceHandler(c *gin.Context) {
	data := templates.GetPageDataFromGin(c)
	data.Title = "Monitor Device"

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

	// Populate device data
	data.Device = *device

	templates.RenderGinTemplate(c, "monitor-device", data)
}
