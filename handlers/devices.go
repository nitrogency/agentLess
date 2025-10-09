package handlers

import (
	"log"
	"net/http"
	"strconv"
	"strings"

	"github.com/gin-gonic/gin"

	"example/go-website/db"
	"example/go-website/templates"
	"example/go-website/utils"
)

// DevicesHandler handles device listing and management
func DevicesHandler(c *gin.Context) {
	data := templates.GetPageDataFromGin(c)
	data.Title = "Devices"

	// Get all devices from database
	devices, err := db.GetAllDevices()
	if err != nil {
		log.Printf("Error getting devices: %v", err)
		data.Error = "Failed to load devices"
		devices = []db.Device{}
	}
	// Populate PageData field used by templates
	data.Devices = devices
	// Keep Data map for any legacy references
	data.Data["Devices"] = devices
	templates.RenderGinTemplate(c, "devices", data)
}

// AddDeviceHandler handles adding new devices
func AddDeviceHandler(c *gin.Context) {
	data := templates.GetPageDataFromGin(c)
	data.Title = "Add Device"

	if c.Request.Method == "POST" {
		// Get form data
		name := strings.TrimSpace(c.PostForm("name"))
		deviceType := strings.TrimSpace(c.PostForm("type"))
		ipAddress := strings.TrimSpace(c.PostForm("ip_address"))
		sshUser := strings.TrimSpace(c.PostForm("ssh_user"))
		sshKeyPath := strings.TrimSpace(c.PostForm("ssh_key_path"))
		sshPortStr := strings.TrimSpace(c.PostForm("ssh_port"))
		hostname := strings.TrimSpace(c.PostForm("hostname"))
		osInfo := strings.TrimSpace(c.PostForm("os_info"))
		sshGroup := strings.TrimSpace(c.PostForm("ssh_group"))
		setupUser := strings.TrimSpace(c.PostForm("setup_user"))
		setupPassword := c.PostForm("setup_password")
		osType := strings.ToLower(strings.TrimSpace(c.PostForm("os_type")))
		randomUserVal := strings.ToLower(strings.TrimSpace(c.PostForm("random_user")))
		randomKeyVal := strings.ToLower(strings.TrimSpace(c.PostForm("random_key")))
		randomUser := randomUserVal == "on" || randomUserVal == "true" || randomUserVal == "1"
		randomKey := randomKeyVal == "on" || randomKeyVal == "true" || randomKeyVal == "1"
		auditArch := strings.TrimSpace(c.PostForm("audit_arch"))
		auditRuleset := strings.TrimSpace(c.PostForm("audit_ruleset"))

		// Default to linux if not specified
		if osType == "" {
			osType = "linux"
		}
		// Default audit settings for Linux
		if auditArch == "" {
			auditArch = "x64"
		}
		if auditRuleset == "" {
			auditRuleset = "audit_default.rules"
		}

		// Store form data for repopulating on error
		data.FormData["name"] = name
		data.FormData["type"] = deviceType
		data.FormData["ip_address"] = ipAddress
		data.FormData["ssh_user"] = sshUser
		data.FormData["ssh_key_path"] = sshKeyPath
		data.FormData["ssh_port"] = sshPortStr
		data.FormData["hostname"] = hostname
		data.FormData["os_info"] = osInfo
		data.FormData["os_type"] = osType
		data.FormData["ssh_group"] = sshGroup
		data.FormData["setup_user"] = setupUser
		data.FormData["setup_password"] = setupPassword
		data.FormData["audit_arch"] = auditArch
		data.FormData["audit_ruleset"] = auditRuleset
		// Preserve checkbox state in template on validation errors
		data.RandomUser = randomUser
		data.RandomKey = randomKey

		// Validate required fields
		if name == "" {
			data.Error = "Device name is required"
			data.ErrorFields["name"] = true
			templates.RenderGinTemplate(c, "add-device", data)
			return
		}

		if deviceType == "" {
			data.Error = "Device type is required"
			data.ErrorFields["type"] = true
			templates.RenderGinTemplate(c, "add-device", data)
			return
		}

		// Validate name uniqueness
		exists, err := db.DeviceExistsByName(name, 0)
		if err != nil {
			log.Printf("Error checking device name: %v", err)
			data.Error = "Error validating device name"
			templates.RenderGinTemplate(c, "add-device", data)
			return
		}
		if exists {
			data.Error = "A device with this name already exists"
			data.ErrorFields["name"] = true
			templates.RenderGinTemplate(c, "add-device", data)
			return
		}

		// Validate IP address if provided
		if ipAddress != "" {
			if !utils.IsValidIPAddress(ipAddress) {
				data.Error = "Invalid IP address format"
				data.ErrorFields["ip_address"] = true
				templates.RenderGinTemplate(c, "add-device", data)
				return
			}

			// Check IP uniqueness
			exists, err := db.DeviceExistsByIP(ipAddress, 0)
			if err != nil {
				log.Printf("Error checking IP address: %v", err)
				data.Error = "Error validating IP address"
				templates.RenderGinTemplate(c, "add-device", data)
				return
			}
			if exists {
				data.Error = "A device with this IP address already exists"
				data.ErrorFields["ip_address"] = true
				templates.RenderGinTemplate(c, "add-device", data)
				return
			}
		}

		// Parse SSH port
		sshPort := 22 // Default
		if sshPortStr != "" {
			parsedPort, err := strconv.Atoi(sshPortStr)
			if err != nil || parsedPort < 1 || parsedPort > 65535 {
				data.Error = "Invalid SSH port number"
				data.ErrorFields["ssh_port"] = true
				templates.RenderGinTemplate(c, "add-device", data)
				return
			}
			sshPort = parsedPort
		}

		// Set default setup user if empty
		if setupUser == "" {
			setupUser = "root"
		}

		// Validate OS type
		if osType != "linux" && osType != "windows" {
			data.Error = "Invalid OS type. Must be 'linux' or 'windows'"
			data.ErrorFields["os_type"] = true
			templates.RenderGinTemplate(c, "add-device", data)
			return
		}

		// Create device
		if ipAddress != "" {
			// Create monitored device with SSH details and OS type
			err = db.CreateMonitoredDeviceWithOS(name, deviceType, ipAddress, sshUser, sshKeyPath, sshPort, hostname, osInfo, osType, sshGroup, randomUser, randomKey, setupUser, setupPassword, auditArch, auditRuleset)
		} else {
			// Create simple device
			err = db.CreateDevice(name, deviceType)
		}

		if err != nil {
			log.Printf("Error creating device: %v", err)
			data.Error = "Failed to create device"
			templates.RenderGinTemplate(c, "add-device", data)
			return
		}

		// Redirect to devices list on success
		c.Redirect(http.StatusFound, "/devices")
		return
	}

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

	// Handle POST request (form submission)
	if c.Request.Method == "POST" {
		// Get form data
		name := strings.TrimSpace(c.PostForm("name"))
		deviceType := strings.TrimSpace(c.PostForm("type"))
		ipAddress := strings.TrimSpace(c.PostForm("ip_address"))
		sshUser := strings.TrimSpace(c.PostForm("ssh_user"))
		sshKeyPath := strings.TrimSpace(c.PostForm("ssh_key_path"))
		sshPortStr := strings.TrimSpace(c.PostForm("ssh_port"))
		hostname := strings.TrimSpace(c.PostForm("hostname"))
		osInfo := strings.TrimSpace(c.PostForm("os_info"))
		osType := strings.ToLower(strings.TrimSpace(c.PostForm("os_type")))
		sshGroup := strings.TrimSpace(c.PostForm("ssh_group"))
		setupUser := strings.TrimSpace(c.PostForm("setup_user"))
		setupPassword := c.PostForm("setup_password")
		randomUser := c.PostForm("random_user") == "on"
		randomKey := c.PostForm("random_key") == "on"
		auditArch := strings.TrimSpace(c.PostForm("audit_arch"))
		auditRuleset := strings.TrimSpace(c.PostForm("audit_ruleset"))

		// Default to device's current OS type if not specified
		if osType == "" {
			osType = device.OSType
			if osType == "" {
				osType = "linux"
			}
		}
		// Default audit settings if not specified
		if auditArch == "" {
			auditArch = device.AuditArch
			if auditArch == "" {
				auditArch = "x64"
			}
		}
		if auditRuleset == "" {
			auditRuleset = device.AuditRuleset
			if auditRuleset == "" {
				auditRuleset = "audit_default.rules"
			}
		}

		// Store form data for repopulating on error
		data.FormData["name"] = name
		data.FormData["type"] = deviceType
		data.FormData["ip_address"] = ipAddress
		data.FormData["ssh_user"] = sshUser
		data.FormData["ssh_key_path"] = sshKeyPath
		data.FormData["ssh_port"] = sshPortStr
		data.FormData["hostname"] = hostname
		data.FormData["os_info"] = osInfo
		data.FormData["os_type"] = osType
		data.FormData["ssh_group"] = sshGroup
		data.FormData["setup_user"] = setupUser
		data.FormData["setup_password"] = setupPassword
		data.FormData["audit_arch"] = auditArch
		data.FormData["audit_ruleset"] = auditRuleset

		// Validate required fields
		if name == "" {
			data.Error = "Device name is required"
			data.ErrorFields["name"] = true
			data.Data["Device"] = device
			templates.RenderGinTemplate(c, "edit-device", data)
			return
		}

		if deviceType == "" {
			data.Error = "Device type is required"
			data.ErrorFields["type"] = true
			data.Data["Device"] = device
			templates.RenderGinTemplate(c, "edit-device", data)
			return
		}

		// Validate name uniqueness (excluding current device)
		if name != device.Name {
			exists, err := db.DeviceExistsByName(name, deviceID)
			if err != nil {
				log.Printf("Error checking device name: %v", err)
				data.Error = "Error validating device name"
				data.Data["Device"] = device
				templates.RenderGinTemplate(c, "edit-device", data)
				return
			}
			if exists {
				data.Error = "A device with this name already exists"
				data.ErrorFields["name"] = true
				data.Data["Device"] = device
				templates.RenderGinTemplate(c, "edit-device", data)
				return
			}
		}

		// Validate IP address if provided
		if ipAddress != "" {
			if !utils.IsValidIPAddress(ipAddress) {
				data.Error = "Invalid IP address format"
				data.ErrorFields["ip_address"] = true
				data.Data["Device"] = device
				templates.RenderGinTemplate(c, "edit-device", data)
				return
			}

			// Check IP uniqueness (excluding current device)
			if ipAddress != device.IPAddress {
				exists, err := db.DeviceExistsByIP(ipAddress, deviceID)
				if err != nil {
					log.Printf("Error checking IP address: %v", err)
					data.Error = "Error validating IP address"
					data.Data["Device"] = device
					templates.RenderGinTemplate(c, "edit-device", data)
					return
				}
				if exists {
					data.Error = "A device with this IP address already exists"
					data.ErrorFields["ip_address"] = true
					data.Data["Device"] = device
					templates.RenderGinTemplate(c, "edit-device", data)
					return
				}
			}
		}

		// Parse SSH port
		sshPort := 22 // Default
		if sshPortStr != "" {
			parsedPort, err := strconv.Atoi(sshPortStr)
			if err != nil || parsedPort < 1 || parsedPort > 65535 {
				data.Error = "Invalid SSH port number"
				data.ErrorFields["ssh_port"] = true
				data.Data["Device"] = device
				templates.RenderGinTemplate(c, "edit-device", data)
				return
			}
			sshPort = parsedPort
		}

		// Set default setup user if empty
		if setupUser == "" {
			setupUser = "root"
		}

		// Validate OS type
		if osType != "linux" && osType != "windows" {
			data.Error = "Invalid OS type. Must be 'linux' or 'windows'"
			data.ErrorFields["os_type"] = true
			data.Data["Device"] = device
			templates.RenderGinTemplate(c, "edit-device", data)
			return
		}

		// Check if enrollment-sensitive fields have changed
		newDevice := &db.Device{
			SSHPort:            sshPort,
			SSHUser:            sshUser,
			SSHKeyPath:         sshKeyPath,
			SSHGroup:           sshGroup,
			AuditArch:          auditArch,
			AuditRuleset:       auditRuleset,
			FirewallMode:       device.FirewallMode, // Firewall settings come from existing device
			FirewallAllowedIPs: device.FirewallAllowedIPs,
			SetupUser:          setupUser,
		}
		needsReenrollment := db.NeedsReenrollmentChanged(device, newDevice)

		// Update device with OS type and reenrollment flag
		err = db.UpdateMonitoredDeviceWithOSAndReenrollment(deviceID, name, deviceType, device.Status, ipAddress, sshUser, sshKeyPath, sshPort, hostname, osInfo, osType, sshGroup, randomUser, randomKey, setupUser, setupPassword, auditArch, auditRuleset, needsReenrollment)
		if err != nil {
			log.Printf("Error updating device: %v", err)
			data.Error = "Failed to update device"
			data.Data["Device"] = device
			templates.RenderGinTemplate(c, "edit-device", data)
			return
		}

		// Redirect to devices list on success
		c.Redirect(http.StatusFound, "/devices")
		return
	}

	// Populate device data for GET request
	// For templates using top-level .Device
	data.Device = *device
	// Keep Data map for any legacy references
	data.Data["Device"] = device
	data.FormData["name"] = device.Name
	data.FormData["type"] = device.Type
	data.FormData["ip_address"] = device.IPAddress
	data.FormData["ssh_user"] = device.SSHUser
	data.FormData["ssh_key_path"] = device.SSHKeyPath
	data.FormData["ssh_port"] = strconv.Itoa(device.SSHPort)
	data.FormData["hostname"] = device.Hostname
	data.FormData["os_info"] = device.OSInfo
	data.FormData["os_type"] = device.OSType
	data.FormData["ssh_group"] = device.SSHGroup
	data.FormData["setup_user"] = device.SetupUser
	data.FormData["setup_password"] = device.SetupPassword
	// Set checkbox states
	data.RandomUser = device.RandomUser
	data.RandomKey = device.RandomKey

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

	// Handle POST request (confirm deletion)
	if c.Request.Method == "POST" {
		confirm := c.PostForm("confirm")
		if confirm == "yes" {
			// Delete the device
			err := db.DeleteDevice(deviceID)
			if err != nil {
				log.Printf("Error deleting device: %v", err)
				data.Error = "Failed to delete device"
				data.Data["Device"] = device
				templates.RenderGinTemplate(c, "delete-device-confirm", data)
				return
			}
			// Redirect to devices list on success
			c.Redirect(http.StatusFound, "/devices")
			return
		} else {
			// User cancelled deletion
			c.Redirect(http.StatusFound, "/devices")
			return
		}
	}

	// Populate device data
	// For templates using top-level .Device
	data.Device = *device
	// Keep Data map for any legacy references
	data.Data["Device"] = device
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

	// Get pagination parameters
	pageStr := c.DefaultQuery("page", "1")
	pageSizeStr := c.DefaultQuery("pageSize", "50")
	page, err := strconv.Atoi(pageStr)
	if err != nil || page < 1 {
		page = 1
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

	searchTerm := c.Query("search")

	// Get audit logs for this device
	logs, totalCount, err := db.GetAuditLogsByDeviceID(deviceID, page, pageSize, searchTerm)
	if err != nil {
		log.Printf("Error getting audit logs for device %d: %v", deviceID, err)
		logs = []db.AuditLog{}
		totalCount = 0
	}

	// Calculate pagination info
	totalPages := (totalCount + pageSize - 1) / pageSize
	if totalPages == 0 {
		totalPages = 1
	}

	// Populate data
	// For templates using top-level .Device
	data.Device = *device
	// Keep Data map for any legacy references
	data.Data["Device"] = device
	data.Data["Logs"] = logs
	// Back-compat for templates expecting .Data.AuditLogs
	data.Data["AuditLogs"] = logs
	data.Data["CurrentPage"] = page
	data.Data["TotalPages"] = totalPages
	data.Data["PageSize"] = pageSize
	data.Data["TotalLogs"] = totalCount
	data.Data["SearchTerm"] = searchTerm

	templates.RenderGinTemplate(c, "monitor-device", data)
}

