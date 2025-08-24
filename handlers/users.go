package handlers

import (
	"log"
	"strconv"

	"github.com/gin-gonic/gin"

	"example/go-website/db"
	"example/go-website/templates"
)

// UsersHandler handles user listing and management
func UsersHandler(c *gin.Context) {
	data := templates.GetPageDataFromGin(c)
	data.Title = "User Management"
	templates.RenderGinTemplate(c, "users", data)
}

// AddUserHandler handles adding new users
func AddUserHandler(c *gin.Context) {
	data := templates.GetPageDataFromGin(c)
	data.Title = "Add User"
	templates.RenderGinTemplate(c, "add-user", data)
}

// EditUserHandler handles editing existing users
func EditUserHandler(c *gin.Context) {
	data := templates.GetPageDataFromGin(c)
	data.Title = "Edit User"

	// Get user ID from URL parameter
	userIDStr := c.Param("id")
	if userIDStr == "" {
		data.Error = "User ID is required"
		templates.RenderGinTemplate(c, "404", data)
		return
	}

	// Parse user ID
	userID, err := strconv.ParseInt(userIDStr, 10, 64)
	if err != nil {
		log.Printf("Invalid user ID: %v", err)
		data.Error = "Invalid user ID"
		templates.RenderGinTemplate(c, "404", data)
		return
	}

	// Load user from database
	user, err := db.GetUserByID(userID)
	if err != nil {
		log.Printf("Error loading user ID %d: %v", userID, err)
		data.Error = "User not found"
		templates.RenderGinTemplate(c, "404", data)
		return
	}

	if user == nil {
		data.Error = "User not found"
		templates.RenderGinTemplate(c, "404", data)
		return
	}

	// Populate user data
	data.User = user

	// Handle POST request (form submission)
	if c.Request.Method == "POST" {
		// Handle user update logic here
		// For now, just render the form
	}

	templates.RenderGinTemplate(c, "edit-user", data)
}
