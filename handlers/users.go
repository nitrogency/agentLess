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

// UsersHandler handles user listing and management
func UsersHandler(c *gin.Context) {
	data := templates.GetPageDataFromGin(c)
	data.Title = "User Management"

	// Check if user is admin
	if !data.IsAdmin {
		data.Error = "Access denied. Admin privileges required."
		templates.RenderGinTemplate(c, "404", data)
		return
	}

	// Get all users from database
	users, err := db.GetAllUsers()
	if err != nil {
		log.Printf("Error getting users: %v", err)
		data.Error = "Failed to load users"
		users = []db.User{}
	}

	// Populate PageData field used by templates
	data.Users = users
	// Keep Data map for any legacy references
	data.Data["Users"] = users
	templates.RenderGinTemplate(c, "users", data)
}

// AddUserHandler handles adding new users
func AddUserHandler(c *gin.Context) {
	data := templates.GetPageDataFromGin(c)
	data.Title = "Add User"

	// Check if user is admin
	if !data.IsAdmin {
		data.Error = "Access denied. Admin privileges required."
		templates.RenderGinTemplate(c, "404", data)
		return
	}

	if c.Request.Method == "POST" {
		// Get form data
		username := strings.TrimSpace(c.PostForm("username"))
		password := c.PostForm("password")
		confirmPassword := c.PostForm("confirm_password")
		isAdmin := c.PostForm("isAdmin") == "on"
		canAddDevices := c.PostForm("canAddDevices") == "on"
		canModifyDevices := c.PostForm("canModifyDevices") == "on"
		canAddUsers := c.PostForm("canAddUsers") == "on"
		canModifyUsers := c.PostForm("canModifyUsers") == "on"

		// Store form data for repopulating on error
		data.FormData["username"] = username

		// Validate required fields
		if username == "" {
			data.Error = "Username is required"
			data.ErrorFields["username"] = true
			templates.RenderGinTemplate(c, "add-user", data)
			return
		}

		if !utils.IsValidUsername(username) {
			data.Error = "Invalid username format. Use lowercase letters, numbers, underscore, and hyphens only."
			data.ErrorFields["username"] = true
			templates.RenderGinTemplate(c, "add-user", data)
			return
		}

		if password == "" {
			data.Error = "Password is required"
			data.ErrorFields["password"] = true
			templates.RenderGinTemplate(c, "add-user", data)
			return
		}

		if len(password) < 8 {
			data.Error = "Password must be at least 8 characters long"
			data.ErrorFields["password"] = true
			templates.RenderGinTemplate(c, "add-user", data)
			return
		}

		if password != confirmPassword {
			data.Error = "Passwords do not match"
			data.ErrorFields["password"] = true
			data.ErrorFields["confirm_password"] = true
			templates.RenderGinTemplate(c, "add-user", data)
			return
		}

		// Check if username already exists
		existingUser, err := db.GetUserByUsername(username)
		if err != nil {
			log.Printf("Error checking username: %v", err)
			data.Error = "Error validating username"
			templates.RenderGinTemplate(c, "add-user", data)
			return
		}
		if existingUser != nil {
			data.Error = "Username already exists"
			data.ErrorFields["username"] = true
			templates.RenderGinTemplate(c, "add-user", data)
			return
		}

		// Create user
		err = db.CreateUser(username, password, isAdmin, canAddDevices, canModifyDevices, canAddUsers, canModifyUsers)
		if err != nil {
			log.Printf("Error creating user: %v", err)
			data.Error = "Failed to create user"
			templates.RenderGinTemplate(c, "add-user", data)
			return
		}

		// Redirect to users list on success
		c.Redirect(http.StatusFound, "/users")
		return
	}

	templates.RenderGinTemplate(c, "add-user", data)
}

// EditUserHandler handles editing existing users
func EditUserHandler(c *gin.Context) {
	data := templates.GetPageDataFromGin(c)
	data.Title = "Edit User"

	// Check if user is admin
	if !data.IsAdmin {
		data.Error = "Access denied. Admin privileges required."
		templates.RenderGinTemplate(c, "404", data)
		return
	}

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

	// Handle POST request (form submission)
	if c.Request.Method == "POST" {
		// Get form data
		username := strings.TrimSpace(c.PostForm("username"))
		password := c.PostForm("password")
		confirmPassword := c.PostForm("confirm_password")
		isAdmin := c.PostForm("isAdmin") == "on"
		canAddDevices := c.PostForm("canAddDevices") == "on"
		canModifyDevices := c.PostForm("canModifyDevices") == "on"
		canAddUsers := c.PostForm("canAddUsers") == "on"
		canModifyUsers := c.PostForm("canModifyUsers") == "on"
		flickerLow := c.PostForm("flickerLow") == "on"
		flickerMedium := c.PostForm("flickerMedium") == "on"
		flickerHigh := c.PostForm("flickerHigh") == "on"
		searchTerms := strings.TrimSpace(c.PostForm("searchTerms"))

		// Store form data for repopulating on error
		data.FormData["username"] = username
		data.FormData["searchTerms"] = searchTerms

		// Validate required fields
		if username == "" {
			data.Error = "Username is required"
			data.ErrorFields["username"] = true
			data.User = user
			templates.RenderGinTemplate(c, "edit-user", data)
			return
		}

		if !utils.IsValidUsername(username) {
			data.Error = "Invalid username format. Use lowercase letters, numbers, underscore, and hyphens only."
			data.ErrorFields["username"] = true
			data.User = user
			templates.RenderGinTemplate(c, "edit-user", data)
			return
		}

		// Check if username changed and if new username already exists
		if username != user.Username {
			existingUser, err := db.GetUserByUsername(username)
			if err != nil {
				log.Printf("Error checking username: %v", err)
				data.Error = "Error validating username"
				data.User = user
				templates.RenderGinTemplate(c, "edit-user", data)
				return
			}
			if existingUser != nil {
				data.Error = "Username already exists"
				data.ErrorFields["username"] = true
				data.User = user
				templates.RenderGinTemplate(c, "edit-user", data)
				return
			}
		}

		// Validate password if provided
		if password != "" {
			if len(password) < 8 {
				data.Error = "Password must be at least 8 characters long"
				data.ErrorFields["password"] = true
				data.User = user
				templates.RenderGinTemplate(c, "edit-user", data)
				return
			}

			if password != confirmPassword {
				data.Error = "Passwords do not match"
				data.ErrorFields["password"] = true
				data.ErrorFields["confirm_password"] = true
				data.User = user
				templates.RenderGinTemplate(c, "edit-user", data)
				return
			}
		}

		// Prevent user from removing their own admin privileges
		if userID == data.UserID && !isAdmin {
			data.Error = "You cannot remove your own admin privileges"
			data.ErrorFields["is_admin"] = true
			data.User = user
			templates.RenderGinTemplate(c, "edit-user", data)
			return
		}

		// Update user
		if password != "" {
			// Update with new password
			err = db.UpdateUserWithPassword(userID, username, password, isAdmin, canAddDevices, canModifyDevices, canAddUsers, canModifyUsers, flickerLow, flickerMedium, flickerHigh, searchTerms)
		} else {
			// Update without changing password
			err = db.UpdateUser(userID, username, isAdmin, canAddDevices, canModifyDevices, canAddUsers, canModifyUsers, flickerLow, flickerMedium, flickerHigh, searchTerms)
		}

		if err != nil {
			log.Printf("Error updating user: %v", err)
			data.Error = "Failed to update user"
			data.User = user
			templates.RenderGinTemplate(c, "edit-user", data)
			return
		}

		// Update notification rules based on search terms
		err = db.UpdateUserNotificationRules(userID, searchTerms)
		if err != nil {
			log.Printf("Error updating user notification rules: %v", err)
			// Don't fail the user update for notification rule errors, just log it
		}

		// Redirect to users list on success
		c.Redirect(http.StatusFound, "/users")
		return
	}

	// Populate user data for GET request
	data.User = user
	data.FormData["username"] = user.Username

	templates.RenderGinTemplate(c, "edit-user", data)
}

// DeleteUserHandler handles user deletion
func DeleteUserHandler(c *gin.Context) {
	data := templates.GetPageDataFromGin(c)
	data.Title = "Delete User"

	// Check if user is admin
	if !data.IsAdmin {
		data.Error = "Access denied. Admin privileges required."
		templates.RenderGinTemplate(c, "404", data)
		return
	}

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

	// Prevent user from deleting themselves
	if userID == data.UserID {
		data.Error = "You cannot delete your own account"
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

	// Handle POST request (confirm deletion)
	if c.Request.Method == "POST" {
		confirm := c.PostForm("confirm")
		if confirm == "yes" {
			// Delete the user
			err := db.DeleteUser(userID, data.UserID)
			if err != nil {
				log.Printf("Error deleting user: %v", err)
				data.Error = "Failed to delete user"
				data.Data["User"] = user
				templates.RenderGinTemplate(c, "delete-user-confirm", data)
				return
			}
			// Redirect to users list on success
			c.Redirect(http.StatusFound, "/users")
			return
		} else {
			// User cancelled deletion
			c.Redirect(http.StatusFound, "/users")
			return
		}
	}

	// Populate user data
	data.Data["User"] = user
	templates.RenderGinTemplate(c, "delete-user-confirm", data)
}
