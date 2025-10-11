package handlers

import (
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/gin-contrib/sessions"
	"github.com/gin-gonic/gin"

	"example/go-website/db"
	"example/go-website/models"
	"example/go-website/templates"
)

// Security logger for fail2ban integration
var securityLogger *log.Logger

func init() {
	// Use system log directory
	logsDir := "/var/log/agentless"
	
	// Create logs directory if it doesn't exist
	if err := os.MkdirAll(logsDir, 0755); err != nil {
		log.Printf("Warning: Could not create logs directory %s: %v", logsDir, err)
	}
	
	// Create or open security log file for fail2ban
	securityLogFile := filepath.Join(logsDir, "security.log")

	// Try to create/open the log file
	logFile, err := os.OpenFile(securityLogFile, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		// Fallback to standard logger if can't open security log
		securityLogger = log.New(os.Stderr, "[SECURITY] ", log.LstdFlags)
		log.Printf("Warning: Could not open security log file %s: %v", securityLogFile, err)
	} else {
		securityLogger = log.New(logFile, "", log.LstdFlags)
		log.Printf("Security logging enabled: %s", securityLogFile)
	}
}

// logSecurityEvent logs security events in a format that fail2ban can parse
func logSecurityEvent(c *gin.Context, event string, username string) {
	clientIP := c.ClientIP()
	userAgent := c.GetHeader("User-Agent")

	// Log in fail2ban-compatible format
	securityLogger.Printf("%s from %s - Username: %s, User-Agent: %s",
		event, clientIP, username, userAgent)

	// Also log to standard logger for debugging
	log.Printf("Security event: %s from %s (username: %s)", event, clientIP, username)
}

// LoginHandler handles user login (GET and POST)
func LoginHandler(c *gin.Context) {
	// Check if user is already authenticated, redirect to home
	session := sessions.Default(c)
	if authenticated := session.Get("authenticated"); authenticated == true {
		c.Redirect(http.StatusFound, "/")
		return
	}

	// Check if users table is empty, redirect to signup if so
	isEmpty, err := db.IsUsersTableEmpty()
	if err != nil {
		log.Printf("Error checking if users table is empty: %v", err)
		templates.RenderGinTemplate(c, "404", models.PageData{
			Title: "Error",
			Error: "Database error occurred.",
		})
		return
	}

	if isEmpty {
		c.Redirect(http.StatusFound, "/signup")
		return
	}

	data := templates.GetPageDataFromGin(c)
	data.Title = "Login"

	if c.Request.Method == "POST" {
		username := strings.TrimSpace(c.PostForm("username"))
		password := c.PostForm("password")

		data.FormData["username"] = username

		if username == "" {
			data.Error = "Username is required"
			data.ErrorFields["username"] = true
			templates.RenderGinTemplate(c, "login", data)
			return
		}

		if password == "" {
			data.Error = "Password is required"
			data.ErrorFields["password"] = true
			templates.RenderGinTemplate(c, "login", data)
			return
		}

		// Validate user credentials
		valid, err := db.ValidateUser(username, password)
		if err != nil || !valid {
			// Log security event for fail2ban
			logSecurityEvent(c, "Authentication failed", username)

			log.Printf("Login validation error for user %s from %s: %v", username, c.ClientIP(), err)
			data.Error = "Invalid username or password"
			data.ErrorFields["username"] = true
			data.ErrorFields["password"] = true
			templates.RenderGinTemplate(c, "login", data)
			return
		}

		// Get user details after successful validation
		user, err := db.GetUserByUsername(username)
		if err != nil || user == nil {
			// Log security event for fail2ban
			logSecurityEvent(c, "Authentication failed", username)

			log.Printf("Error getting user details: %v", err)
			data.Error = "Login failed. Please try again."
			templates.RenderGinTemplate(c, "login", data)
			return
		}

		// Create session
		session := sessions.Default(c)
		session.Set("username", user.Username)
		session.Set("user_id", user.ID)
		session.Set("authenticated", true)
		session.Set("login_time", time.Now().Format(time.RFC3339))

		if err := session.Save(); err != nil {
			// Log security event for fail2ban
			logSecurityEvent(c, "Authentication failed", username)

			log.Printf("Session save error: %v", err)
			data.Error = "Login failed. Please try again."
			templates.RenderGinTemplate(c, "login", data)
			return
		}

		// Log successful login
		logSecurityEvent(c, "Successful login", user.Username)

		c.Redirect(http.StatusFound, "/")
		return
	}

	templates.RenderGinTemplate(c, "login", data)
}

// LogoutHandler handles user logout
func LogoutHandler(c *gin.Context) {
	session := sessions.Default(c)

	// Log logout event if user was authenticated
	if username := session.Get("username"); username != nil {
		logSecurityEvent(c, "User logout", username.(string))
	}

	session.Clear()
	session.Save()
	c.Redirect(http.StatusFound, "/login")
}

// SignupHandler handles initial admin user creation
func SignupHandler(c *gin.Context) {
	isEmpty, err := db.IsUsersTableEmpty()
	if err != nil {
		log.Printf("Error checking if users table is empty: %v", err)
		templates.RenderGinTemplate(c, "404", models.PageData{
			Title: "Error",
			Error: "Database error occurred.",
		})
		return
	}

	if !isEmpty {
		c.Redirect(http.StatusFound, "/login")
		return
	}

	data := templates.GetPageDataFromGin(c)
	data.Title = "Create Admin Account"

	if c.Request.Method == "POST" {
		username := strings.TrimSpace(c.PostForm("username"))
		password := c.PostForm("password")
		confirmPassword := c.PostForm("confirm_password")

		data.FormData["username"] = username

		if username == "" {
			data.Error = "Username is required"
			data.ErrorFields["username"] = true
			templates.RenderGinTemplate(c, "signup", data)
			return
		}

		if password == "" {
			data.Error = "Password is required"
			data.ErrorFields["password"] = true
			templates.RenderGinTemplate(c, "signup", data)
			return
		}

		if password != confirmPassword {
			data.Error = "Passwords do not match"
			data.ErrorFields["password"] = true
			data.ErrorFields["confirm_password"] = true
			templates.RenderGinTemplate(c, "signup", data)
			return
		}

		// Create admin user
		if err := db.CreateUser(username, password, true, true, true, true, true); err != nil {
			log.Printf("Error creating admin user: %v", err)
			data.Error = "Failed to create admin account"
			templates.RenderGinTemplate(c, "signup", data)
			return
		}

		// Create session
		session := sessions.Default(c)
		session.Set("username", username)
		session.Set("authenticated", true)
		session.Set("login_time", time.Now().Format(time.RFC3339))

		if err := session.Save(); err != nil {
			log.Printf("Session save error: %v", err)
			data.Error = "Account created but login failed. Please try logging in."
			templates.RenderGinTemplate(c, "signup", data)
			return
		}

		c.Redirect(http.StatusFound, "/")
		return
	}

	templates.RenderGinTemplate(c, "signup", data)
}
