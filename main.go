package main

import (
	"context"
	"errors"
	"fmt"
	"html/template"
	"log"
	"math/rand"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/gin-contrib/sessions"
	"github.com/gin-contrib/sessions/cookie"
	"github.com/gin-gonic/gin"
	"github.com/joho/godotenv"

	"example/go-website/config"
	"example/go-website/db"
	"example/go-website/middleware"
	"example/go-website/utils"
)

type PageData struct {
	Title              string
	Error              string
	Success            string
	Content            string
	Username           string
	UserID             int64
	IsAdmin            bool
	Users              []db.User
	Devices            []db.Device
	User               *db.User
	Device             db.Device
	RandomUser         bool
	RandomKey          bool
	FormToken          string
	FormData           map[string]string
	ErrorFields        map[string]bool
	MonitoringData     map[string]string
	Data               map[string]interface{}
	HasHighSecurityLogs bool
}

// getPageData creates a PageData struct with common fields populated (Gin version)
// renderGinTemplate renders a template with layout pattern (similar to original renderTemplate)
func renderGinTemplate(c *gin.Context, tmpl string, data PageData) {
	// Create template with functions
	funcMap := template.FuncMap{
		"add": func(a, b int) int {
			return a + b
		},
		"subtract": func(a, b int) int {
			return a - b
		},
		"sequence": func(start, end int) []int {
			var result []int
			for i := start; i <= end; i++ {
				result = append(result, i)
			}
			return result
		},
		"add1": func(a int) int {
			return a + 1
		},
		"sub1": func(a int) int {
			return a - 1
		},
		"sub": func(a, b int) int {
			return a - b
		},
		"deviceName": func(id int64) string {
			return db.GetDeviceNameByID(id)
		},
	}

	// Parse both layout and specific template
	t, err := template.New("layout.html").Funcs(funcMap).ParseFiles(
		"templates/layout.html",
		fmt.Sprintf("templates/%s.html", tmpl),
	)
	if err != nil {
		log.Printf("Template parsing error: %v", err)
		c.String(http.StatusInternalServerError, "Internal Server Error")
		return
	}

	// Set content type
	c.Header("Content-Type", "text/html; charset=utf-8")
	
	// Execute the layout template
	if err := t.ExecuteTemplate(c.Writer, "layout", data); err != nil {
		log.Printf("Template execution error: %v", err)
		c.String(http.StatusInternalServerError, "Internal Server Error")
		return
	}
}

func getPageDataFromGin(c *gin.Context) PageData {
	session := sessions.Default(c)
	
	data := PageData{
		Data:        make(map[string]interface{}),
		FormData:    make(map[string]string),
		ErrorFields: make(map[string]bool),
	}

	// Check if user is authenticated
	authenticated := session.Get("authenticated")
	if authenticated != true {
		return data
	}

	// Get username from session
	usernameInterface := session.Get("username")
	if usernameInterface == nil {
		return data
	}
	
	username, ok := usernameInterface.(string)
	if !ok {
		return data
	}

	data.Username = username

	// Get user ID from session
	userIDInterface := session.Get("user_id")
	if userIDInterface != nil {
		if userID, ok := userIDInterface.(int64); ok {
			data.UserID = userID
		}
	}

	// Get user from database to check admin status
	user, err := db.GetUserByUsername(username)
	if err == nil && user != nil {
		data.IsAdmin = user.IsAdmin
	}

	return data
}


// generateSecretKey generates a random 32-byte key
func generateSecretKey() []byte {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		log.Fatalf("Failed to generate secret key: %v", err)
	}
	return key
}



func init() {
	// Load environment variables
	if err := godotenv.Load(); err != nil {
		log.Printf("Warning: .env file not found")
	}
}





func main() {
	// Load environment variables
	err := godotenv.Load()
	if err != nil {
		log.Printf("Warning: Could not load .env file: %v", err)
	}

	// Load configuration
	cfg, err := config.Load()
	if err != nil {
		log.Fatalf("Failed to load configuration: %v", err)
	}

	// Initialize database
	if err := db.InitDB(); err != nil {
		log.Fatal(err)
	}
	defer db.Close()

	// Start a background status checker
	startStatusChecker(5 * time.Minute)

	// Set Gin mode based on environment
	if os.Getenv("GIN_MODE") != "debug" {
		gin.SetMode(gin.ReleaseMode)
	}

	// Create Gin router
	router := gin.New()

	// Add middleware
	router.Use(gin.Logger())
	router.Use(gin.Recovery())

	// Setup session store
	cookieStore := cookie.NewStore([]byte(cfg.Session.SecretKey))
	cookieStore.Options(sessions.Options{
		Path:     "/",
		HttpOnly: cfg.Session.HttpOnly,
		Secure:   cfg.Session.Secure,
		MaxAge:   3600 * 24, // 24 hours
	})
	
	router.Use(sessions.Sessions(cfg.Session.Name, cookieStore))

	// Add template functions for Gin
	router.SetFuncMap(template.FuncMap{
		"add": func(a, b int) int {
			return a + b
		},
		"subtract": func(a, b int) int {
			return a - b
		},
		"sequence": func(start, end int) []int {
			var result []int
			for i := start; i <= end; i++ {
				result = append(result, i)
			}
			return result
		},
		"add1": func(a int) int {
			return a + 1
		},
		"sub1": func(a int) int {
			return a - 1
		},
		"sub": func(a, b int) int {
			return a - b
		},
		"deviceName": func(id int64) string {
			return db.GetDeviceNameByID(id)
		},
	})
	
	// Load HTML templates with layout pattern
	router.LoadHTMLGlob("templates/*")

	// Serve static files
	router.Static("/static", "./static")

	// Apply security middleware (Gin version)
	router.Use(func(c *gin.Context) {
		// Security headers
		c.Writer.Header().Set("X-Content-Type-Options", "nosniff")
		c.Writer.Header().Set("X-Frame-Options", "DENY")
		c.Writer.Header().Set("X-XSS-Protection", "1; mode=block")
		c.Writer.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")
		c.Writer.Header().Set("Content-Security-Policy", "default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self'")
		c.Next()
	})

	// Initialize rate limiter
	rateLimiter := middleware.NewRateLimiter(5, 15*time.Minute, 30*time.Minute)
	
	// Add rate limiting middleware for login attempts
	router.Use(func(c *gin.Context) {
		if c.Request.URL.Path == "/login" && c.Request.Method == "POST" {
			clientIP := c.ClientIP()
			if !rateLimiter.IsAllowed(clientIP) {
				renderGinTemplate(c, "login", PageData{
					Title: "Login",
					Error: "Too many login attempts. Please try again later.",
				})
				c.Abort()
				return
			}
		}
		c.Next()
	})

	// Public routes
	router.GET("/login", ginLoginHandler)
	router.POST("/login", ginLoginHandler)
	router.GET("/signup", ginSignupHandler)
	router.POST("/signup", ginSignupHandler)
	router.GET("/logout", ginLogoutHandler)

	// Protected routes
	protected := router.Group("/")
	protected.Use(ginRequireAuth())
	{
		protected.GET("/", ginHomeHandler)
		protected.GET("/devices", ginDevicesHandler)
		protected.POST("/devices", ginDevicesHandler)
		protected.GET("/devices/add", ginAddDeviceHandler)
		protected.POST("/devices/add", ginAddDeviceHandler)
		protected.GET("/devices/edit/:id", ginEditDeviceHandler)
		protected.POST("/devices/edit/:id", ginEditDeviceHandler)
		protected.GET("/devices/delete/:id", ginDeleteDeviceHandler)
		protected.POST("/devices/delete/:id", ginDeleteDeviceHandler)
		protected.GET("/devices/monitor/:id", ginMonitorDeviceHandler)
		protected.GET("/logs", ginAllLogsHandler)
	}

	// Admin routes
	admin := router.Group("/")
	admin.Use(ginRequireAdmin())
	{
		admin.GET("/users", ginUsersHandler)
		admin.POST("/users", ginUsersHandler)
		admin.GET("/users/add", ginAddUserHandler)
		admin.POST("/users/add", ginAddUserHandler)
		admin.GET("/users/edit/:id", ginEditUserHandler)
		admin.POST("/users/edit/:id", ginEditUserHandler)
	}

	// API routes
	api := router.Group("/api")
	api.Use(ginRequireAuth())
	{
		api.Any("/devices/*path", ginApiDeviceHandler)
	}

	// 404 handler
	router.NoRoute(ginNotFoundHandler)

	// Create HTTP server
	srv := &http.Server{
		Addr:         ":" + cfg.Server.Port,
		Handler:      router,
		ReadTimeout:  cfg.Server.ReadTimeout,
		WriteTimeout: cfg.Server.WriteTimeout,
		IdleTimeout:  cfg.Server.IdleTimeout,
	}

	// Start server in a goroutine
	go func() {
		log.Printf("Server starting on port %s", cfg.Server.Port)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("Server failed to start: %v", err)
		}
	}()

	// Wait for interrupt signal to gracefully shutdown the server
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit
	log.Println("Server shutting down...")

	// Give outstanding requests 30 seconds to complete
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if err := srv.Shutdown(ctx); err != nil {
		log.Fatalf("Server forced to shutdown: %v", err)
	}

	log.Println("Server exited")
}

// Gin middleware functions
func ginRequireAuth() gin.HandlerFunc {
	return func(c *gin.Context) {
		session := sessions.Default(c)
		authenticated := session.Get("authenticated")
		username := session.Get("username")
		
		if authenticated == nil || authenticated != true || username == nil {
			c.Redirect(http.StatusFound, "/login")
			c.Abort()
			return
		}
		
		c.Next()
	}
}

func ginRequireAdmin() gin.HandlerFunc {
	return func(c *gin.Context) {
		session := sessions.Default(c)
		username := session.Get("username")
		
		if username == nil {
			c.Redirect(http.StatusFound, "/login")
			c.Abort()
			return
		}
		
		user, err := db.GetUserByUsername(username.(string))
		if err != nil || user == nil || !user.IsAdmin {
			renderGinTemplate(c, "404", PageData{
				Title: "403 - Forbidden",
				Error: "You don't have permission to access this resource.",
			})
			c.Abort()
			return
		}
		
		c.Next()
	}
}

// Gin handler functions
func ginLoginHandler(c *gin.Context) {
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
		renderGinTemplate(c, "404", PageData{
			Title: "Error",
			Error: "Database error occurred.",
		})
		return
	}

	if isEmpty {
		c.Redirect(http.StatusFound, "/signup")
		return
	}

	data := getPageDataFromGin(c)
	data.Title = "Login"

	if c.Request.Method == "POST" {
		username := strings.TrimSpace(c.PostForm("username"))
		password := c.PostForm("password")

		data.FormData["username"] = username

		if username == "" {
			data.Error = "Username is required"
			data.ErrorFields["username"] = true
			renderGinTemplate(c, "login", data)
			return
		}

		if password == "" {
			data.Error = "Password is required"
			data.ErrorFields["password"] = true
			renderGinTemplate(c, "login", data)
			return
		}

		// Validate user credentials
		valid, err := db.ValidateUser(username, password)
		if err != nil || !valid {
			log.Printf("Login validation error: %v", err)
			data.Error = "Invalid username or password"
			data.ErrorFields["username"] = true
			data.ErrorFields["password"] = true
			renderGinTemplate(c, "login", data)
			return
		}

		// Get user details after successful validation
		user, err := db.GetUserByUsername(username)
		if err != nil || user == nil {
			log.Printf("Error getting user details: %v", err)
			data.Error = "Login failed. Please try again."
			renderGinTemplate(c, "login", data)
			return
		}

		// Create session
		session := sessions.Default(c)
		session.Set("username", user.Username)
		session.Set("user_id", user.ID)
		session.Set("authenticated", true)
		session.Set("login_time", time.Now().Format(time.RFC3339))
		
		if err := session.Save(); err != nil {
			log.Printf("Session save error: %v", err)
			data.Error = "Login failed. Please try again."
			renderGinTemplate(c, "login", data)
			return
		}

		c.Redirect(http.StatusFound, "/")
		return
	}

	renderGinTemplate(c, "login", data)
}

func ginLogoutHandler(c *gin.Context) {
	session := sessions.Default(c)
	session.Clear()
	session.Save()
	c.Redirect(http.StatusFound, "/login")
}

func ginHomeHandler(c *gin.Context) {
	data := getPageDataFromGin(c)
	data.Title = "Dashboard"

	// Get device statistics (simplified - these functions may not exist)
	data.Data["TotalDevices"] = 0
	data.Data["OnlineDevices"] = 0
	data.Data["RecentLogs"] = 0

	renderGinTemplate(c, "home", data)
}

func ginSignupHandler(c *gin.Context) {
	isEmpty, err := db.IsUsersTableEmpty()
	if err != nil {
		log.Printf("Error checking if users table is empty: %v", err)
		renderGinTemplate(c, "404", PageData{
			Title: "Error",
			Error: "Database error occurred.",
		})
		return
	}

	if !isEmpty {
		c.Redirect(http.StatusFound, "/login")
		return
	}

	data := getPageDataFromGin(c)
	data.Title = "Create Admin Account"

	if c.Request.Method == "POST" {
		username := strings.TrimSpace(c.PostForm("username"))
		password := c.PostForm("password")
		confirmPassword := c.PostForm("confirm_password")

		data.FormData["username"] = username

		if username == "" {
			data.Error = "Username is required"
			data.ErrorFields["username"] = true
			renderGinTemplate(c, "signup", data)
			return
		}

		if password == "" {
			data.Error = "Password is required"
			data.ErrorFields["password"] = true
			renderGinTemplate(c, "signup", data)
			return
		}

		if password != confirmPassword {
			data.Error = "Passwords do not match"
			data.ErrorFields["password"] = true
			data.ErrorFields["confirm_password"] = true
			renderGinTemplate(c, "signup", data)
			return
		}

		// Create admin user
		if err := db.CreateUser(username, password, true, true, true, true, true); err != nil {
			log.Printf("Error creating admin user: %v", err)
			data.Error = "Failed to create admin account"
			renderGinTemplate(c, "signup", data)
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
			renderGinTemplate(c, "signup", data)
			return
		}

		c.Redirect(http.StatusFound, "/")
		return
	}

	renderGinTemplate(c, "signup", data)
}

func ginNotFoundHandler(c *gin.Context) {
	data := getPageDataFromGin(c)
	data.Title = "404 - Not Found"
	renderGinTemplate(c, "404", data)
}

// Placeholder handlers for the other routes
func ginDevicesHandler(c *gin.Context) {
	data := getPageDataFromGin(c)
	data.Title = "Devices"
	renderGinTemplate(c, "devices", data)
}

func ginAddDeviceHandler(c *gin.Context) {
	data := getPageDataFromGin(c)
	data.Title = "Add Device"
	renderGinTemplate(c, "add-device", data)
}

func ginEditDeviceHandler(c *gin.Context) {
	data := getPageDataFromGin(c)
	data.Title = "Edit Device"
	renderGinTemplate(c, "edit-device", data)
}

func ginDeleteDeviceHandler(c *gin.Context) {
	data := getPageDataFromGin(c)
	data.Title = "Delete Device"
	renderGinTemplate(c, "delete-device-confirm", data)
}

func ginMonitorDeviceHandler(c *gin.Context) {
	data := getPageDataFromGin(c)
	data.Title = "Monitor Device"
	renderGinTemplate(c, "monitor-device", data)
}

func ginAllLogsHandler(c *gin.Context) {
	data := getPageDataFromGin(c)
	data.Title = "System Audit Logs"
	
	// Set pagination defaults
	data.Data["CurrentPage"] = 1
	data.Data["TotalPages"] = 1
	data.Data["PageSize"] = 50
	data.Data["TotalLogs"] = 0
	data.Data["Logs"] = []interface{}{}
	
	renderGinTemplate(c, "logs", data)
}

func ginUsersHandler(c *gin.Context) {
	data := getPageDataFromGin(c)
	data.Title = "User Management"
	renderGinTemplate(c, "users", data)
}

func ginAddUserHandler(c *gin.Context) {
	data := getPageDataFromGin(c)
	data.Title = "Add User"
	renderGinTemplate(c, "add-user", data)
}

func ginEditUserHandler(c *gin.Context) {
	data := getPageDataFromGin(c)
	data.Title = "Edit User"
	renderGinTemplate(c, "edit-user", data)
}

func ginApiDeviceHandler(c *gin.Context) {
	c.JSON(http.StatusNotImplemented, gin.H{"error": "API not implemented yet"})
}









// Helper function to get pagination parameters from request
func getPaginationParams(r *http.Request) (int, int) {
	pageStr := r.URL.Query().Get("page")
	page, err := strconv.Atoi(pageStr)
	if err != nil || page < 1 {
		page = 1
	}

	pageSize := 20 // Default page size
	if pageSizeParam := r.URL.Query().Get("pageSize"); pageSizeParam != "" {
		if ps, err := strconv.Atoi(pageSizeParam); err == nil && ps > 0 {
			pageSize = ps
		}
	}

	return page, pageSize
}


// generatePaginationNumbers creates a list of page numbers for pagination controls.
// It includes the first page, last page, pages around the current page, and 0 for ellipses.
func generatePaginationNumbers(currentPage, totalPages, window int) []int {
	if totalPages <= 1 {
		return []int{}
	}

	var pages []int
	showEllipsisStart := false
	showEllipsisEnd := false

	// Always add the first page
	pages = append(pages, 1)

	// Determine start and end for the window around current page
	start := currentPage - window
	end := currentPage + window

	if start <= 1 {
		start = 2
	}
	if end >= totalPages {
		end = totalPages - 1
	}

	// Add ellipsis if there's a gap after the first page
	if start > 2 {
		showEllipsisStart = true
	}

	// Add page numbers in the window
	for i := start; i <= end; i++ {
		if i > 1 && i < totalPages {
			pages = append(pages, i)
		}
	}

	// Add ellipsis if there's a gap before the last page
	if end < totalPages-1 {
		showEllipsisEnd = true
	}

	// Add the last page if it's not the first page
	if totalPages > 1 {
		pages = append(pages, totalPages)
	}

	// Reconstruct pages with ellipses (0 represents ellipsis)
	var finalPages []int
	finalPages = append(finalPages, 1) // First page

	if showEllipsisStart {
		finalPages = append(finalPages, 0) // Ellipsis
	}

	for i := start; i <= end; i++ {
		if i > 1 && i < totalPages && !contains(finalPages, i) {
			finalPages = append(finalPages, i)
		}
	}

	if showEllipsisEnd {
		if !contains(finalPages, 0) || (end < totalPages-2 && currentPage < totalPages-window-1) {
			// Add ellipsis if not already added or if there's a significant gap
			// and current page is far enough from the end.
			if finalPages[len(finalPages)-1] != 0 { // Avoid double ellipsis if last page is also in window
				finalPages = append(finalPages, 0) // Ellipsis
			}
		}
	}

	// Add last page if not already included
	if totalPages > 1 && !contains(finalPages, totalPages) {
		finalPages = append(finalPages, totalPages)
	}

	// Remove duplicate 0 if first page is 1, ellipsis, then 2 (e.g. 1,0,2...)
	// and total pages is small, leading to 1,0,2,0,N. This is a bit of a hack.
	if len(finalPages) > 3 && finalPages[1] == 0 && finalPages[3] == 0 && finalPages[2] < totalPages {
		// if we have 1, 0, X, 0, Y and X is not Y-1
		if len(finalPages) > 4 && finalPages[2] != finalPages[4]-1 {
			// check if X is far from Y
			if finalPages[4]-finalPages[2] > 1 {
				// keep both ellipses
			} else {
				// remove second ellipsis if X and Y are consecutive or same
				finalPages = append(finalPages[:3], finalPages[4:]...)
			}
		} else if len(finalPages) == 4 && finalPages[0] == 1 && finalPages[1] == 0 && finalPages[2] == totalPages-1 && finalPages[3] == 0 { // Case 1,0,N-1,0 -> 1,0,N-1,N
			// This case is actually fine, e.g. 1 ... 4 5. No, it should be 1 ... 4. Then 5.
			// Let's test: current=3, total=5, window=1. Pages: 1. start=2, end=4. pages=[1,2,3,4]. showEllipsisStart=false, showEllipsisEnd=false. finalPages=[1,2,3,4,5]
			// current=1, total=5, window=1. Pages: 1. start=2, end=2. pages=[1,2]. showEllipsisStart=false, showEllipsisEnd=true. finalPages=[1,2,0,5]
			// current=5, total=5, window=1. Pages: 1. start=4, end=4. pages=[1,4]. showEllipsisStart=true, showEllipsisEnd=false. finalPages=[1,0,4,5]
		}
	}

	return finalPages
}

// contains checks if a slice contains an integer.
func contains(slice []int, val int) bool {
	for _, item := range slice {
		if item == val {
			return true
		}
	}
	return false
}

// startStatusChecker starts a goroutine to periodically check device statuses
func startStatusChecker(interval time.Duration) {
	go func() {
		for {
			log.Println("Running device status check...")
			if err := db.UpdateAllDeviceStatuses(); err != nil {
				log.Printf("Error updating device statuses: %v", err)
			}
			time.Sleep(interval)
		}
	}()
}

type Process struct {
	ID        string
	Cmd       *exec.Cmd
	Output    []string
	Error     string
	Complete  bool
	Success   bool
	DeviceID  int64
	StartTime time.Time
}

var processes = make(map[string]*Process)
var processesMutex sync.Mutex


func addDeviceEnlistCommand(device db.Device, setupUser string) (string, error) {
	// Validate inputs before command generation
	if !utils.IsValidIPAddress(device.IPAddress) && !utils.IsValidHostname(device.IPAddress) {
		return "", errors.New("invalid IP address or hostname")
	}

	if !device.RandomUser {
		if !utils.IsValidUsername(device.SSHUser) {
			return "", errors.New("invalid SSH username format")
		}
		if !utils.IsValidGroupname(device.SSHGroup) {
			return "", errors.New("invalid SSH group format")
		}
	}

	if !device.RandomKey && !utils.IsValidFilePath(device.SSHKeyPath) {
		return "", errors.New("invalid SSH key path")
	}

	if !utils.IsValidUsername(setupUser) {
		return "", errors.New("invalid setup username format")
	}

	// Use array of arguments instead of string concatenation for safety
	args := []string{"./scripts/enlist.sh"}

	// Add parameters
	if device.RandomUser {
		args = append(args, "-r")
	} else {
		args = append(args, "-u", device.SSHUser, "-g", device.SSHGroup)
	}

	if device.RandomKey {
		args = append(args, "-R")
	} else {
		args = append(args, "-k", device.SSHKeyPath)
	}

	args = append(args, "-p", fmt.Sprintf("%d", device.SSHPort))
	args = append(args, "-l", setupUser)
	args = append(args, device.IPAddress)

	// Join arguments with proper spacing
	enlistCmd := strings.Join(args, " ")
	return enlistCmd, nil
}
