package main

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"html/template"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
	"unicode"

	"github.com/gorilla/sessions"
	"github.com/joho/godotenv"

	"example/go-website/db"
	"example/go-website/middleware"
	"example/go-website/utils"
)

type PageData struct {
	Title          string
	Error          string
	Success        string
	Content        string
	Username       string
	UserID         int64
	IsAdmin        bool
	Users          []db.User
	Devices        []db.Device
	User           *db.User
	Device         db.Device
	RandomUser     bool
	RandomKey      bool
	FormToken      string
	FormData       map[string]string
	ErrorFields    map[string]bool
	MonitoringData map[string]string
	Data           map[string]interface{}
}

// getPageData creates a PageData struct with common fields populated
func getPageData(w http.ResponseWriter, r *http.Request) PageData {
	if store == nil {
		log.Printf("Session store is not initialized")
		return PageData{}
	}

	session, err := store.Get(r, "session-name")
	if err != nil {
		log.Printf("Error getting session in getPageData: %v", err)
		return PageData{}
	}

	// Get username from session
	username, ok := session.Values["username"].(string)
	if !ok {
		return PageData{}
	}

	// Get user from database to check admin status
	var isAdmin bool
	var userID int64
	if username != "" {
		user, err := db.GetUserByUsername(username)
		if err != nil {
			log.Printf("Error getting user: %v", err)
			return PageData{}
		}
		if user != nil {
			isAdmin = user.IsAdmin
			userID = user.ID
		}
	}

	return PageData{
		Username: username,
		UserID:   userID,
		IsAdmin:  isAdmin,
	}
}

// generateSecretKey generates a random 32-byte key
func generateSecretKey() []byte {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		log.Fatalf("Failed to generate secret key: %v", err)
	}
	return key
}

// generateFormToken creates a unique token for form submission
func generateFormToken() string {
	// Generate a random token
	b := make([]byte, 16)
	rand.Read(b)
	return fmt.Sprintf("%x-%d", b, time.Now().UnixNano())
}

// validateFormToken checks if the token is valid and hasn't been used before
func validateFormToken(r *http.Request, token string) bool {
	if token == "" {
		return false
	}

	session, _ := store.Get(r, "session-name")

	// Check if this token has been used before
	usedTokens, ok := session.Values["used_tokens"].(map[string]bool)
	if !ok {
		usedTokens = make(map[string]bool)
	}

	if usedTokens[token] {
		// Token has been used before
		return false
	}

	// Mark token as used
	usedTokens[token] = true
	session.Values["used_tokens"] = usedTokens

	return true
}

// Create a new session store with a secure key
var store *sessions.CookieStore
var loginLimiter *middleware.RateLimiter

func init() {
	// Load environment variables from .env file
	err := godotenv.Load()
	if err != nil {
		log.Printf("Warning: Error loading .env file: %v", err)
		// Continue execution even if .env file is missing
	}

	// Get session key from environment variable or generate a secure one
	var key []byte
	sessionSecret := os.Getenv("SESSION_SECRET")
	if sessionSecret != "" {
		key = []byte(sessionSecret)
		log.Println("Using session key from environment variable")
	} else {
		// If no environment variable is set, generate a random key
		key = generateSecretKey()
		log.Println("Generated random session key")
	}

	store = sessions.NewCookieStore(key)
	if store == nil {
		log.Fatal("Failed to create session store")
	}

	// Determine if we're in production mode
	isProduction := os.Getenv("GO_ENV") == "production"

	// Set secure cookie options
	store.Options = &sessions.Options{
		Path:     "/",
		MaxAge:   86400 * 7,    // 7 days
		HttpOnly: true,         // Prevent JavaScript access
		Secure:   isProduction, // Set to true in production with HTTPS
		SameSite: http.SameSiteStrictMode,
	}

	// Initialize rate limiter: 5 attempts per 15 minutes, block for 30 minutes after max attempts
	loginLimiter = middleware.NewRateLimiter(5, 15*time.Minute, 30*time.Minute)
}

// sessionMiddleware ensures consistent session handling
func sessionMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if store == nil {
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}

		// Try to get session
		session, err := store.Get(r, "session-name")
		if err != nil {
			log.Printf("Error getting session: %v", err)
			// Clear any invalid session cookie
			c := &http.Cookie{
				Name:     "session-name",
				Value:    "",
				Path:     "/",
				MaxAge:   -1,
				HttpOnly: true,
			}
			http.SetCookie(w, c)
			// Also try to clear through session store
			if session != nil {
				session.Options.MaxAge = -1
				if err := session.Save(r, w); err != nil {
					log.Printf("Error saving cleared session: %v", err)
				}
			}
			// Create a new session
			session, err = store.New(r, "session-name")
			if err != nil {
				log.Printf("Error creating new session: %v", err)
				http.Error(w, "Internal server error", http.StatusInternalServerError)
				return
			}
		}

		// Store the session in the request context
		ctx := context.WithValue(r.Context(), "session", session)
		next(w, r.WithContext(ctx))
	}
}

// getClientIP extracts the client IP from the request
func getClientIP(r *http.Request) string {
	// Check for X-Forwarded-For header first (for proxies)
	ip := r.Header.Get("X-Forwarded-For")
	if ip != "" {
		return ip
	}

	// Otherwise use RemoteAddr
	ip = r.RemoteAddr
	// Strip port if present
	if i := strings.LastIndex(ip, ":"); i != -1 {
		ip = ip[:i]
	}
	return ip
}

func loginHandler(w http.ResponseWriter, r *http.Request) {
	// Initialize basic page data
	data := PageData{
		Title: "Login",
		Data:  make(map[string]interface{}),
	}

	// Get client IP for rate limiting
	ip := getClientIP(r)

	// Check if the IP is allowed to make login attempts
	if !loginLimiter.IsAllowed(ip) {
		// IP is rate limited - show block message with time until unblock
		timeLeft := loginLimiter.TimeUntilUnblock(ip)
		data.Error = fmt.Sprintf("Too many login attempts. Your IP has been temporarily blocked. Please try again in %d minutes.", int(timeLeft.Minutes()))
		renderTemplate(w, "login", data)
		return
	}

	// Check if users table is empty
	isEmpty, err := db.IsUsersTableEmpty()
	if err != nil {
		log.Printf("Error checking users table: %v", err)
		data.Error = "Database error occurred. Please try again."
		renderTemplate(w, "login", data)
		return
	}

	// If table is empty, redirect to signup
	if isEmpty {
		http.Redirect(w, r, "/signup", http.StatusSeeOther)
		return
	}

	// Handle login form submission
	if r.Method == "POST" {
		// Check if this is a logout request
		if r.FormValue("action") == "logout" {
			if session, err := store.Get(r, "session-name"); err == nil {
				session.Options.MaxAge = -1 // Delete the session
				session.Save(r, w)
			}
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}

		username := r.FormValue("username")
		password := r.FormValue("password")

		if username == "" || password == "" {
			data.Error = "Username and password are required"
			// Don't record empty submissions as attempts
			// But show remaining attempts as a warning
			data.Data["RemainingAttempts"] = loginLimiter.GetRemainingAttempts(ip)
			data.Data["ShowRemainingAttempts"] = true
			renderTemplate(w, "login", data)
			return
		}

		// Validate user credentials
		valid, err := db.ValidateUser(username, password)
		if err != nil {
			log.Printf("Login error: %v", err)
			data.Error = "An error occurred during login"
			// Don't count system errors as failed attempts
			renderTemplate(w, "login", data)
			return
		}

		if valid {
			// Successful login - create new session
			session, _ := store.Get(r, "session-name")
			session.Values["authenticated"] = true
			session.Values["username"] = username
			if err := session.Save(r, w); err != nil {
				log.Printf("Session save error: %v", err)
				data.Error = "An error occurred during login"
				renderTemplate(w, "login", data)
				return
			}

			http.Redirect(w, r, "/", http.StatusSeeOther)
			return
		}

		// Failed login - only now record the attempt
		loginLimiter.RecordAttempt(ip)
		data.Error = "Invalid username or password"

		// Show remaining attempts after a failed login
		data.Data["RemainingAttempts"] = loginLimiter.GetRemainingAttempts(ip)
		data.Data["ShowRemainingAttempts"] = true

		// Check if this attempt exceeded the limit
		if !loginLimiter.IsAllowed(ip) {
			timeLeft := loginLimiter.TimeUntilUnblock(ip)
			data.Error = fmt.Sprintf("Too many failed login attempts. Your IP has been temporarily blocked. Please try again in %d minutes.", int(timeLeft.Minutes()))
		}

		renderTemplate(w, "login", data)
		return
	}

	// Display login form (initial load)
	renderTemplate(w, "login", data)
}

func main() {
	// Initialize database
	if err := db.InitDB(); err != nil {
		log.Fatal(err)
	}
	defer db.Close()

	// Start a background status checker
	startStatusChecker(5 * time.Minute)

	// Handle graceful shutdown
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-c
		log.Println("Shutting down...")
		if err := db.Close(); err != nil {
			log.Printf("Error closing database: %v", err)
		}
		os.Exit(0)
	}()

	// Create file server
	fs := http.FileServer(http.Dir("static"))

	// Create router
	mux := http.NewServeMux()
	mux.Handle("/static/", http.StripPrefix("/static/", fs))

	// Routes with session middleware
	mux.HandleFunc("/", sessionMiddleware(homeHandler))
	// Apply rate limiting to login handler
	// Note: We're not using the middleware here because we've integrated the rate limiting directly in the handler
	mux.HandleFunc("/login", loginHandler)
	mux.HandleFunc("/signup", sessionMiddleware(signupHandler))
	mux.HandleFunc("/users", sessionMiddleware(adminOnly(usersHandler)))
	mux.HandleFunc("/users/edit", sessionMiddleware(adminOnly(editUserHandler)))
	mux.HandleFunc("/users/add", sessionMiddleware(adminOnly(addUserHandler)))
	mux.HandleFunc("/devices", sessionMiddleware(authRequired(devicesHandler)))
	mux.HandleFunc("/devices/add", sessionMiddleware(authRequired(addDeviceHandler)))
	mux.HandleFunc("/devices/edit/", sessionMiddleware(authRequired(editDeviceHandler)))
	mux.HandleFunc("/devices/delete/", sessionMiddleware(authRequired(deleteDeviceHandler)))
	mux.HandleFunc("/devices/monitor/", sessionMiddleware(authRequired(monitorDeviceHandler)))

	// API routes
	mux.HandleFunc("/api/devices/", apiDeviceHandler)

	// Serve static files

	// Apply security headers middleware to all routes
	secureHandler := middleware.SecurityHeaders(mux)

	// Starts the server
	log.Println("Server starting on http://localhost:8080")
	log.Fatal(http.ListenAndServe(":8080", secureHandler))
}

// authRequired middleware ensures only authenticated users can access certain routes
func authRequired(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		session, _ := store.Get(r, "session-name")

		// Check if user is authenticated
		auth, ok := session.Values["authenticated"].(bool)
		_, hasUser := session.Values["username"].(string)
		if !ok || !auth || !hasUser {
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}

		next(w, r)
	}
}

// adminOnly middleware ensures only admin users can access certain routes
func adminOnly(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		session, _ := store.Get(r, "session-name")

		// Check if user is authenticated and is admin
		auth, ok := session.Values["authenticated"].(bool)
		username, hasUser := session.Values["username"].(string)
		if !ok || !auth || !hasUser {
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}

		// Check if user is admin
		user, err := db.GetUserByUsername(username)
		if err != nil || !user.IsAdmin {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		next(w, r)
	}
}

func usersHandler(w http.ResponseWriter, r *http.Request) {
	data := getPageData(w, r)
	data.Title = "User Management"

	switch r.Method {
	case "POST":
		action := r.FormValue("action")
		switch action {
		case "create":
			username := r.FormValue("username")
			password := r.FormValue("password")
			isAdmin := r.FormValue("isAdmin") == "on"
			canAddDevices := r.FormValue("canAddDevices") == "on"
			canModifyDevices := r.FormValue("canModifyDevices") == "on"
			canAddUsers := r.FormValue("canAddUsers") == "on"
			canModifyUsers := r.FormValue("canModifyUsers") == "on"

			if username == "" || password == "" {
				data.Error = "Username and password are required"
				break
			}

			// Admin users get all permissions by default
			if isAdmin {
				canAddDevices = true
				canModifyDevices = true
				canAddUsers = true
				canModifyUsers = true
			}

			if err := db.CreateUser(username, password, isAdmin, canAddDevices, canModifyDevices, canAddUsers, canModifyUsers); err != nil {
				data.Error = "Failed to create user"
				break
			}

			if isAdmin {
				user, err := db.GetUserByUsername(username)
				if err != nil {
					data.Error = "User created but failed to set admin status"
					break
				}
				if err := db.UpdateUser(user.ID, username, true, true, true, true, true); err != nil {
					data.Error = "User created but failed to set admin status"
					break
				}
			}
			data.Success = "User created successfully"

		case "edit":
			userID, err := strconv.ParseInt(r.FormValue("userId"), 10, 64)
			if err != nil {
				data.Error = "Invalid user ID"
				break
			}

			username := r.FormValue("username")
			password := r.FormValue("password")
			isAdmin := r.FormValue("isAdmin") == "on"

			if username == "" {
				data.Error = "Username is required"
				break
			}

			// Get the current permission values to preserve them if not explicitly changed
			existingUser, err := db.GetUserByID(userID)
			if err != nil {
				data.Error = "Failed to get user information"
				break
			}

			// Check if this is the last admin and they're trying to remove admin rights
			if existingUser.IsAdmin && !isAdmin {
				// Count total admins
				allUsers, err := db.GetAllUsers()
				if err != nil {
					data.Error = "Failed to verify admin count"
					break
				}

				adminCount := 0
				for _, u := range allUsers {
					if u.IsAdmin {
						adminCount++
					}
				}

				// If this is the last admin, prevent removing admin rights
				if adminCount <= 1 {
					data.Error = "Cannot remove admin rights from the last admin user"
					break
				}
			}

			// Get form values for new permissions
			// If form values aren't provided, use existing permissions
			canAddDevices := r.FormValue("canAddDevices") == "on"
			if r.FormValue("canAddDevices") == "" && existingUser != nil {
				canAddDevices = existingUser.CanAddDevices
			}

			canModifyDevices := r.FormValue("canModifyDevices") == "on"
			if r.FormValue("canModifyDevices") == "" && existingUser != nil {
				canModifyDevices = existingUser.CanModifyDevices
			}

			canAddUsers := r.FormValue("canAddUsers") == "on"
			if r.FormValue("canAddUsers") == "" && existingUser != nil {
				canAddUsers = existingUser.CanAddUsers
			}

			canModifyUsers := r.FormValue("canModifyUsers") == "on"
			if r.FormValue("canModifyUsers") == "" && existingUser != nil {
				canModifyUsers = existingUser.CanModifyUsers
			}

			// Admin users automatically get all permissions
			if isAdmin {
				canAddDevices = true
				canModifyDevices = true
				canAddUsers = true
				canModifyUsers = true
			}

			if err := db.UpdateUser(userID, username, isAdmin, canAddDevices, canModifyDevices, canAddUsers, canModifyUsers); err != nil {
				data.Error = "Failed to update user"
				break
			}

			if password != "" {
				if err := db.UpdateUserPassword(userID, password); err != nil {
					data.Error = "Failed to update password"
					break
				}
			}
			data.Success = "User updated successfully"
			http.Redirect(w, r, "/users", http.StatusSeeOther)
			return

		case "delete":
			userID, err := strconv.ParseInt(r.FormValue("userId"), 10, 64)
			if err != nil {
				data.Error = "Invalid user ID"
				break
			}

			// Get current user's ID for self-deletion prevention
			currentUser, err := db.GetUserByUsername(data.Username)
			if err != nil {
				data.Error = "Failed to verify current user"
				break
			}

			if err := db.DeleteUser(userID, currentUser.ID); err != nil {
				data.Error = err.Error()
				break
			}
			data.Success = "User deleted successfully"
		}
	}

	// Get updated list of users
	users, err := db.GetAllUsers()
	if err != nil {
		data.Error = "Failed to load users"
	}
	data.Users = users

	renderTemplate(w, "users", data)
}

func homeHandler(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		notFoundHandler(w, r)
		return
	}

	// Check if user is authenticated
	session, _ := store.Get(r, "session-name")
	auth, ok := session.Values["authenticated"].(bool)
	if !ok || !auth {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}

	data := getPageData(w, r)
	data.Title = "Home"
	data.Content = "Welcome to our Go Web Application!"
	renderTemplate(w, "home", data)
}

func signupHandler(w http.ResponseWriter, r *http.Request) {
	// Check if users table is empty
	isEmpty, err := db.IsUsersTableEmpty()
	if err != nil {
		log.Printf("Error checking users table: %v", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	// If table is not empty, redirect to login
	if !isEmpty {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}

	data := getPageData(w, r)
	data.Title = "Create Admin Account"

	switch r.Method {
	case "POST":
		username := r.FormValue("username")
		password := r.FormValue("password")
		confirmPassword := r.FormValue("confirm_password")

		// Validate input
		if username == "" || password == "" {
			data.Error = "Username and password are required"
			renderTemplate(w, "signup", data)
			return
		}

		if password != confirmPassword {
			data.Error = "Passwords do not match"
			renderTemplate(w, "signup", data)
			return
		}

		// Validate password requirements
		if err := validatePassword(password); err != nil {
			data.Error = err.Error()
			renderTemplate(w, "signup", data)
			return
		}

		// Create the user - first user is always admin with all permissions
		if err := db.CreateUser(username, password, true, true, true, true, true); err != nil {
			data.Error = "Failed to create user"
			renderTemplate(w, "signup", data)
			return
		}

		// Since we verified the table is empty, this is the first user
		// Make them an admin
		user, err := db.GetUserByUsername(username)
		if err != nil {
			log.Printf("Error getting new user: %v", err)
		} else {
			if err := db.UpdateUser(user.ID, username, true, true, true, true, true); err != nil {
				log.Printf("Error setting admin status: %v", err)
			}
		}

		// Create a new session
		session, err := store.Get(r, "session-name")
		if err != nil {
			data.Error = "Error creating session"
			renderTemplate(w, "signup", data)
			return
		}

		session.Values["username"] = username
		if err := session.Save(r, w); err != nil {
			data.Error = "Error saving session"
			renderTemplate(w, "signup", data)
			return
		}

		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}

	renderTemplate(w, "signup", data)
}

func notFoundHandler(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusNotFound)
	data := getPageData(w, r)
	data.Title = "404 - Not Found"
	data.Content = "The page you're looking for doesn't exist."
	renderTemplate(w, "404", data)
}

func renderTemplate(w http.ResponseWriter, tmpl string, data PageData) {
	// Add template functions
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
	}

	// First, try to parse both the layout and the specific template
	t, err := template.New("layout.html").Funcs(funcMap).ParseFiles(
		"templates/layout.html",
		fmt.Sprintf("templates/%s.html", tmpl),
	)
	if err != nil {
		log.Printf("Template parsing error: %v", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	// Execute the template
	if err := t.ExecuteTemplate(w, "layout", data); err != nil {
		log.Printf("Template execution error: %v", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
}

func validatePassword(password string) error {
	var (
		hasUpper   bool
		hasLower   bool
		hasNumber  bool
		hasSpecial bool
		length     int = 12
	)

	if len(password) < length {
		return fmt.Errorf("password must be at least %d characters long", length)
	}

	for _, char := range password {
		switch {
		case unicode.IsUpper(char):
			hasUpper = true
		case unicode.IsLower(char):
			hasLower = true
		case unicode.IsNumber(char):
			hasNumber = true
		case unicode.IsPunct(char) || unicode.IsSymbol(char):
			hasSpecial = true
		}
	}

	var missing []string
	if !hasUpper {
		missing = append(missing, "an uppercase letter")
	}
	if !hasLower {
		missing = append(missing, "a lowercase letter")
	}
	if !hasNumber {
		missing = append(missing, "a number")
	}
	if !hasSpecial {
		missing = append(missing, "a special character")
	}

	if len(missing) > 0 {
		if len(missing) == 1 {
			return fmt.Errorf("password must contain %s", missing[0])
		}
		last := missing[len(missing)-1]
		rest := missing[:len(missing)-1]
		requirements := strings.Join(rest, ", ") + " and " + last
		return fmt.Errorf("password must contain %s", requirements)
	}

	return nil
}

func devicesHandler(w http.ResponseWriter, r *http.Request) {
	data := getPageData(w, r)
	data.Title = "Devices"

	// Check for flashed messages
	session, _ := store.Get(r, "session-name")
	if flashes := session.Flashes("success"); len(flashes) > 0 {
		data.Success = flashes[0].(string)
		session.Save(r, w)
	}

	// Get all devices
	devices, err := db.GetAllDevices()
	if err != nil {
		log.Printf("Error getting devices: %v", err)
		data.Error = "Failed to load devices"
		renderTemplate(w, "devices", data)
		return
	}
	data.Devices = devices

	switch r.Method {
	case "POST":
		action := r.FormValue("action")
		switch action {
		case "create":
			name := r.FormValue("name")
			deviceType := r.FormValue("type")

			if name == "" || deviceType == "" {
				data.Error = "Name and type are required"
				break
			}

			if err := db.CreateDevice(name, deviceType); err != nil {
				log.Printf("Error creating device: %v", err)
				data.Error = "Failed to create device"
				break
			}

			data.Success = "Device created successfully"

		case "edit":
			deviceID, err := strconv.ParseInt(r.FormValue("deviceId"), 10, 64)
			if err != nil {
				data.Error = "Invalid device ID"
				break
			}

			name := r.FormValue("name")
			deviceType := r.FormValue("type")
			status := r.FormValue("status")

			if name == "" || deviceType == "" || status == "" {
				data.Error = "All fields are required"
				break
			}

			if err := db.UpdateDevice(deviceID, name, deviceType, status); err != nil {
				log.Printf("Error updating device: %v", err)
				data.Error = "Failed to update device"
				break
			}

			data.Success = "Device updated successfully"

		case "delete":
			deviceID, err := strconv.ParseInt(r.FormValue("deviceId"), 10, 64)
			if err != nil {
				data.Error = "Invalid device ID"
				break
			}

			if err := db.DeleteDevice(deviceID); err != nil {
				log.Printf("Error deleting device: %v", err)
				data.Error = "Failed to delete device"
				break
			}

			data.Success = "Device deleted successfully"
		}

		// Refresh device list after any action
		devices, err := db.GetAllDevices()
		if err != nil {
			log.Printf("Error getting devices: %v", err)
			data.Error = "Failed to load devices"
		}
		data.Devices = devices
	}

	renderTemplate(w, "devices", data)
}

func editUserHandler(w http.ResponseWriter, r *http.Request) {
	data := getPageData(w, r)
	data.Title = "Edit User"

	// Get user ID from query parameter or use current user's ID
	userIDStr := r.URL.Query().Get("id")
	var userID int64

	if userIDStr == "" {
		// If no ID provided, use the current user's ID
		userID = data.UserID
	} else {
		// If ID is provided, parse it
		var err error
		userID, err = strconv.ParseInt(userIDStr, 10, 64)
		if err != nil {
			http.Error(w, "Invalid user ID", http.StatusBadRequest)
			return
		}

		// Security check: Only allow editing other users if the current user is an admin
		if userID != data.UserID && !data.IsAdmin {
			http.Error(w, "Unauthorized", http.StatusForbidden)
			return
		}
	}

	// Get user details
	user, err := db.GetUserByID(userID)
	if err != nil || user == nil {
		log.Printf("Error getting user or user not found: %v", err)
		http.Error(w, "User not found", http.StatusNotFound)
		return
	}

	data.User = user
	renderTemplate(w, "edit-user", data)
}

func addUserHandler(w http.ResponseWriter, r *http.Request) {
	data := getPageData(w, r)
	data.Title = "Add User"

	if r.Method == "POST" {
		username := r.FormValue("username")
		password := r.FormValue("password")
		isAdmin := r.FormValue("isAdmin") == "on"

		// Validate input
		if username == "" || password == "" {
			data.Error = "Username and password are required"
			renderTemplate(w, "add-user", data)
			return
		}

		// Check if username already exists
		existingUser, err := db.GetUserByUsername(username)
		if err != nil {
			data.Error = "Error checking username"
			renderTemplate(w, "add-user", data)
			return
		}
		if existingUser != nil {
			data.Error = "Username already exists"
			renderTemplate(w, "add-user", data)
			return
		}

		// Get permission values from form
		canAddDevices := r.FormValue("canAddDevices") == "on"
		canModifyDevices := r.FormValue("canModifyDevices") == "on"
		canAddUsers := r.FormValue("canAddUsers") == "on"
		canModifyUsers := r.FormValue("canModifyUsers") == "on"

		// Admin users automatically get all permissions
		if isAdmin {
			canAddDevices = true
			canModifyDevices = true
			canAddUsers = true
			canModifyUsers = true
		}

		// Create the user with specified permissions
		if err := db.CreateUser(username, password, isAdmin, canAddDevices, canModifyDevices, canAddUsers, canModifyUsers); err != nil {
			data.Error = "Failed to create user"
			renderTemplate(w, "add-user", data)
			return
		}

		// If user should be admin, update their status
		if isAdmin {
			// Get the newly created user
			user, err := db.GetUserByUsername(username)
			if err == nil && user != nil {
				// Get form values for new permissions
				canAddDevices := r.FormValue("canAddDevices") == "on"
				canModifyDevices := r.FormValue("canModifyDevices") == "on"
				canAddUsers := r.FormValue("canAddUsers") == "on"
				canModifyUsers := r.FormValue("canModifyUsers") == "on"

				// Admin users automatically get all permissions
				if isAdmin {
					canAddDevices = true
					canModifyDevices = true
					canAddUsers = true
					canModifyUsers = true
				}

				db.UpdateUser(user.ID, username, isAdmin, canAddDevices, canModifyDevices, canAddUsers, canModifyUsers)
			}
		}

		data.Success = "User created successfully"
		http.Redirect(w, r, "/users", http.StatusSeeOther)
		return
	}

	renderTemplate(w, "add-user", data)
}

func addDeviceHandler(w http.ResponseWriter, r *http.Request) {
	data := getPageData(w, r)
	data.Title = "Add Device"

	// Check if user has permission to add devices
	currentUser, err := db.GetUserByUsername(data.Username)
	if err != nil || currentUser == nil {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}

	// Only allow users with admin or canAddDevices permission
	if !currentUser.IsAdmin && !currentUser.CanAddDevices {
		http.Error(w, "You don't have permission to add devices", http.StatusForbidden)
		return
	}
	data.FormData = make(map[string]string)
	data.ErrorFields = make(map[string]bool)

	// Check for flashed messages
	session, _ := store.Get(r, "session-name")
	if flashes := session.Flashes("success"); len(flashes) > 0 {
		data.Success = flashes[0].(string)
		session.Save(r, w)
	}

	// Set RandomUser to false by default
	data.RandomUser = false
	data.RandomKey = false

	// Generate a unique form token
	data.FormToken = generateFormToken()
	session.Values["form_token"] = data.FormToken
	session.Save(r, w)

	if r.Method == "POST" {
		// Validate form token to prevent duplicate submissions
		formToken := r.FormValue("form_token")
		if !validateFormToken(r, formToken) {
			// This is a duplicate submission or invalid token
			http.Redirect(w, r, "/devices", http.StatusSeeOther)
			return
		}

		// Collect all form values
		name := r.FormValue("name")
		deviceType := r.FormValue("type")
		ipAddress := r.FormValue("ip_address")
		sshUser := r.FormValue("ssh_user")
		sshGroup := r.FormValue("ssh_group")
		sshKeyPath := r.FormValue("ssh_key_path")
		sshPortStr := r.FormValue("ssh_port")
		randomUser := r.FormValue("random_user") == "true"
		randomKey := r.FormValue("random_key") == "true"
		setupUser := r.FormValue("setup_user")
		// No longer using password authentication

		// Store form values for redisplay in case of error
		data.FormData["name"] = name
		data.FormData["type"] = deviceType
		data.FormData["ip_address"] = ipAddress
		data.FormData["ssh_user"] = sshUser
		data.FormData["ssh_group"] = sshGroup
		data.FormData["ssh_key_path"] = sshKeyPath
		data.FormData["ssh_port"] = sshPortStr
		data.FormData["setup_user"] = setupUser

		// Update RandomUser in data for template rendering in case of error
		data.RandomUser = randomUser
		data.RandomKey = randomKey

		// Validate input
		if name == "" || deviceType == "" {
			data.Error = "Name and type are required"
			if name == "" {
				data.ErrorFields["name"] = true
			}
			if deviceType == "" {
				data.ErrorFields["type"] = true
			}
			renderTemplate(w, "add-device", data)
			return
		}

		// Check for duplicate device name
		exists, err := db.DeviceExistsByName(name, 0)
		if err != nil {
			data.Error = "Error checking device name: " + err.Error()
			renderTemplate(w, "add-device", data)
			return
		}
		if exists {
			data.Error = "A device with this name already exists"
			data.ErrorFields["name"] = true
			// Clear the name field to force user to enter a new one
			data.FormData["name"] = ""
			renderTemplate(w, "add-device", data)
			return
		}

		// Validate IP address format
		if ipAddress == "" || net.ParseIP(ipAddress) == nil {
			data.Error = "Valid IP address is required"
			data.ErrorFields["ip_address"] = true
			renderTemplate(w, "add-device", data)
			return
		}

		// Check for duplicate IP address
		exists, err = db.DeviceExistsByIP(ipAddress, 0)
		if err != nil {
			data.Error = "Error checking IP address: " + err.Error()
			renderTemplate(w, "add-device", data)
			return
		}
		if exists {
			data.Error = "A device with this IP address already exists"
			data.ErrorFields["ip_address"] = true
			// Clear the IP address field to force user to enter a new one
			data.FormData["ip_address"] = ""
			renderTemplate(w, "add-device", data)
			return
		}

		// Validate setup user
		if setupUser == "" {
			data.Error = "Setup username is required"
			data.ErrorFields["setup_user"] = true
			renderTemplate(w, "add-device", data)
			return
		}

		// Password validation removed - using key-based authentication only

		// Set default SSH port if not provided
		sshPort := 22
		if sshPortStr != "" {
			var err error
			sshPort, err = strconv.Atoi(sshPortStr)
			if err != nil || sshPort < 1 || sshPort > 65535 {
				data.Error = "Invalid SSH port number"
				data.ErrorFields["ssh_port"] = true
				renderTemplate(w, "add-device", data)
				return
			}
		}

		// If random user is not selected, we need both user and group
		if !randomUser && (sshUser == "" || sshGroup == "") {
			data.Error = "SSH username and group are required (or select random generation)"
			if sshUser == "" {
				data.ErrorFields["ssh_user"] = true
			}
			if sshGroup == "" {
				data.ErrorFields["ssh_group"] = true
			}
			renderTemplate(w, "add-device", data)
			return
		}

		// If SSH key path is not provided and random key is not selected
		if sshKeyPath == "" && !randomKey {
			data.Error = "SSH key path is required unless random key generation is enabled"
			data.ErrorFields["ssh_key_path"] = true
			renderTemplate(w, "add-device", data)
			return
		}

		// Set default values for random user generation
		if randomUser {
			sshUser = "random_user"   // Will be replaced by the script
			sshGroup = "random_group" // Will be replaced by the script
		}

		// Set default key path for random key generation
		if randomKey {
			sshKeyPath = "$HOME/.ssh/ids_monitoring_key" // Will be generated by the script if it doesn't exist
		}

		// Create the device with SSH monitoring details
		hostname := ""
		osInfo := ""

		// Try to get hostname and OS info if possible (this would be done by the enlist.sh script)
		// For demo purposes, we'll just create the device without this info
		err = db.CreateMonitoredDevice(name, deviceType, ipAddress, sshUser, sshKeyPath, sshPort, hostname, osInfo, sshGroup, randomUser, randomKey, setupUser, "")
		if err != nil {
			data.Error = "Failed to create device: " + err.Error()
			renderTemplate(w, "add-device", data)
			return
		}

		// After creating the device, check its status immediately
		// Get the newly created device to get its ID
		devices, err := db.GetAllDevices()
		if err == nil && len(devices) > 0 {
			// Find the device we just created by name
			var newDeviceID int64
			for _, d := range devices {
				if d.Name == name {
					newDeviceID = d.ID
					break
				}
			}

			if newDeviceID > 0 {
				// Check if the device is online
				online, err := db.CheckDeviceStatus(ipAddress)
				if err == nil {
					status := "offline"
					if online {
						status = "online"
					}
					// Update the status
					db.UpdateDeviceStatus(newDeviceID, status)
				}
			}
		}

		// Set a success message and redirect to prevent form resubmission
		session.AddFlash("Device created successfully", "success")
		session.Save(r, w)

		http.Redirect(w, r, "/devices", http.StatusSeeOther)
		return
	}

	// For GET requests, just render the template with empty form
	renderTemplate(w, "add-device", data)
}

func editDeviceHandler(w http.ResponseWriter, r *http.Request) {
	data := getPageData(w, r)
	data.Title = "Edit Device"

	// Check if user has permission to modify devices
	currentUser, err := db.GetUserByUsername(data.Username)
	if err != nil || currentUser == nil {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}

	// Only allow users with admin or canModifyDevices permission
	if !currentUser.IsAdmin && !currentUser.CanModifyDevices {
		http.Error(w, "You don't have permission to modify devices", http.StatusForbidden)
		return
	}
	data.FormData = make(map[string]string)
	data.ErrorFields = make(map[string]bool)

	// Check for flashed messages
	session, _ := store.Get(r, "session-name")
	if flashes := session.Flashes("success"); len(flashes) > 0 {
		data.Success = flashes[0].(string)
		session.Save(r, w)
	}

	// Extract device ID from URL
	parts := strings.Split(r.URL.Path, "/")
	if len(parts) < 4 {
		http.NotFound(w, r)
		return
	}

	deviceID, err := strconv.ParseInt(parts[3], 10, 64)
	if err != nil {
		http.NotFound(w, r)
		return
	}

	// Get device from database
	device, err := db.GetDeviceByID(deviceID)
	if err != nil {
		data.Error = "Error retrieving device: " + err.Error()
		renderTemplate(w, "edit-device", data)
		return
	}

	if device == nil {
		http.NotFound(w, r)
		return
	}

	data.Device = *device
	data.RandomUser = device.RandomUser
	data.RandomKey = device.RandomKey

	// Pre-populate form data with existing device values
	data.FormData["name"] = device.Name
	data.FormData["type"] = device.Type
	data.FormData["status"] = device.Status
	data.FormData["ip_address"] = device.IPAddress
	data.FormData["ssh_user"] = device.SSHUser
	data.FormData["ssh_group"] = device.SSHGroup
	data.FormData["ssh_key_path"] = device.SSHKeyPath
	data.FormData["ssh_port"] = strconv.Itoa(device.SSHPort)
	data.FormData["setup_user"] = device.SetupUser
	// Don't pre-populate password for security reasons

	// Generate a unique form token
	data.FormToken = generateFormToken()
	session.Values["form_token"] = data.FormToken
	session.Save(r, w)

	if r.Method == "POST" {
		// Validate form token to prevent duplicate submissions
		formToken := r.FormValue("form_token")
		if !validateFormToken(r, formToken) {
			// This is a duplicate submission or invalid token
			http.Redirect(w, r, "/devices", http.StatusSeeOther)
			return
		}

		// Collect all form values
		name := r.FormValue("name")
		deviceType := r.FormValue("type")
		status := r.FormValue("status")
		ipAddress := r.FormValue("ip_address")
		sshUser := r.FormValue("ssh_user")
		sshGroup := r.FormValue("ssh_group")
		sshKeyPath := r.FormValue("ssh_key_path")
		sshPortStr := r.FormValue("ssh_port")
		randomUser := r.FormValue("random_user") == "true"
		randomKey := r.FormValue("random_key") == "true"
		setupUser := r.FormValue("setup_user")
		// No longer using password authentication

		// Store form values for redisplay in case of error
		data.FormData["name"] = name
		data.FormData["type"] = deviceType
		data.FormData["status"] = status
		data.FormData["ip_address"] = ipAddress
		data.FormData["ssh_user"] = sshUser
		data.FormData["ssh_group"] = sshGroup
		data.FormData["ssh_key_path"] = sshKeyPath
		data.FormData["ssh_port"] = sshPortStr
		data.FormData["setup_user"] = setupUser

		// Update RandomUser in data for template rendering in case of error
		data.RandomUser = randomUser
		data.RandomKey = randomKey

		// Validate input
		if name == "" || deviceType == "" || status == "" {
			data.Error = "Name, type, and status are required"
			if name == "" {
				data.ErrorFields["name"] = true
			}
			if deviceType == "" {
				data.ErrorFields["type"] = true
			}
			if status == "" {
				data.ErrorFields["status"] = true
			}
			renderTemplate(w, "edit-device", data)
			return
		}

		// Check for duplicate device name
		exists, err := db.DeviceExistsByName(name, deviceID)
		if err != nil {
			data.Error = "Error checking device name: " + err.Error()
			renderTemplate(w, "edit-device", data)
			return
		}
		if exists {
			data.Error = "A device with this name already exists"
			data.ErrorFields["name"] = true
			// Clear the name field to force user to enter a new one
			data.FormData["name"] = ""
			renderTemplate(w, "edit-device", data)
			return
		}

		// Validate IP address format
		if ipAddress == "" || net.ParseIP(ipAddress) == nil {
			data.Error = "Valid IP address is required"
			data.ErrorFields["ip_address"] = true
			renderTemplate(w, "edit-device", data)
			return
		}

		// Check for duplicate IP address
		exists, err = db.DeviceExistsByIP(ipAddress, deviceID)
		if err != nil {
			data.Error = "Error checking IP address: " + err.Error()
			renderTemplate(w, "edit-device", data)
			return
		}
		if exists {
			data.Error = "A device with this IP address already exists"
			data.ErrorFields["ip_address"] = true
			// Clear the IP address field to force user to enter a new one
			data.FormData["ip_address"] = ""
			renderTemplate(w, "edit-device", data)
			return
		}

		// Validate setup user
		if setupUser == "" {
			data.Error = "Setup username is required"
			data.ErrorFields["setup_user"] = true
			renderTemplate(w, "edit-device", data)
			return
		}

		// Password validation removed - using key-based authentication only

		// Set default SSH port if not provided
		sshPort := 22
		if sshPortStr != "" {
			var err error
			sshPort, err = strconv.Atoi(sshPortStr)
			if err != nil || sshPort < 1 || sshPort > 65535 {
				data.Error = "Invalid SSH port number"
				data.ErrorFields["ssh_port"] = true
				renderTemplate(w, "edit-device", data)
				return
			}
		}

		// If random user is not selected, we need both user and group
		if !randomUser && (sshUser == "" || sshGroup == "") {
			data.Error = "SSH username and group are required (or select random generation)"
			if sshUser == "" {
				data.ErrorFields["ssh_user"] = true
			}
			if sshGroup == "" {
				data.ErrorFields["ssh_group"] = true
			}
			renderTemplate(w, "edit-device", data)
			return
		}

		// If SSH key path is not provided
		if sshKeyPath == "" {
			data.Error = "SSH key path is required"
			data.ErrorFields["ssh_key_path"] = true
			renderTemplate(w, "edit-device", data)
			return
		}

		// Set default values for random user generation
		if randomUser {
			// Only replace if this is a new random user setting
			if !device.RandomUser {
				sshUser = "random_user"   // Will be replaced by the script
				sshGroup = "random_group" // Will be replaced by the script
			}
		}

		// Update the device with SSH monitoring details
		hostname := device.Hostname // Preserve existing hostname
		osInfo := device.OSInfo     // Preserve existing OS info

		err = db.UpdateMonitoredDevice(deviceID, name, deviceType, status,
			ipAddress, sshUser, sshKeyPath, sshPort, hostname, osInfo, sshGroup, randomUser, randomKey, setupUser, "")
		if err != nil {
			data.Error = "Failed to update device: " + err.Error()
			renderTemplate(w, "edit-device", data)
			return
		}

		// Set a success message and redirect to prevent form resubmission
		session.AddFlash("Device updated successfully", "success")
		session.Save(r, w)

		http.Redirect(w, r, "/devices", http.StatusSeeOther)
		return
	}

	renderTemplate(w, "edit-device", data)
}

func deleteDeviceHandler(w http.ResponseWriter, r *http.Request) {
	// Check if user has permission to delete devices
	data := getPageData(w, r)
	currentUser, err := db.GetUserByUsername(data.Username)
	if err != nil || currentUser == nil {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}

	// Only allow users with admin or canModifyDevices permission
	if !currentUser.IsAdmin && !currentUser.CanModifyDevices {
		http.Error(w, "You don't have permission to delete devices", http.StatusForbidden)
		return
	}

	// Extract device ID from URL
	parts := strings.Split(r.URL.Path, "/")
	if len(parts) < 4 {
		http.NotFound(w, r)
		return
	}

	deviceID, err := strconv.ParseInt(parts[3], 10, 64)
	if err != nil {
		http.NotFound(w, r)
		return
	}

	// Check if the device exists
	device, err := db.GetDeviceByID(deviceID)
	if err != nil {
		http.NotFound(w, r)
		return
	}

	// Check if this is a confirmation request
	if len(parts) >= 5 && parts[4] == "confirm" && r.Method == "POST" {
		// Delete the device
		if err := db.DeleteDevice(deviceID); err != nil {
			log.Printf("Error deleting device: %v", err)
			session, _ := store.Get(r, "session-name")
			session.AddFlash("Failed to delete device: "+err.Error(), "error")
			session.Save(r, w)
		} else {
			// Set success message
			session, _ := store.Get(r, "session-name")
			session.AddFlash("Device deleted successfully", "success")
			session.Save(r, w)
		}

		// Redirect back to devices page
		http.Redirect(w, r, "/devices", http.StatusSeeOther)
		return
	}

	// Show confirmation page
	// Update the data object instead of redeclaring it
	data.Title = "Confirm Delete Device"
	data.Device = *device
	renderTemplate(w, "delete-device-confirm", data)
}

func monitorDeviceHandler(w http.ResponseWriter, r *http.Request) {
	// Get page data with user info
	data := getPageData(w, r)
	data.Title = "Monitor Device"

	// If user is not logged in, redirect to login page
	if data.Username == "" {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}

	// Extract device ID from URL
	parts := strings.Split(r.URL.Path, "/")
	if len(parts) < 4 {
		http.NotFound(w, r)
		return
	}

	deviceID, err := strconv.ParseInt(parts[3], 10, 64)
	if err != nil {
		http.NotFound(w, r)
		return
	}

	// Get device details
	device, err := db.GetDeviceByID(deviceID)
	if err != nil {
		http.Error(w, "Device not found", http.StatusNotFound)
		return
	}

	// Set device in page data
	data.Device = *device

	// Get pagination parameters
	page := 1
	pageSize := 10 // Default page size
	searchTerm := ""

	// Parse query parameters
	if r.Method == "GET" {
		if pageParam := r.URL.Query().Get("page"); pageParam != "" {
			if p, err := strconv.Atoi(pageParam); err == nil && p > 0 {
				page = p
			}
		}

		if pageSizeParam := r.URL.Query().Get("pageSize"); pageSizeParam != "" {
			if ps, err := strconv.Atoi(pageSizeParam); err == nil && (ps == 10 || ps == 20 || ps == 50) {
				pageSize = ps
			}
		}

		searchTerm = r.URL.Query().Get("search")
	}

	// Get audit logs for this device with pagination and search
	logs, totalCount, err := db.GetAuditLogsByDeviceID(deviceID, page, pageSize, searchTerm)
	if err != nil {
		log.Printf("Error fetching audit logs: %v", err)
		data.Error = "Failed to fetch audit logs: " + err.Error()
	}

	log.Printf("Retrieved %d audit logs for device ID %d (page %d, total %d)", len(logs), deviceID, page, totalCount)

	// Calculate pagination information
	totalPages := (totalCount + pageSize - 1) / pageSize // Ceiling division

	// Initialize monitoring data map
	data.MonitoringData = make(map[string]string)

	// Add system information to monitoring data
	data.MonitoringData["Status"] = device.Status
	data.MonitoringData["Last Updated"] = device.LastUpdated.Format("2006-01-02 15:04:05")

	// Add audit logs and pagination data to the Data map for the template
	data.Data = make(map[string]interface{})
	data.Data["AuditLogs"] = logs
	data.Data["CurrentPage"] = page
	data.Data["TotalPages"] = totalPages
	data.Data["PageSize"] = pageSize
	data.Data["TotalLogs"] = totalCount
	data.Data["SearchTerm"] = searchTerm

	// Generate enlist command for display
	enlistCmd, err := addDeviceEnlistCommand(*device, device.SetupUser)
	if err != nil {
		data.Error = "Failed to generate enlist command: " + err.Error()
	} else {
		if data.FormData == nil {
			data.FormData = make(map[string]string)
		}
		data.FormData["enlist_command"] = enlistCmd
	}

	renderTemplate(w, "monitor-device", data)
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

func apiDeviceHandler(w http.ResponseWriter, r *http.Request) {
	// Parse the URL path to extract the device ID and action
	pathParts := strings.Split(strings.TrimPrefix(r.URL.Path, "/api/devices/"), "/")
	if len(pathParts) < 2 {
		http.Error(w, "Invalid API path", http.StatusBadRequest)
		return
	}

	deviceIDStr := pathParts[0]
	action := pathParts[1]

	deviceID, err := strconv.ParseInt(deviceIDStr, 10, 64)
	if err != nil {
		http.Error(w, "Invalid device ID", http.StatusBadRequest)
		return
	}

	// Get the device
	_, err = db.GetDeviceByID(deviceID)
	if err != nil {
		http.Error(w, "Device not found", http.StatusNotFound)
		return
	}

	// Handle different actions
	switch action {
	default:
		http.Error(w, "Unknown action", http.StatusBadRequest)
	}
}

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
