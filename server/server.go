package server

import (
	"html/template"
	"net/http"
	"os"
	"time"

	"github.com/gin-contrib/sessions"
	"github.com/gin-contrib/sessions/cookie"
	"github.com/gin-gonic/gin"

	"example/go-website/config"
	"example/go-website/db"
	"example/go-website/handlers"
	"example/go-website/middleware"
	"example/go-website/models"
	"example/go-website/templates"
)

// SetupRouter configures and returns a Gin router with all routes and middleware
func SetupRouter(cfg *config.Config) *gin.Engine {
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
	// Serve favicon
	router.StaticFile("/favicon.ico", "./static/favicon.ico")

	// Apply security middleware
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
				templates.RenderGinTemplate(c, "login", models.PageData{
					Title: "Login",
					Error: "Too many login attempts. Please try again later.",
				})
				c.Abort()
				return
			}
		}
		c.Next()
	})

	// Setup routes
	setupRoutes(router)

	return router
}

// setupRoutes configures all application routes
func setupRoutes(router *gin.Engine) {
	// Public routes
	router.GET("/login", handlers.LoginHandler)
	router.POST("/login", handlers.LoginHandler)
	router.GET("/signup", handlers.SignupHandler)
	router.POST("/signup", handlers.SignupHandler)
	router.GET("/logout", handlers.LogoutHandler)

	// Protected routes
	protected := router.Group("/")
	protected.Use(middleware.RequireAuth())
	{
		// Dashboard
		protected.GET("/", handlers.HomeHandler)

		// Device management
		protected.GET("/devices", handlers.DevicesHandler)
		protected.POST("/devices", handlers.DevicesHandler)
		protected.GET("/devices/add", handlers.AddDeviceHandler)
		protected.POST("/devices/add", handlers.AddDeviceHandler)
		protected.GET("/devices/edit/:id", handlers.EditDeviceHandler)
		protected.POST("/devices/edit/:id", handlers.EditDeviceHandler)
		protected.GET("/devices/delete/:id", handlers.DeleteDeviceHandler)
		protected.POST("/devices/delete/:id", handlers.DeleteDeviceHandler)
		protected.GET("/devices/monitor/:id", handlers.MonitorDeviceHandler)
		protected.GET("/devices/logs/:id", handlers.DeviceLogsHandler)

		// Audit logs
		protected.GET("/logs", handlers.AllLogsHandler)
		protected.GET("/logs/export", handlers.AllLogsHandler) // CSV export
		protected.GET("/logs/retention", handlers.LogRetentionHandler)
		protected.POST("/logs/retention", handlers.LogRetentionHandler)

		// Notifications
		protected.GET("/notifications/summary", handlers.NotificationsSummaryHandler)
		protected.POST("/notifications/mark-seen", handlers.NotificationsMarkSeenHandler)
	}

	// Admin routes
	admin := router.Group("/")
	admin.Use(middleware.RequireAuth())
	admin.Use(middleware.RequireAdmin())
	{
		// User management
		admin.GET("/users", handlers.UsersHandler)
		admin.POST("/users", handlers.UsersHandler)
		admin.GET("/users/add", handlers.AddUserHandler)
		admin.POST("/users/add", handlers.AddUserHandler)
		admin.GET("/users/edit/:id", handlers.EditUserHandler)
		admin.POST("/users/edit/:id", handlers.EditUserHandler)
		admin.GET("/users/delete/:id", handlers.DeleteUserHandler)
		admin.POST("/users/delete/:id", handlers.DeleteUserHandler)
	}

	// 404 handler
	router.NoRoute(handlers.NotFoundHandler)
}

// CreateServer creates and configures the HTTP server
func CreateServer(router *gin.Engine, cfg *config.Config) *http.Server {
	return &http.Server{
		Addr:         ":" + cfg.Server.Port,
		Handler:      router,
		ReadTimeout:  cfg.Server.ReadTimeout,
		WriteTimeout: cfg.Server.WriteTimeout,
		IdleTimeout:  cfg.Server.IdleTimeout,
	}
}
