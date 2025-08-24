package main

import (
	"context"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/joho/godotenv"

	"example/go-website/config"
	"example/go-website/db"
	"example/go-website/server"
)

func main() {
	// Load environment variables if .env file exists
	_ = godotenv.Load()

	// Initialize configuration
	cfg, err := config.Load()
	if err != nil {
		log.Fatalf("Failed to load config: %v", err)
	}

	// Initialize database
	if err := db.InitDB(); err != nil {
		log.Fatalf("Failed to initialize database: %v", err)
	}

	// Setup router with all routes and middleware
	router := server.SetupRouter(cfg)

	// Create server
	srv := server.CreateServer(router, cfg)

	// Start monitoring in background
	go startDeviceMonitoring()

	// Graceful shutdown handling
	c := make(chan os.Signal, 1)
	signal.Notify(c, syscall.SIGINT, syscall.SIGTERM)

	// Start server in a goroutine
	go func() {
		log.Printf("Server starting on port %s", cfg.Server.Port)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("Server failed to start: %v", err)
		}
	}()

	// Wait for interrupt signal
	<-c
	log.Println("Shutting down server...")

	// Create a context with timeout for graceful shutdown
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Shutdown the server
	if err := srv.Shutdown(ctx); err != nil {
		log.Printf("Server forced to shutdown: %v", err)
	}

	log.Println("Server exited")
}

// startDeviceMonitoring runs the device monitoring script in the background
func startDeviceMonitoring() {
	log.Println("Starting device monitoring service...")
	
	// Run initial device status check
	go func() {
		for {
			log.Println("Running device status check...")
			
			// Update all device statuses
			if err := db.UpdateAllDeviceStatuses(); err != nil {
				log.Printf("Error updating device statuses: %v", err)
			} else {
				log.Println("Device status check completed")
			}
			
			// Wait 5 minutes before next check
			time.Sleep(5 * time.Minute)
		}
	}()
	
	log.Println("Device monitoring service started")
}
