package db

import (
	"database/sql"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"

	_ "github.com/mutecomm/go-sqlcipher/v4"
	"github.com/joho/godotenv"
)

var db *sql.DB

// getEncryptionKey returns the database encryption key from environment variables
// or generates a new one if not found
func getEncryptionKey() (string, error) {
	// Try to load from .env file first (in case it wasn't loaded yet)
	_ = godotenv.Load()
	
	// Get encryption key from environment
	encKey := os.Getenv("DB_ENCRYPTION_KEY")
	if encKey == "" {
		// For development only - in production, this should be set in environment
		if os.Getenv("GO_ENV") == "production" {
			return "", errors.New("DB_ENCRYPTION_KEY must be set in production environment")
		}
		
		log.Println("Warning: Using default database encryption key. This is insecure for production.")
		encKey = "default-dev-encryption-key-do-not-use-in-production"
	}
	
	return encKey, nil
}

// InitDB initializes the database connection with encryption
func InitDB() error {
	// Ensure database directory exists
	dbDir := "data"
	if err := os.MkdirAll(dbDir, 0750); err != nil {
		return err
	}

	// Get encryption key
	encryptionKey, err := getEncryptionKey()
	if err != nil {
		return fmt.Errorf("failed to get encryption key: %w", err)
	}

	dbPath := filepath.Join(dbDir, "site.db")
	
	// Open encrypted database using SQLCipher
	// The connection string includes the encryption key
	connStr := fmt.Sprintf("%s?_pragma_key=%s", dbPath, encryptionKey)
	db, err = sql.Open("sqlite3", connStr)
	if err != nil {
		return fmt.Errorf("failed to open database: %w", err)
	}

	// Verify the encryption key works by running a simple query
	if err := db.Ping(); err != nil {
		return fmt.Errorf("database ping failed (possibly wrong encryption key): %w", err)
	}

	// Sets DB parameters
	if _, err := db.Exec(`PRAGMA journal_mode=WAL;`); err != nil {
		return err
	}
	if _, err := db.Exec(`PRAGMA synchronous=NORMAL;`); err != nil {
		return err
	}
	if _, err := db.Exec(`PRAGMA foreign_keys=ON;`); err != nil {
		return err
	}

	// Initialize tables
	if err := InitUserTable(); err != nil {
		return err
	}

	if err := InitDeviceTable(); err != nil {
		return err
	}

	if err := InitAuditLogTable(); err != nil {
		return err
	}

	return db.Ping()
}

// Close closes the database connection
func Close() error {
	if db != nil {
		return db.Close()
	}
	return nil
}

// GetDB returns the database instance
func GetDB() *sql.DB {
	return db
}
