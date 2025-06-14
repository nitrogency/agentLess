package db

import (
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	"golang.org/x/crypto/bcrypt"
)

// User represents a user in the system
type User struct {
	ID                int64     `json:"id"`
	Username          string    `json:"username"`
	IsAdmin           bool      `json:"is_admin"`
	CanAddDevices     bool      `json:"can_add_devices"`
	CanModifyDevices  bool      `json:"can_modify_devices"`
	CanAddUsers       bool      `json:"can_add_users"`
	CanModifyUsers    bool      `json:"can_modify_users"`
	CreatedAt         time.Time `json:"created_at"`
}

// InitUserTable creates the users table if it doesn't exist
func InitUserTable() error {
	_, err := db.Exec(`
		CREATE TABLE IF NOT EXISTS users (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			username TEXT NOT NULL UNIQUE,
			password_hash TEXT NOT NULL,
			is_admin INTEGER NOT NULL DEFAULT 0,
			can_add_devices INTEGER NOT NULL DEFAULT 0,
			can_modify_devices INTEGER NOT NULL DEFAULT 0,
			can_add_users INTEGER NOT NULL DEFAULT 0,
			can_modify_users INTEGER NOT NULL DEFAULT 0,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP
		);
		CREATE INDEX IF NOT EXISTS idx_users_username ON users(username);
	`)

	// Add new permission columns if they don't exist (for backward compatibility)
	_, err = db.Exec(`
		PRAGMA table_info(users);
	`)
	if err != nil {
		return err
	}

	// Add can_add_devices column if it doesn't exist
	_, err = db.Exec(`
		ALTER TABLE users ADD COLUMN can_add_devices INTEGER NOT NULL DEFAULT 0;
	`)
	if err != nil && !strings.Contains(err.Error(), "duplicate column name") {
		return err
	}

	// Add can_modify_devices column if it doesn't exist
	_, err = db.Exec(`
		ALTER TABLE users ADD COLUMN can_modify_devices INTEGER NOT NULL DEFAULT 0;
	`)
	if err != nil && !strings.Contains(err.Error(), "duplicate column name") {
		return err
	}
	
	// Add can_add_users column if it doesn't exist
	_, err = db.Exec(`
		ALTER TABLE users ADD COLUMN can_add_users INTEGER NOT NULL DEFAULT 0;
	`)
	if err != nil && !strings.Contains(err.Error(), "duplicate column name") {
		return err
	}
	
	// Add can_modify_users column if it doesn't exist
	_, err = db.Exec(`
		ALTER TABLE users ADD COLUMN can_modify_users INTEGER NOT NULL DEFAULT 0;
	`)
	if err != nil && !strings.Contains(err.Error(), "duplicate column name") {
		return err
	}

	return nil
}

// CreateUser creates a new user with the given username and password
func CreateUser(username, password string, isAdmin, canAddDevices, canModifyDevices, canAddUsers, canModifyUsers bool) error {
	// Check if username already exists
	var exists bool
	err := db.QueryRow("SELECT 1 FROM users WHERE username = ?", username).Scan(&exists)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return err
	}

	// Hash the password
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return err
	}

	// Convert boolean values to integers for SQLite
	isAdminInt := 0
	if isAdmin {
		isAdminInt = 1
	}

	canAddDevicesInt := 0
	if canAddDevices {
		canAddDevicesInt = 1
	}

	canModifyDevicesInt := 0
	if canModifyDevices {
		canModifyDevicesInt = 1
	}

	canAddUsersInt := 0
	if canAddUsers {
		canAddUsersInt = 1
	}

	canModifyUsersInt := 0
	if canModifyUsers {
		canModifyUsersInt = 1
	}

	// Insert the new user
	_, err = db.Exec(
		"INSERT INTO users (username, password_hash, is_admin, can_add_devices, can_modify_devices, can_add_users, can_modify_users) VALUES (?, ?, ?, ?, ?, ?, ?)",
		username, string(hash), isAdminInt, canAddDevicesInt, canModifyDevicesInt, canAddUsersInt, canModifyUsersInt,
	)
	return err
}

// ValidateUser checks if the username and password combination is valid
func ValidateUser(username, password string) (bool, error) {
	var hash string
	err := db.QueryRow(
		"SELECT password_hash FROM users WHERE username = ?",
		username,
	).Scan(&hash)

	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return false, nil // User not found
		}
		return false, err
	}

	// Compare password with hash
	err = bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	if err != nil {
		if errors.Is(err, bcrypt.ErrMismatchedHashAndPassword) {
			return false, nil // Wrong password
		}
		return false, err
	}

	return true, nil
}

// GetUser retrieves a user by username
func GetUser(username string) (*User, error) {
	user := &User{}
	err := db.QueryRow(
		"SELECT id, username, is_admin, can_add_devices, can_modify_devices, created_at FROM users WHERE username = ?",
		username,
	).Scan(&user.ID, &user.Username, &user.IsAdmin, &user.CanAddDevices, &user.CanModifyDevices, &user.CreatedAt)

	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil // User not found
		}
		return nil, err
	}

	return user, nil
}

// GetUserByID returns a user by their ID
func GetUserByID(id int64) (*User, error) {
	var user User
	err := db.QueryRow("SELECT id, username, is_admin, can_add_devices, can_modify_devices, can_add_users, can_modify_users, created_at FROM users WHERE id = ?", id).
		Scan(&user.ID, &user.Username, &user.IsAdmin, &user.CanAddDevices, &user.CanModifyDevices, &user.CanAddUsers, &user.CanModifyUsers, &user.CreatedAt)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}
	return &user, nil
}

// GetUserByUsername returns a user by their username
func GetUserByUsername(username string) (*User, error) {
	var user User
	err := db.QueryRow("SELECT id, username, is_admin, can_add_devices, can_modify_devices, can_add_users, can_modify_users, created_at FROM users WHERE username = ?", username).
		Scan(&user.ID, &user.Username, &user.IsAdmin, &user.CanAddDevices, &user.CanModifyDevices, &user.CanAddUsers, &user.CanModifyUsers, &user.CreatedAt)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}
	return &user, nil
}

// GetAllUsers returns all users from the database
func GetAllUsers() ([]User, error) {
	rows, err := db.Query("SELECT id, username, is_admin, can_add_devices, can_modify_devices, can_add_users, can_modify_users, created_at FROM users")
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var users []User
	for rows.Next() {
		var user User
		if err := rows.Scan(&user.ID, &user.Username, &user.IsAdmin, &user.CanAddDevices, &user.CanModifyDevices, &user.CanAddUsers, &user.CanModifyUsers, &user.CreatedAt); err != nil {
			return nil, err
		}
		users = append(users, user)
	}
	return users, nil
}

// UpdateUser updates a user's information
func UpdateUser(id int64, username string, isAdmin bool, canAddDevices bool, canModifyDevices bool, canAddUsers bool, canModifyUsers bool) error {
	_, err := db.Exec("UPDATE users SET username = ?, is_admin = ?, can_add_devices = ?, can_modify_devices = ?, can_add_users = ?, can_modify_users = ? WHERE id = ?",
		username, isAdmin, canAddDevices, canModifyDevices, canAddUsers, canModifyUsers, id)
	return err
}

// UpdateUserPassword updates a user's password
func UpdateUserPassword(id int64, newPassword string) error {
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(newPassword), bcrypt.DefaultCost)
	if err != nil {
		return err
	}

	_, err = db.Exec("UPDATE users SET password_hash = ? WHERE id = ?",
		string(hashedPassword), id)
	return err
}

// DeleteUser deletes a user by ID
// currentUserID is the ID of the user performing the deletion
func DeleteUser(id int64, currentUserID int64) error {
	// Prevent self-deletion
	if id == currentUserID {
		return fmt.Errorf("You cannot delete your own account.")
	}

	// Check if this is the last user
	var count int
	err := db.QueryRow("SELECT COUNT(*) FROM users").Scan(&count)
	if err != nil {
		return err
	}

	if count <= 1 {
		return fmt.Errorf("You cannot delete the last user in the system.")
	}

	_, err = db.Exec("DELETE FROM users WHERE id = ?", id)
	return err
}

// IsUsersTableEmpty checks if the users table has any records
func IsUsersTableEmpty() (bool, error) {
	var count int
	err := db.QueryRow("SELECT COUNT(*) FROM users").Scan(&count)
	if err != nil {
		return false, err
	}
	return count == 0, nil
}
