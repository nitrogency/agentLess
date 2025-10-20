package db

import (
	"database/sql"
	"errors"
	"fmt"
	"time"

	"golang.org/x/crypto/bcrypt"
)

// User represents a user in the system
type User struct {
	ID               int64     `json:"id"`
	Username         string    `json:"username"`
	IsAdmin          bool      `json:"is_admin"`
	CanAddDevices    bool      `json:"can_add_devices"`
	CanModifyDevices bool      `json:"can_modify_devices"`
	CanAddUsers      bool      `json:"can_add_users"`
	CanModifyUsers   bool      `json:"can_modify_users"`
	FlickerLow       bool      `json:"flicker_low"`
	FlickerMedium    bool      `json:"flicker_medium"`
	FlickerHigh      bool      `json:"flicker_high"`
	SearchTerms      string    `json:"search_terms"`
	CreatedAt        time.Time `json:"created_at"`
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
			flicker_low INTEGER NOT NULL DEFAULT 0,
			flicker_medium INTEGER NOT NULL DEFAULT 1,
			flicker_high INTEGER NOT NULL DEFAULT 1,
			search_terms TEXT NOT NULL DEFAULT '',
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP
		);
		CREATE INDEX IF NOT EXISTS idx_users_username ON users(username);
	`)
	
	// Add search_terms column if it doesn't exist (for existing databases)
	if err == nil {
		_, _ = db.Exec(`ALTER TABLE users ADD COLUMN search_terms TEXT NOT NULL DEFAULT ''`)
	}

	if err != nil {
		return err
	}

	// Attempt to add new columns for flicker preferences if upgrading from older schema
	// These will fail harmlessly if the columns already exist
	_, _ = db.Exec("ALTER TABLE users ADD COLUMN flicker_low INTEGER NOT NULL DEFAULT 0;")
	_, _ = db.Exec("ALTER TABLE users ADD COLUMN flicker_medium INTEGER NOT NULL DEFAULT 1;")
	_, _ = db.Exec("ALTER TABLE users ADD COLUMN flicker_high INTEGER NOT NULL DEFAULT 1;")

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
		"INSERT INTO users (username, password_hash, is_admin, can_add_devices, can_modify_devices, can_add_users, can_modify_users, flicker_low, flicker_medium, flicker_high) VALUES (?, ?, ?, ?, ?, ?, ?, 0, 1, 1)",
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

// GetUserByID returns a user by their ID
func GetUserByID(id int64) (*User, error) {
	var user User
	err := db.QueryRow("SELECT id, username, is_admin, can_add_devices, can_modify_devices, can_add_users, can_modify_users, flicker_low, flicker_medium, flicker_high, search_terms, created_at FROM users WHERE id = ?", id).
		Scan(&user.ID, &user.Username, &user.IsAdmin, &user.CanAddDevices, &user.CanModifyDevices, &user.CanAddUsers, &user.CanModifyUsers, &user.FlickerLow, &user.FlickerMedium, &user.FlickerHigh, &user.SearchTerms, &user.CreatedAt)
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
	err := db.QueryRow("SELECT id, username, is_admin, can_add_devices, can_modify_devices, can_add_users, can_modify_users, flicker_low, flicker_medium, flicker_high, search_terms, created_at FROM users WHERE username = ?", username).
		Scan(&user.ID, &user.Username, &user.IsAdmin, &user.CanAddDevices, &user.CanModifyDevices, &user.CanAddUsers, &user.CanModifyUsers, &user.FlickerLow, &user.FlickerMedium, &user.FlickerHigh, &user.SearchTerms, &user.CreatedAt)
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
	rows, err := db.Query("SELECT id, username, is_admin, can_add_devices, can_modify_devices, can_add_users, can_modify_users, flicker_low, flicker_medium, flicker_high, search_terms, created_at FROM users")
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var users []User
	for rows.Next() {
		var user User
		if err := rows.Scan(&user.ID, &user.Username, &user.IsAdmin, &user.CanAddDevices, &user.CanModifyDevices, &user.CanAddUsers, &user.CanModifyUsers, &user.FlickerLow, &user.FlickerMedium, &user.FlickerHigh, &user.SearchTerms, &user.CreatedAt); err != nil {
			return nil, err
		}
		users = append(users, user)
	}
	return users, nil
}

// UpdateUser updates a user's information
func UpdateUser(id int64, username string, isAdmin bool, canAddDevices bool, canModifyDevices bool, canAddUsers bool, canModifyUsers bool, flickerLow bool, flickerMedium bool, flickerHigh bool, searchTerms string) error {
	_, err := db.Exec("UPDATE users SET username = ?, is_admin = ?, can_add_devices = ?, can_modify_devices = ?, can_add_users = ?, can_modify_users = ?, flicker_low = ?, flicker_medium = ?, flicker_high = ?, search_terms = ? WHERE id = ?",
		username, isAdmin, canAddDevices, canModifyDevices, canAddUsers, canModifyUsers, flickerLow, flickerMedium, flickerHigh, searchTerms, id)
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

// UpdateUserWithPassword updates a user's information including password
func UpdateUserWithPassword(id int64, username, newPassword string, isAdmin bool, canAddDevices bool, canModifyDevices bool, canAddUsers bool, canModifyUsers bool, flickerLow bool, flickerMedium bool, flickerHigh bool, searchTerms string) error {
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(newPassword), bcrypt.DefaultCost)
	if err != nil {
		return err
	}

	_, err = db.Exec("UPDATE users SET username = ?, password_hash = ?, is_admin = ?, can_add_devices = ?, can_modify_devices = ?, can_add_users = ?, can_modify_users = ?, flicker_low = ?, flicker_medium = ?, flicker_high = ?, search_terms = ? WHERE id = ?",
		username, string(hashedPassword), isAdmin, canAddDevices, canModifyDevices, canAddUsers, canModifyUsers, flickerLow, flickerMedium, flickerHigh, searchTerms, id)
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
