package models

import "example/go-website/db"

// PageData represents the data structure passed to templates
type PageData struct {
	Title               string
	Error               string
	Success             string
	Content             string
	Username            string
	UserID              int64
	IsAdmin             bool
	Users               []db.User
	Devices             []db.Device
	User                *db.User
	Device              db.Device
	RandomUser          bool
	RandomKey           bool
	FormToken           string
	FormData            map[string]string
	ErrorFields         map[string]bool
	MonitoringData      map[string]string
	Data                map[string]interface{}
	HasHighSecurityLogs bool
}
