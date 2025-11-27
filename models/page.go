package models

import "agentless/db"

// PageData represents the data structure passed to templates
type PageData struct {
	Title               string
	Error               string
	Success             string
	Content             string
	Username            string
	UserID              int64
	IsAdmin             bool
	CanAddDevices       bool
	CanModifyDevices    bool
	CanAddUsers         bool
	CanModifyUsers      bool
	Users               []db.User
	Devices             []db.Device
	User                *db.User
	Device              db.Device
	FormToken           string
	FormData            map[string]string
	ErrorFields         map[string]bool
	MonitoringData      map[string]string
	Data                map[string]interface{}
	HasHighSecurityLogs bool
	FlickerLow          bool
	FlickerMedium       bool
	FlickerHigh         bool
}
