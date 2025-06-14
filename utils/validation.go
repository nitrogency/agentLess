package utils

import (
	"errors"
	"net"
	"regexp"
	"strings"
)

// IsValidIPAddress checks if a string is a valid IPv4 or IPv6 address
func IsValidIPAddress(ip string) bool {
	return net.ParseIP(ip) != nil
}

// IsValidHostname checks if a string is a valid hostname
func IsValidHostname(hostname string) bool {
	// Hostname validation regex
	// Allows alphanumeric characters, hyphens, and dots
	// Each label (part between dots) must start and end with alphanumeric
	// Total length must be between 1 and 253 characters
	hostnameRegex := regexp.MustCompile(`^([a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])(\.([a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9\-]{0,61}[a-zA-Z0-9]))*$`)
	return len(hostname) <= 253 && hostnameRegex.MatchString(hostname)
}

// IsValidUsername checks if a string is a valid Unix username
func IsValidUsername(username string) bool {
	// Unix username validation regex
	// Allows lowercase letters, digits, underscores, and hyphens
	// Must start with a letter and be between 1 and 32 characters
	usernameRegex := regexp.MustCompile(`^[a-z][a-z0-9_-]{0,31}$`)
	return usernameRegex.MatchString(username)
}

// IsValidGroupname checks if a string is a valid Unix group name
func IsValidGroupname(groupname string) bool {
	// Unix group name validation regex (similar to username)
	groupRegex := regexp.MustCompile(`^[a-z][a-z0-9_-]{0,31}$`)
	return groupRegex.MatchString(groupname)
}

// IsValidFilePath checks if a string is a valid file path
// This is a basic check to prevent command injection
func IsValidFilePath(path string) bool {
	// Disallow paths with potentially dangerous characters
	dangerousChars := []string{";", "&", "|", ">", "<", "`", "$", "(", ")", "{", "}", "[", "]", "\"", "'", "\\", "\n", "\r"}
	for _, char := range dangerousChars {
		if strings.Contains(path, char) {
			return false
		}
	}
	return true
}

// ValidateCommandInput validates input for command execution
func ValidateCommandInput(input string) error {
	// Check for shell metacharacters that could be used for command injection
	shellMetaChars := []string{";", "&", "|", ">", "<", "`", "$", "(", ")", "{", "}", "[", "]", "\"", "'", "\\", "\n", "\r"}
	for _, char := range shellMetaChars {
		if strings.Contains(input, char) {
			return errors.New("input contains invalid characters that could be used for command injection")
		}
	}
	return nil
}

// SanitizeCommandArg sanitizes a command argument to prevent command injection
func SanitizeCommandArg(arg string) string {
	// Replace any potentially dangerous characters with underscores
	dangerousChars := []string{";", "&", "|", ">", "<", "`", "$", "(", ")", "{", "}", "[", "]", "\"", "'", "\\", "\n", "\r"}
	result := arg
	for _, char := range dangerousChars {
		result = strings.ReplaceAll(result, char, "_")
	}
	return result
}
