package utils

import (
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// RulesetInfo holds information about an available audit ruleset
type RulesetInfo struct {
	Filename    string
	DisplayName string
	IsDefault   bool
}

// GetAvailableRulesets scans the ruleset directories and returns available audit rule files
// It looks for .rules files in the rulesets/x32 and rulesets/x64 directories
func GetAvailableRulesets(arch string) ([]RulesetInfo, error) {
	var rulesets []RulesetInfo

	// Validate architecture
	if arch != "x32" && arch != "x64" {
		arch = "x64" // Default to x64
	}

	// Get the ruleset directory path
	rulesetDir := filepath.Join("rulesets", arch)

	// Read directory contents
	entries, err := os.ReadDir(rulesetDir)
	if err != nil {
		// If directory doesn't exist, return empty list
		if os.IsNotExist(err) {
			return rulesets, nil
		}
		return nil, err
	}

	// Process each entry
	for _, entry := range entries {
		// Skip directories
		if entry.IsDir() {
			continue
		}

		filename := entry.Name()

		// Only include .rules files
		if !strings.HasSuffix(filename, ".rules") {
			continue
		}

		// Use filename as display name
		displayName := filename

		// Check if this is the default ruleset
		isDefault := filename == "audit_default.rules"

		rulesets = append(rulesets, RulesetInfo{
			Filename:    filename,
			DisplayName: displayName,
			IsDefault:   isDefault,
		})
	}

	// Sort rulesets: default first, then alphabetically
	sort.Slice(rulesets, func(i, j int) bool {
		// Default always comes first
		if rulesets[i].IsDefault {
			return true
		}
		if rulesets[j].IsDefault {
			return false
		}
		// Otherwise sort alphabetically by filename
		return rulesets[i].Filename < rulesets[j].Filename
	})

	return rulesets, nil
}

// ValidateRuleset checks if a given ruleset file exists for the specified architecture
func ValidateRuleset(arch, ruleset string) bool {
	// Validate architecture
	if arch != "x32" && arch != "x64" {
		return false
	}

	// Check if file exists
	rulesetPath := filepath.Join("rulesets", arch, ruleset)
	_, err := os.Stat(rulesetPath)
	return err == nil
}
