package templates

import (
	"fmt"
	"html/template"
	"log"
	"net/http"

	"github.com/gin-contrib/sessions"
	"github.com/gin-gonic/gin"

	"example/go-website/db"
	"example/go-website/models"
)

// RenderGinTemplate renders a template with layout pattern for Gin
func RenderGinTemplate(c *gin.Context, tmpl string, data models.PageData) {
	// Create template with functions
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
		"deviceName": func(id int64) string {
			return db.GetDeviceNameByID(id)
		},
	}

	// Parse both layout and specific template
	t, err := template.New("layout.html").Funcs(funcMap).ParseFiles(
		"templates/layout.html",
		fmt.Sprintf("templates/%s.html", tmpl),
	)
	if err != nil {
		log.Printf("Template parsing error: %v", err)
		c.String(http.StatusInternalServerError, "Internal Server Error")
		return
	}

	// Set content type
	c.Header("Content-Type", "text/html; charset=utf-8")
	
	// Execute the layout template
	if err := t.ExecuteTemplate(c.Writer, "layout", data); err != nil {
		log.Printf("Template execution error: %v", err)
		c.String(http.StatusInternalServerError, "Internal Server Error")
		return
	}
}

// GetPageDataFromGin creates a PageData struct with common fields populated from Gin context
func GetPageDataFromGin(c *gin.Context) models.PageData {
	session := sessions.Default(c)
	
	data := models.PageData{
		Data:        make(map[string]interface{}),
		FormData:    make(map[string]string),
		ErrorFields: make(map[string]bool),
	}

	// Check if user is authenticated
	authenticated := session.Get("authenticated")
	if authenticated != true {
		return data
	}

	// Get username from session
	usernameInterface := session.Get("username")
	if usernameInterface == nil {
		return data
	}
	
	username, ok := usernameInterface.(string)
	if !ok {
		return data
	}

	data.Username = username

	// Get user from database to get user ID and other details
	user, err := db.GetUserByUsername(username)
	if err == nil && user != nil {
		data.UserID = user.ID  // Use user ID from database instead of session
		data.IsAdmin = user.IsAdmin
		// Populate flicker preferences
		data.FlickerLow = user.FlickerLow
		data.FlickerMedium = user.FlickerMedium
		data.FlickerHigh = user.FlickerHigh
		// Note: SearchTerms is specific to user and not needed in general page data
	}

	return data
}
