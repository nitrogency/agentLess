package middleware

import (
	"crypto/rand"
	"encoding/base64"
	"net/http"

	"github.com/gin-contrib/sessions"
	"github.com/gin-gonic/gin"
)

const csrfTokenKey = "csrf_token"
const csrfFormField = "csrf_token"

// GenerateCSRFToken generates a new CSRF token
func GenerateCSRFToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(b), nil
}

// CSRFMiddleware adds CSRF protection to forms
func CSRFMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		session := sessions.Default(c)
		
		// For state-changing requests (POST, PUT, DELETE, PATCH)
		if c.Request.Method != "GET" && c.Request.Method != "HEAD" && c.Request.Method != "OPTIONS" {
			// Get token from form
			formToken := c.PostForm(csrfFormField)
			if formToken == "" {
				// Try multipart form
				formToken = c.Request.FormValue(csrfFormField)
			}
			
			// Get token from session
			sessionToken := session.Get(csrfTokenKey)
			
			// Validate token
			if formToken == "" || sessionToken == nil || formToken != sessionToken.(string) {
				c.HTML(http.StatusForbidden, "error", gin.H{
					"Title": "Security Error",
					"Error": "Invalid or missing CSRF token. Please try again.",
				})
				c.Abort()
				return
			}
		}
		
		// Generate new token for GET requests or after successful validation
		token, err := GenerateCSRFToken()
		if err != nil {
			c.AbortWithStatus(http.StatusInternalServerError)
			return
		}
		
		// Store in session
		session.Set(csrfTokenKey, token)
		if err := session.Save(); err != nil {
			c.AbortWithStatus(http.StatusInternalServerError)
			return
		}
		
		// Make token available to templates
		c.Set(csrfTokenKey, token)
		
		c.Next()
	}
}

// GetCSRFToken retrieves the CSRF token from the context
func GetCSRFToken(c *gin.Context) string {
	if token, exists := c.Get(csrfTokenKey); exists {
		return token.(string)
	}
	return ""
}
