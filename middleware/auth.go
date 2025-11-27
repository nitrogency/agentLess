package middleware

import (
	"net/http"

	"github.com/gin-contrib/sessions"
	"github.com/gin-gonic/gin"

	"agentless/db"
	"agentless/models"
	"agentless/templates"
)

// RequireAuth middleware ensures user is authenticated and sets user context
func RequireAuth() gin.HandlerFunc {
	return func(c *gin.Context) {
		session := sessions.Default(c)
		authenticated := session.Get("authenticated")
		username := session.Get("username")

		if authenticated == nil || authenticated != true || username == nil {
			c.Redirect(http.StatusFound, "/login")
			c.Abort()
			return
		}

		// Get user details and set in context for handlers to use
		user, err := db.GetUserByUsername(username.(string))
		if err != nil || user == nil {
			c.Redirect(http.StatusFound, "/login")
			c.Abort()
			return
		}

		// Set user information in context
		c.Set("user_id", user.ID)
		c.Set("username", user.Username)
		c.Set("is_admin", user.IsAdmin)

		c.Next()
	}
}

// RequireAdmin middleware ensures user is an admin
func RequireAdmin() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Get admin status from context (set by RequireAuth middleware)
		isAdmin, exists := c.Get("is_admin")

		if !exists || isAdmin != true {
			templates.RenderGinTemplate(c, "404", models.PageData{
				Title: "403 - Forbidden",
				Error: "You don't have permission to access this resource.",
			})
			c.Abort()
			return
		}

		c.Next()
	}
}
