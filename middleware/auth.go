package middleware

import (
	"net/http"

	"github.com/gin-contrib/sessions"
	"github.com/gin-gonic/gin"

	"example/go-website/db"
	"example/go-website/models"
	"example/go-website/templates"
)

// RequireAuth middleware ensures user is authenticated
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
		
		c.Next()
	}
}

// RequireAdmin middleware ensures user is an admin
func RequireAdmin() gin.HandlerFunc {
	return func(c *gin.Context) {
		session := sessions.Default(c)
		username := session.Get("username")
		
		if username == nil {
			c.Redirect(http.StatusFound, "/login")
			c.Abort()
			return
		}
		
		user, err := db.GetUserByUsername(username.(string))
		if err != nil || user == nil || !user.IsAdmin {
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
