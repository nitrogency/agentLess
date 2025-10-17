package middleware

import (
	"net/http"
	"time"

	"github.com/gin-contrib/sessions"
	"github.com/gin-gonic/gin"
)

// SessionTimeoutMiddleware enforces idle and absolute session timeouts
func SessionTimeoutMiddleware(idleTimeout, absoluteTimeout time.Duration) gin.HandlerFunc {
	return func(c *gin.Context) {
		session := sessions.Default(c)
		
		// Skip timeout checks for unauthenticated sessions
		authenticated := session.Get("authenticated")
		if authenticated == nil || authenticated != true {
			c.Next()
			return
		}
		
		now := time.Now().Unix()
		
		// Check absolute timeout - session age since login
		if loginTime := session.Get("login_time"); loginTime != nil {
			if loginTimeInt, ok := loginTime.(int64); ok {
				sessionAge := now - loginTimeInt
				if sessionAge > int64(absoluteTimeout.Seconds()) {
					// Session too old - force logout
					session.Clear()
					session.Options(sessions.Options{MaxAge: -1})
					session.Save()
					c.Redirect(http.StatusFound, "/login?timeout=session_expired")
					c.Abort()
					return
				}
			}
		}
		
		// Check idle timeout - time since last activity
		if lastActivity := session.Get("last_activity"); lastActivity != nil {
			if lastActivityInt, ok := lastActivity.(int64); ok {
				idleTime := now - lastActivityInt
				if idleTime > int64(idleTimeout.Seconds()) {
					// Session idle too long - force logout
					session.Clear()
					session.Options(sessions.Options{MaxAge: -1})
					session.Save()
					c.Redirect(http.StatusFound, "/login?timeout=idle")
					c.Abort()
					return
				}
			}
		}
		
		// Update last activity timestamp
		session.Set("last_activity", now)
		session.Save()
		
		c.Next()
	}
}
