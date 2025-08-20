package handlers

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

// ApiDeviceHandler handles API requests for device operations
func ApiDeviceHandler(c *gin.Context) {
	c.JSON(http.StatusNotImplemented, gin.H{"error": "API not implemented yet"})
}
