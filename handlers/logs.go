package handlers

import (
	"github.com/gin-gonic/gin"

	"example/go-website/templates"
)

// AllLogsHandler handles system audit logs viewing
func AllLogsHandler(c *gin.Context) {
	data := templates.GetPageDataFromGin(c)
	data.Title = "System Audit Logs"
	
	// Set pagination defaults
	data.Data["CurrentPage"] = 1
	data.Data["TotalPages"] = 1
	data.Data["PageSize"] = 50
	data.Data["TotalLogs"] = 0
	data.Data["Logs"] = []interface{}{}
	
	templates.RenderGinTemplate(c, "logs", data)
}
