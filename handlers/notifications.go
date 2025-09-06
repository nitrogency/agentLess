package handlers

import (
    "net/http"

    "github.com/gin-gonic/gin"

    "example/go-website/db"
)

// NotificationsSummaryHandler returns JSON with unseen count and counts by level, plus a few recent unseen notifications
func NotificationsSummaryHandler(c *gin.Context) {
    unseen, err := db.CountUnseenNotifications()
    if err != nil {
        c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
        return
    }

    byLevel, err := db.CountNotificationsByLevel(true)
    if err != nil {
        c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
        return
    }

    recent, err := db.ListNotifications(10, true)
    if err != nil {
        c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
        return
    }

    c.JSON(http.StatusOK, gin.H{
        "unseen": unseen,
        "byLevel": gin.H{
            "low":    byLevel[db.NotificationLow],
            "medium": byLevel[db.NotificationMedium],
            "high":   byLevel[db.NotificationHigh],
        },
        "recent": recent,
    })
}

// NotificationsMarkSeenHandler marks all notifications as seen
func NotificationsMarkSeenHandler(c *gin.Context) {
    if err := db.MarkAllNotificationsSeen(); err != nil {
        c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
        return
    }
    c.JSON(http.StatusOK, gin.H{"status": "ok"})
}
