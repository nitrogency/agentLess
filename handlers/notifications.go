package handlers

import (
    "log"
    "net/http"
    "strconv"

    "github.com/gin-gonic/gin"

    "example/go-website/db"
)

// NotificationsSummaryHandler returns JSON with unseen count and counts by level, plus a few recent unseen notifications
func NotificationsSummaryHandler(c *gin.Context) {
    // Get current user ID from session
    userID, exists := c.Get("user_id")
    if !exists {
        log.Printf("No user_id in session context")
        c.JSON(http.StatusUnauthorized, gin.H{"error": "Authentication required"})
        return
    }
    
    uid, ok := userID.(int64)
    if !ok {
        log.Printf("Invalid user_id type in session context")
        c.JSON(http.StatusUnauthorized, gin.H{"error": "Authentication required"})
        return
    }

    unseen, err := db.CountUnseenNotifications(uid)
    if err != nil {
        log.Printf("Error counting unseen notifications: %v", err)
        c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to retrieve notification summary"})
        return
    }

    byLevel, err := db.CountNotificationsByLevel(uid, true)
    if err != nil {
        log.Printf("Error counting notifications by level: %v", err)
        c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to retrieve notification summary"})
        return
    }

    recent, err := db.ListNotifications(uid, 10, true)
    if err != nil {
        log.Printf("Error listing recent notifications: %v", err)
        c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to retrieve notification summary"})
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

// NotificationsMarkSeenHandler marks all notifications as seen for the current user
func NotificationsMarkSeenHandler(c *gin.Context) {
    // Get current user ID from session
    userID, exists := c.Get("user_id")
    if !exists {
        log.Printf("No user_id in session context")
        c.JSON(http.StatusUnauthorized, gin.H{"error": "Authentication required"})
        return
    }
    
    uid, ok := userID.(int64)
    if !ok {
        log.Printf("Invalid user_id type in session context")
        c.JSON(http.StatusUnauthorized, gin.H{"error": "Authentication required"})
        return
    }

    if err := db.MarkAllNotificationsSeen(uid); err != nil {
        log.Printf("Error marking all notifications as seen: %v", err)
        c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to mark notifications as seen"})
        return
    }
    c.JSON(http.StatusOK, gin.H{"status": "ok"})
}

// NotificationMarkSeenHandler marks a specific notification as seen
func NotificationMarkSeenHandler(c *gin.Context) {
    // Get current user ID from session
    userID, exists := c.Get("user_id")
    if !exists {
        log.Printf("No user_id in session context")
        c.JSON(http.StatusUnauthorized, gin.H{"error": "Authentication required"})
        return
    }
    
    uid, ok := userID.(int64)
    if !ok {
        log.Printf("Invalid user_id type in session context")
        c.JSON(http.StatusUnauthorized, gin.H{"error": "Authentication required"})
        return
    }
    
    idStr := c.Param("id")
    id, err := strconv.ParseInt(idStr, 10, 64)
    if err != nil {
        log.Printf("Invalid notification ID provided: %s", idStr)
        c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid notification ID"})
        return
    }
    
    // Input validation: ensure ID is positive
    if id <= 0 {
        log.Printf("Invalid notification ID provided: %d", id)
        c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid notification ID"})
        return
    }
    
    if err := db.MarkNotificationSeenByUser(id, uid); err != nil {
        log.Printf("Error marking notification %d as seen for user %d: %v", id, uid, err)
        c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to mark notification as seen"})
        return
    }
    c.JSON(http.StatusOK, gin.H{"status": "ok"})
}
