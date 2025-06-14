package middleware

import (
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"
)

// RateLimiter provides rate limiting functionality
type RateLimiter struct {
	mu           sync.Mutex
	ipAttempts   map[string][]time.Time
	maxAttempts  int           // Maximum number of attempts allowed
	windowPeriod time.Duration // Time window for rate limiting
	blockPeriod  time.Duration // How long to block after max attempts
}

// NewRateLimiter creates a new rate limiter
func NewRateLimiter(maxAttempts int, windowPeriod, blockPeriod time.Duration) *RateLimiter {
	return &RateLimiter{
		ipAttempts:   make(map[string][]time.Time),
		maxAttempts:  maxAttempts,
		windowPeriod: windowPeriod,
		blockPeriod:  blockPeriod,
	}
}

// cleanupOldAttempts removes attempts that are outside the window period
func (rl *RateLimiter) cleanupOldAttempts(ip string, now time.Time) {
	cutoff := now.Add(-rl.windowPeriod)
	newAttempts := []time.Time{}
	
	for _, attemptTime := range rl.ipAttempts[ip] {
		if attemptTime.After(cutoff) {
			newAttempts = append(newAttempts, attemptTime)
		}
	}
	
	rl.ipAttempts[ip] = newAttempts
}

// IsAllowed checks if an IP is allowed to make another attempt
func (rl *RateLimiter) IsAllowed(ip string) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	
	now := time.Now()
	
	// Clean up old attempts
	rl.cleanupOldAttempts(ip, now)
	
	// Check if IP is currently blocked
	attempts := rl.ipAttempts[ip]
	if len(attempts) >= rl.maxAttempts {
		// Check if the oldest attempt (after cleanup) is within the block period
		oldestBlockingAttempt := attempts[len(attempts)-rl.maxAttempts]
		blockUntil := oldestBlockingAttempt.Add(rl.blockPeriod)
		
		if now.Before(blockUntil) {
			return false // IP is blocked
		}
	}
	
	return true
}

// RecordAttempt records a login attempt for an IP
func (rl *RateLimiter) RecordAttempt(ip string) {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	
	now := time.Now()
	
	// Clean up old attempts first
	rl.cleanupOldAttempts(ip, now)
	
	// Record this attempt
	rl.ipAttempts[ip] = append(rl.ipAttempts[ip], now)
}

// GetRemainingAttempts returns the number of attempts remaining for an IP
func (rl *RateLimiter) GetRemainingAttempts(ip string) int {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	
	now := time.Now()
	
	// Clean up old attempts
	rl.cleanupOldAttempts(ip, now)
	
	return rl.maxAttempts - len(rl.ipAttempts[ip])
}

// TimeUntilUnblock returns the time until an IP is unblocked
func (rl *RateLimiter) TimeUntilUnblock(ip string) time.Duration {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	
	now := time.Now()
	
	// Clean up old attempts
	rl.cleanupOldAttempts(ip, now)
	
	attempts := rl.ipAttempts[ip]
	if len(attempts) < rl.maxAttempts {
		return 0 // Not blocked
	}
	
	// Calculate time until unblock
	oldestBlockingAttempt := attempts[len(attempts)-rl.maxAttempts]
	blockUntil := oldestBlockingAttempt.Add(rl.blockPeriod)
	
	if now.After(blockUntil) {
		return 0 // Already unblocked
	}
	
	return blockUntil.Sub(now)
}

// RateLimitMiddleware is a middleware that limits login attempts
func (rl *RateLimiter) RateLimitMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ip := getClientIP(r)
		
		if !rl.IsAllowed(ip) {
			// IP is rate limited
			w.WriteHeader(http.StatusTooManyRequests)
			timeLeft := rl.TimeUntilUnblock(ip)
			w.Write([]byte(fmt.Sprintf("Too many login attempts. Please try again in %d minutes.", int(timeLeft.Minutes()))))
			return
		}
		
		// Continue with the request
		next.ServeHTTP(w, r)
	})
}

// getClientIP extracts the client IP from the request
func getClientIP(r *http.Request) string {
	// Check for X-Forwarded-For header first (for proxies)
	ip := r.Header.Get("X-Forwarded-For")
	if ip != "" {
		return ip
	}
	
	// Otherwise use RemoteAddr
	ip = r.RemoteAddr
	// Strip port if present
	if i := strings.LastIndex(ip, ":"); i != -1 {
		ip = ip[:i]
	}
	return ip
}
