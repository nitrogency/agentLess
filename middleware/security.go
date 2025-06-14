package middleware

import (
	"net/http"
)

// SecurityHeaders adds security-related HTTP headers to all responses
func SecurityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Content Security Policy - restricts sources of content
		w.Header().Set("Content-Security-Policy", 
			"default-src 'self'; "+
			"script-src 'self' 'unsafe-inline'; "+
			"style-src 'self' 'unsafe-inline'; "+
			"img-src 'self' data:; "+
			"connect-src 'self'; "+
			"font-src 'self'; "+
			"object-src 'none'; "+
			"media-src 'self'; "+
			"frame-src 'self';")

		// X-XSS-Protection - stops pages from loading when XSS is detected
		w.Header().Set("X-XSS-Protection", "1; mode=block")

		// X-Frame-Options - prevents clickjacking by controlling iframe embedding
		w.Header().Set("X-Frame-Options", "SAMEORIGIN")

		// X-Content-Type-Options - prevents MIME type sniffing
		w.Header().Set("X-Content-Type-Options", "nosniff")

		// Referrer-Policy - controls how much referrer information is included
		w.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")

		// Strict-Transport-Security - enforces HTTPS
		w.Header().Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")

		// Permissions-Policy - controls browser features
		w.Header().Set("Permissions-Policy", "camera=(), microphone=(), geolocation=(), interest-cohort=()")

		// Cache-Control - prevents sensitive information caching
		w.Header().Set("Cache-Control", "no-cache, no-store, max-age=0, must-revalidate")
		w.Header().Set("Pragma", "no-cache")
		w.Header().Set("Expires", "0")

		next.ServeHTTP(w, r)
	})
}
