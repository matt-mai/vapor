package retry

import (
	"net/http"
	"strconv"
	"time"
)

// Status reports whether an HTTP status may pass on a retry. A rate limit and a
// server-side failure are transient; a missing file or a bad request is the answer,
// and asking again only wastes the caller's time.
func Status(status int) bool {
	switch status {
	case http.StatusRequestTimeout, http.StatusTooManyRequests,
		http.StatusInternalServerError, http.StatusBadGateway,
		http.StatusServiceUnavailable, http.StatusGatewayTimeout:
		return true
	default:
		return false
	}
}

// After reads the delay a server asked for, in either form the Retry-After header
// allows. Zero means the server named no delay, or named one already past.
func After(response *http.Response) time.Duration {
	header := response.Header.Get("Retry-After")
	if header == "" {
		return 0
	}
	if seconds, err := strconv.Atoi(header); err == nil && seconds > 0 {
		return time.Duration(seconds) * time.Second
	}
	if when, err := http.ParseTime(header); err == nil {
		if delay := time.Until(when); delay > 0 {
			return delay
		}
	}
	return 0
}
