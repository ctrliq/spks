package hkpserver

import (
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/sirupsen/logrus"
)

// logResponseWriter wraps an http.ResponseWriter to intercept
// the http code status returned by an HTTP handler.
type logResponseWriter struct {
	http.ResponseWriter
	code int
	size int
}

// WriteHeader records the HTTP status code as it is written.
func (lw *logResponseWriter) WriteHeader(code int) {
	lw.code = code
	lw.ResponseWriter.WriteHeader(code)
}

// Write accumulates the response size as the response is written.
func (lw *logResponseWriter) Write(b []byte) (int, error) {
	n, err := lw.ResponseWriter.Write(b)
	lw.size += n
	return n, err
}

// remoteIP attempts to find the remote IP associated with a HTTP request.
func remoteIP(req *http.Request) string {
	realIP := req.Header.Get("X-Real-Ip")
	forwardedFor := req.Header.Get("X-Forwarded-For")
	if realIP == "" && forwardedFor == "" {
		ip, _, _ := net.SplitHostPort(req.RemoteAddr)
		return ip
	} else if forwardedFor != "" {
		parts := strings.Split(forwardedFor, ",")
		return strings.TrimSpace(parts[0])
	}
	return realIP
}

// LogRequestHandler provides an HTTP handler to log HTTP requests.
func LogRequestHandler(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()

		lw := &logResponseWriter{w, http.StatusOK, 0}
		h.ServeHTTP(lw, r)

		entry := logrus.WithFields(logrus.Fields{
			"remote":  remoteIP(r),
			"code":    lw.code,
			"size":    lw.size,
			"host":    r.Host,
			"method":  r.Method,
			"path":    r.RequestURI,
			"referer": r.Referer(),
			"agent":   r.UserAgent(),
			"took":    time.Since(start),
		})
		entry.Info("http request")
	})
}
