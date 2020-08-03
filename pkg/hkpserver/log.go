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
	ip   string
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
	realIP := ""
	forwardedFor := ""

	ip, _, _ := net.SplitHostPort(req.RemoteAddr)
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return ip
	}

	if parsed.IsLoopback() {
		realIP = req.Header.Get("X-Real-Ip")
		forwardedFor = req.Header.Get("X-Forwarded-For")
	} else {
		private := false
		for _, pn := range privateNet {
			if pn.Contains(parsed) {
				private = true
				break
			}
		}
		// within private range, looks for reverse proxy headers
		if private {
			realIP = req.Header.Get("X-Real-Ip")
			forwardedFor = req.Header.Get("X-Forwarded-For")
		}
	}

	if realIP != "" {
		if net.ParseIP(realIP) != nil {
			return realIP
		}
	} else if forwardedFor != "" {
		parts := strings.Split(forwardedFor, ",")
		forwardedIP := strings.TrimSpace(parts[0])
		if net.ParseIP(forwardedIP) != nil {
			return forwardedIP
		}
	}

	return ip
}

// LogRequestHandler provides an HTTP handler to log HTTP requests.
func LogRequestHandler(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()

		lw := &logResponseWriter{w, http.StatusOK, 0, remoteIP(r)}
		h.ServeHTTP(lw, r)

		entry := logrus.WithFields(logrus.Fields{
			"remote":  lw.ip,
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

var privateNet = map[string]*net.IPNet{
	"10.0.0.0/8":     nil,
	"172.16.0.0/12":  nil,
	"192.168.0.0/16": nil,
	"fc00::/7":       nil,
}

func init() {
	for k := range privateNet {
		_, privateNet[k], _ = net.ParseCIDR(k)
	}
}
