package hkpserver

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
)

// ErrorResponse describes a JSON error response.
type ErrorResponse struct {
	Error *Error `json:"error"`
}

// Error describes an error with code and message.
type Error struct {
	Code    int    `json:"code,omitempty"`
	Message string `json:"message,omitempty"`
}

type Status interface {
	Is(int) bool
	IsError() bool
	Write(http.ResponseWriter)
}

type status struct {
	message string
	code    int
	isError bool
}

func NewStatus(code int, isError bool, message ...string) Status {
	msg := http.StatusText(code)
	if len(message) > 0 {
		msg = strings.Join(message, ": ")
	}
	return &status{msg, code, isError}
}

func NewOKStatus(message ...string) Status {
	return NewStatus(http.StatusOK, false, message...)
}

func NewAcceptedStatus(message ...string) Status {
	return NewStatus(http.StatusAccepted, false, message...)
}

func NewBadRequestStatus(message ...string) Status {
	return NewStatus(http.StatusBadRequest, true, message...)
}

func NewForbiddenStatus(message ...string) Status {
	return NewStatus(http.StatusForbidden, true, message...)
}

func NewMethodNotAllowedStatus(message ...string) Status {
	return NewStatus(http.StatusMethodNotAllowed, true, message...)
}

func NewNotImplementedStatus(message ...string) Status {
	return NewStatus(http.StatusNotImplemented, true, message...)
}

func NewConflictStatus(message ...string) Status {
	return NewStatus(http.StatusConflict, true, message...)
}

func NewInternalServerErrorStatus(message ...string) Status {
	return NewStatus(http.StatusInternalServerError, true, message...)
}

func NewNotFoundStatus(message ...string) Status {
	return NewStatus(http.StatusNotFound, true, message...)
}

func NewTooManyRequestStatus(message ...string) Status {
	return NewStatus(http.StatusTooManyRequests, true, message...)
}

func (s *status) IsError() bool {
	return s.isError
}

func (s *status) Write(w http.ResponseWriter) {
	if s.isError || s.code == http.StatusAccepted {
		w.WriteHeader(s.code)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(&ErrorResponse{
			&Error{
				Code:    s.code,
				Message: s.message,
			},
		})
	} else {
		fmt.Fprintf(w, "%s\n", s.message)
	}
}

func (s *status) Is(code int) bool {
	return s.code == code
}
