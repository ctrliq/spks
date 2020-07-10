package hkpserver

import (
	"fmt"
	"net/http"
	"strings"
)

type Status interface {
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
		msg = strings.Join(message, ":")
	}
	return &status{msg, code, isError}
}

func NewOKStatus(message ...string) Status {
	return NewStatus(http.StatusOK, false, message...)
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

func (s *status) IsError() bool {
	return s.isError
}

func (s *status) Write(w http.ResponseWriter) {
	if s.isError {
		http.Error(w, s.message, s.code)
	} else {
		fmt.Fprintf(w, "%s\n", s.message)
	}
}
