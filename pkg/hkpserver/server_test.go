package hkpserver

import (
	"context"
	"testing"
	"time"
)

func TestServer(t *testing.T) {
	cfg := Config{}

	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()

	if err := Start(ctx, cfg); err != nil {
		t.Fatalf("unexpected error: %s", err)
	}
}
