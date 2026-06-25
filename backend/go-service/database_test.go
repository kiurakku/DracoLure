package main

import "testing"

func TestGetenvFallback(t *testing.T) {
	t.Setenv("POSTGRES_HOST", "example")
	if got := getenv("POSTGRES_HOST", "db"); got != "example" {
		t.Fatalf("expected example, got %s", got)
	}
	if got := getenv("POSTGRES_MISSING", "fallback"); got != "fallback" {
		t.Fatalf("expected fallback, got %s", got)
	}
}
