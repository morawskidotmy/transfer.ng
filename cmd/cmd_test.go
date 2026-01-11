package cmd

import (
	"testing"
)

func TestParseSize(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected int64
		wantErr  bool
	}{
		{"bytes only", "100", 100, false},
		{"bytes with b suffix", "100b", 100, false},
		{"kilobytes with kb", "1kb", 1024, false},
		{"kilobytes with k", "1k", 1024, false},
		{"megabytes with mb", "1mb", 1024 * 1024, false},
		{"megabytes with m", "1m", 1024 * 1024, false},
		{"gigabytes with gb", "1gb", 1024 * 1024 * 1024, false},
		{"gigabytes with g", "1g", 1024 * 1024 * 1024, false},
		{"terabytes with tb", "1tb", 1024 * 1024 * 1024 * 1024, false},
		{"terabytes with t", "1t", 1024 * 1024 * 1024 * 1024, false},
		{"decimal value", "1.5mb", int64(1.5 * 1024 * 1024), false},
		{"with whitespace", " 100kb ", 100 * 1024, false},
		{"uppercase", "100KB", 100 * 1024, false},
		{"mixed case", "100Mb", 100 * 1024 * 1024, false},
		{"invalid format", "abc", 0, true},
		{"invalid unit", "100xyz", 0, true},
		{"empty string", "", 0, true},
		{"negative value", "-100", 0, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := parseSize(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("parseSize(%q) error = %v, wantErr %v", tt.input, err, tt.wantErr)
				return
			}
			if !tt.wantErr && result != tt.expected {
				t.Errorf("parseSize(%q) = %d, want %d", tt.input, result, tt.expected)
			}
		})
	}
}

func TestNew(t *testing.T) {
	cmd := New()
	if cmd == nil {
		t.Fatal("New() returned nil")
	}
	if cmd.App == nil {
		t.Fatal("New().App is nil")
	}
	if cmd.App.Name != "transfer.ng" {
		t.Errorf("expected app name 'transfer.ng', got %q", cmd.App.Name)
	}
}
