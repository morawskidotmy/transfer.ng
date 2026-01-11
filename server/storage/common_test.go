package storage

import (
	"testing"
)

func TestParseRange(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected *Range
	}{
		{
			name:     "empty string",
			input:    "",
			expected: nil,
		},
		{
			name:     "valid range with start and end",
			input:    "bytes=0-499",
			expected: &Range{Start: 0, Limit: 500},
		},
		{
			name:     "valid range with only start",
			input:    "bytes=500-",
			expected: &Range{Start: 500, Limit: 0},
		},
		{
			name:     "valid range with large numbers",
			input:    "bytes=1000-1999",
			expected: &Range{Start: 1000, Limit: 1000},
		},
		{
			name:     "invalid format - missing bytes prefix",
			input:    "0-499",
			expected: nil,
		},
		{
			name:     "invalid format - wrong prefix",
			input:    "chars=0-499",
			expected: nil,
		},
		{
			name:     "invalid range - end before start",
			input:    "bytes=500-100",
			expected: nil,
		},
		{
			name:     "invalid format - no start",
			input:    "bytes=-500",
			expected: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ParseRange(tt.input)
			if tt.expected == nil {
				if result != nil {
					t.Errorf("expected nil, got %+v", result)
				}
				return
			}
			if result == nil {
				t.Errorf("expected %+v, got nil", tt.expected)
				return
			}
			if result.Start != tt.expected.Start || result.Limit != tt.expected.Limit {
				t.Errorf("expected Start=%d Limit=%d, got Start=%d Limit=%d",
					tt.expected.Start, tt.expected.Limit, result.Start, result.Limit)
			}
		})
	}
}

func TestRange_Range(t *testing.T) {
	tests := []struct {
		name     string
		rng      Range
		expected string
	}{
		{
			name:     "range with limit",
			rng:      Range{Start: 0, Limit: 500},
			expected: "bytes=0-499",
		},
		{
			name:     "range without limit",
			rng:      Range{Start: 500, Limit: 0},
			expected: "bytes=500-",
		},
		{
			name:     "range with offset and limit",
			rng:      Range{Start: 1000, Limit: 500},
			expected: "bytes=1000-1499",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.rng.Range()
			if result != tt.expected {
				t.Errorf("expected %q, got %q", tt.expected, result)
			}
		})
	}
}

func TestRange_AcceptLength(t *testing.T) {
	tests := []struct {
		name           string
		rng            Range
		contentLength  uint64
		expectedLength uint64
		expectedCR     string
	}{
		{
			name:           "full range accepted",
			rng:            Range{Start: 0, Limit: 500},
			contentLength:  1000,
			expectedLength: 500,
			expectedCR:     "bytes 0-499/1000",
		},
		{
			name:           "open-ended range",
			rng:            Range{Start: 500, Limit: 0},
			contentLength:  1000,
			expectedLength: 500,
			expectedCR:     "bytes 500-999/1000",
		},
		{
			name:           "start beyond content length",
			rng:            Range{Start: 2000, Limit: 500},
			contentLength:  1000,
			expectedLength: 1000,
			expectedCR:     "",
		},
		{
			name:           "limit exceeds remaining content",
			rng:            Range{Start: 800, Limit: 500},
			contentLength:  1000,
			expectedLength: 1000,
			expectedCR:     "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.rng.AcceptLength(tt.contentLength)
			if result != tt.expectedLength {
				t.Errorf("expected length %d, got %d", tt.expectedLength, result)
			}
			if tt.rng.ContentRange() != tt.expectedCR {
				t.Errorf("expected content-range %q, got %q", tt.expectedCR, tt.rng.ContentRange())
			}
		})
	}
}

func TestRange_SetContentRange(t *testing.T) {
	rng := &Range{}
	rng.SetContentRange("bytes 0-499/1000")
	if rng.ContentRange() != "bytes 0-499/1000" {
		t.Errorf("expected 'bytes 0-499/1000', got %q", rng.ContentRange())
	}
}

func TestCloseCheck(t *testing.T) {
	CloseCheck(nil)
}
