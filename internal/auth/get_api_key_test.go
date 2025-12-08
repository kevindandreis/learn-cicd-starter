package auth

import (
	"errors"
	"net/http"
	"testing"
)

func TestGetAPIKey(t *testing.T) {
	tests := []struct {
		name          string
		headers       http.Header
		expectedKey   string
		expectedError error
	}{
		{
			name:          "Valid API key",
			headers:       http.Header{"Authorization": []string{"ApiKey test-api-key-123"}},
			expectedKey:   "test-api-key-123",
			expectedError: nil,
		},
		{
			name:          "Missing authorization header",
			headers:       http.Header{},
			expectedKey:   "",
			expectedError: ErrNoAuthHeaderIncluded,
		},
		{
			name:          "Malformed authorization header - missing ApiKey prefix",
			headers:       http.Header{"Authorization": []string{"Bearer token123"}},
			expectedKey:   "",
			expectedError: errors.New("malformed authorization header"),
		},
		{
			name:          "Malformed authorization header - invalid format",
			headers:       http.Header{"Authorization": []string{"ApiKey"}},
			expectedKey:   "",
			expectedError: errors.New("malformed authorization header"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			key, err := GetAPIKey(tt.headers)

			// Check if the error matches expected
			if (err != nil && tt.expectedError == nil) ||
				(err == nil && tt.expectedError != nil) ||
				(err != nil && tt.expectedError != nil && err.Error() != tt.expectedError.Error()) {
				t.Errorf("GetAPIKey() error = %v, expectedError %v", err, tt.expectedError)
				return
			}

			// Check if the returned key matches expected
			if key != tt.expectedKey {
				t.Errorf("GetAPIKey() = %v, want %v", key, tt.expectedKey)
			}
		})
	}
}
