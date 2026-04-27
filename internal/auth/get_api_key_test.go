package auth

import (
	"errors"
	"net/http"
	"testing"
)

func TestGetAPIKey(t *testing.T) {
	tests := []struct {
		name        string
		headers     http.Header
		expected    string
		expectedErr error
	}{
		{
			name:        "valid api key",
			headers:     http.Header{"Authorization": []string{"ApiKey my-secret-key"}},
			expected:    "my-secret-key",
			expectedErr: nil,
		},
		{
			name:        "missing authorization header",
			headers:     http.Header{},
			expected:    "",
			expectedErr: ErrNoAuthHeaderIncluded,
		},
		{
			name:        "malformed header - wrong prefix",
			headers:     http.Header{"Authorization": []string{"Bearer some-token"}},
			expected:    "",
			expectedErr: errors.New("malformed authorization header"),
		},
		{
			name:        "malformed header - no key value",
			headers:     http.Header{"Authorization": []string{"ApiKey"}},
			expected:    "",
			expectedErr: errors.New("malformed authorization header"),
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			actual, err := GetAPIKey(tc.headers)
			if actual != tc.expected {
				t.Errorf("expected %s, got %s", tc.expected, actual)
			}

			if tc.expectedErr != nil {
				if err == nil {
					t.Fatalf("expected error %v, got nil", tc.expectedErr)
				}
				if err.Error() != tc.expectedErr.Error() {
					t.Errorf("expected error %v, got %v", tc.expectedErr, err)
				}
			} else if err != nil {
				t.Fatalf("expected no error, got %v", err)
			}
		})
	}
}
