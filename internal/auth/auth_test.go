package auth

import (
	"net/http"
	"testing"
)

func TestGetAPIKeyBasic(t *testing.T) {
	headings := http.Header{}
	headings.Add("Authorization", "ApiKey testapikey")
	expected := "testapikey"

	apiKey, err := GetAPIKey(headings)
	if err != nil {
		t.Errorf("ERROR: %v", err)
		return
	}

    if apiKey != expected {
        t.Errorf("GetAPIKey(%v) = %s; expected %s\n", headings, apiKey, expected)
    }
}

func TestGetAPIKeyEmptyHeader(t *testing.T) {
	headings := http.Header{}
	expectedErr := ErrNoAuthHeaderIncluded

	apiKey, err := GetAPIKey(headings)
	if err != nil {
		if err != expectedErr {
			t.Errorf("ERROR: %v", err)
		}
		return
	}

	t.Errorf("GetAPIKey(%v) = %s; expected err = %v\n", headings, apiKey, expectedErr)
}

func TestGetAPIKeyMalformedHeader(t *testing.T) {
	headings := http.Header{}
	headings.Add("Authorization", "Foobar testapikey")
	expectedErr := ErrMalformedAuthHeader

	apiKey, err := GetAPIKey(headings)
	if err != nil {
		if err != expectedErr {
			t.Errorf("ERROR: %v", err)
		}
		return
	}

	t.Errorf("GetAPIKey(%v) = %s; expected err = %v\n", headings, apiKey, expectedErr)
}
