package pattern

import (
	"github.com/sahraali252/sentinel/detector/internal/model"
	"testing"
)

func TestSignatureFinding(t *testing.T) {
	tests := []struct{ name, query, body, rule string }{
		{"SQLi query", "q=%27+UNION+SELECT+password+FROM+users--", "", "sql_injection"},
		{"XSS body", "", `<img src=x onerror=alert(1)>`, "xss"},
		{"benign", "q=unionized+selective+design", "", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := SignatureFinding(model.APIRequest{Query: tt.query, Body: tt.body}, "critical")
			if tt.rule == "" && got != nil {
				t.Fatalf("false positive: %#v", got)
			}
			if tt.rule != "" && (got == nil || got.Rule != tt.rule) {
				t.Fatalf("got %#v want %q", got, tt.rule)
			}
		})
	}
}

func TestTrailingResourceID(t *testing.T) {
	for _, tt := range []struct {
		endpoint string
		id       int64
		ok       bool
	}{{"/v1/items/42", 42, true}, {"/v1/items/42/", 42, true}, {"/v1/items/current", 0, false}} {
		id, ok := trailingResourceID(tt.endpoint)
		if id != tt.id || ok != tt.ok {
			t.Errorf("trailingResourceID(%q)=(%d,%v)", tt.endpoint, id, ok)
		}
	}
}
