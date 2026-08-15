package whitelist

import (
	"github.com/sahraali252/sentinel/detector/internal/config"
	"testing"
)

func TestAllowsExactCIDRAndEndpoint(t *testing.T) {
	list, err := New(config.Whitelist{SourceIPs: []string{"192.0.2.1"}, CIDRs: []string{"10.0.0.0/8"}, Endpoints: []string{"/health"}})
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		ip, endpoint string
		want         bool
	}{{"192.0.2.1", "/v1", true}, {"10.2.3.4", "/v1", true}, {"203.0.113.2", "/health/deep", true}, {"203.0.113.2", "/v1", false}}
	for _, tt := range tests {
		if got := list.Allows(tt.ip, tt.endpoint); got != tt.want {
			t.Errorf("Allows(%q,%q)=%v want %v", tt.ip, tt.endpoint, got, tt.want)
		}
	}
}
