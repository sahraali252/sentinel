package event

import "time"

// APIRequest is the versioned wire contract published to raw-events.
type APIRequest struct {
	SchemaVersion  int       `json:"schema_version"`
	ID             string    `json:"id"`
	Timestamp      time.Time `json:"timestamp"`
	SourceIP       string    `json:"source_ip"`
	Endpoint       string    `json:"endpoint"`
	Method         string    `json:"method"`
	StatusCode     int       `json:"status_code"`
	UserAgent      string    `json:"user_agent"`
	ResponseTimeMS int       `json:"response_time_ms"`
	Query          string    `json:"query,omitempty"`
	Body           string    `json:"body,omitempty"`
	Scenario       string    `json:"scenario"`
}
