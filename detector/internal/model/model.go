package model

import (
	"encoding/json"
	"time"
)

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

type Finding struct {
	Rule     string
	Severity string
	Message  string
	Metadata map[string]any
}

type Alert struct {
	ID          string          `json:"id"`
	Severity    string          `json:"severity"`
	Rule        string          `json:"rule"`
	SourceIP    string          `json:"source_ip"`
	Timestamp   time.Time       `json:"timestamp"`
	EventID     string          `json:"event_id"`
	Message     string          `json:"message"`
	Metadata    map[string]any  `json:"metadata"`
	RawEvent    json.RawMessage `json:"raw_event"`
	KafkaTopic  string          `json:"kafka_topic"`
	Partition   int32           `json:"kafka_partition"`
	KafkaOffset int64           `json:"kafka_offset"`
}
