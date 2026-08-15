package engine

import "testing"

func TestAlertIDIsDeterministicAndRuleSpecific(t *testing.T) {
	a := alertID("event-1", "rate")
	if a != alertID("event-1", "rate") {
		t.Fatal("ID not deterministic")
	}
	if a == alertID("event-1", "xss") {
		t.Fatal("different rules must produce different IDs")
	}
}
