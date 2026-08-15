package simulator

import (
	"net/url"
	"strconv"
	"strings"
	"testing"
)

func TestCredentialStuffingHasStableSourceAndUnauthorizedStatus(t *testing.T) {
	g := New(1)
	first, second := g.Next(CredentialStuffing, 1, 10), g.Next(CredentialStuffing, 2, 10)
	if first.SourceIP != second.SourceIP || first.StatusCode != 401 || second.StatusCode != 401 {
		t.Fatalf("expected repeated 401s from one IP: %#v %#v", first, second)
	}
}

func TestScrapingIDsAreSequential(t *testing.T) {
	g := New(1)
	a, b := g.Next(Scraping, 1, 10), g.Next(Scraping, 2, 10)
	parseID := func(endpoint string) int {
		parts := strings.Split(endpoint, "/")
		value, _ := strconv.Atoi(parts[len(parts)-1])
		return value
	}
	if parseID(b.Endpoint)-parseID(a.Endpoint) != 1 {
		t.Fatalf("expected sequential IDs, got %s then %s", a.Endpoint, b.Endpoint)
	}
}

func TestInjectionPayloadIsEncodedInQuery(t *testing.T) {
	g := New(2)
	e := g.Next(Injection, 1, 10)
	query, err := url.ParseQuery(e.Query)
	if err != nil || query.Get("q") == "" {
		t.Fatalf("expected parseable malicious query, got %q (%v)", e.Query, err)
	}
}

func TestMixedOnlyInjectsAtConfiguredInterval(t *testing.T) {
	g := New(1)
	for i := 1; i <= 9; i++ {
		got := g.Next(Mixed, i, 5).Scenario
		if i%5 == 0 && got == string(Normal) {
			t.Fatalf("event %d should be malicious", i)
		}
		if i%5 != 0 && got != string(Normal) {
			t.Fatalf("event %d should be normal, got %q", i, got)
		}
	}
}

func TestParseModeRejectsUnknownMode(t *testing.T) {
	if _, err := ParseMode("not-a-mode"); err == nil {
		t.Fatal("expected invalid mode error")
	}
}
