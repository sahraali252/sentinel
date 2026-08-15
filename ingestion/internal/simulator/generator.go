package simulator

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	mathrand "math/rand"
	"net/url"
	"strings"
	"time"

	"github.com/sahraali252/sentinel/ingestion/internal/event"
)

type Mode string

const (
	Normal             Mode = "normal"
	CredentialStuffing Mode = "credential-stuffing"
	Scraping           Mode = "scraping"
	Injection          Mode = "injection"
	Spike              Mode = "spike"
	Mixed              Mode = "mixed"
)

var ValidModes = []Mode{Normal, CredentialStuffing, Scraping, Injection, Spike, Mixed}

type Generator struct {
	rng             *mathrand.Rand
	now             func() time.Time
	clients         []string
	sequenceID      int
	mixedAttackStep int
}

func New(seed int64) *Generator {
	clients := make([]string, 48)
	for i := range clients {
		clients[i] = fmt.Sprintf("10.24.%d.%d", i/16, 20+i)
	}
	return &Generator{rng: mathrand.New(mathrand.NewSource(seed)), now: time.Now, clients: clients, sequenceID: 8400}
}

func (g *Generator) Next(mode Mode, ordinal, attackEvery int) event.APIRequest {
	if mode == Mixed {
		if attackEvery <= 0 || ordinal%attackEvery != 0 {
			mode = Normal
		} else {
			attacks := []Mode{CredentialStuffing, Scraping, Injection, Spike}
			mode = attacks[g.mixedAttackStep%len(attacks)]
			g.mixedAttackStep++
		}
	}
	switch mode {
	case CredentialStuffing:
		return g.credentialStuffing()
	case Scraping:
		return g.scraping()
	case Injection:
		return g.injection()
	case Spike:
		return g.spike()
	default:
		return g.normal()
	}
}

func (g *Generator) normal() event.APIRequest {
	paths := []struct {
		method, endpoint string
		statuses         []int
	}{
		{"GET", "/v1/products", []int{200, 200, 200, 304}},
		{"GET", "/v1/profile", []int{200, 200, 404}},
		{"POST", "/v1/orders", []int{201, 201, 422}},
		{"GET", "/v1/orders/active", []int{200, 200, 503}},
		{"POST", "/v1/auth/refresh", []int{200, 200, 401}},
	}
	choice := paths[g.rng.Intn(len(paths))]
	return g.base(g.clients[g.rng.Intn(len(g.clients))], choice.method, choice.endpoint, choice.statuses[g.rng.Intn(len(choice.statuses))], Normal)
}

func (g *Generator) credentialStuffing() event.APIRequest {
	e := g.base("203.0.113.42", "POST", "/v1/auth/login", 401, CredentialStuffing)
	e.Body = fmt.Sprintf(`{"email":"user%d@example.test","password":"%s"}`, g.rng.Intn(500), randomPassword(g.rng))
	e.ResponseTimeMS = 18 + g.rng.Intn(28)
	return e
}

func (g *Generator) scraping() event.APIRequest {
	g.sequenceID++
	e := g.base("192.0.2.119", "GET", fmt.Sprintf("/v1/products/%d", g.sequenceID), 200, Scraping)
	e.ResponseTimeMS = 25 + g.rng.Intn(20)
	return e
}

func (g *Generator) injection() event.APIRequest {
	payloads := []string{`' UNION SELECT password FROM users--`, `<script>fetch('/steal?c='+document.cookie)</script>`, `1 OR 1=1`, `<img src=x onerror=alert(1)>`}
	payload := payloads[g.rng.Intn(len(payloads))]
	e := g.base("198.51.100.8", "GET", "/v1/search", 400, Injection)
	e.Query = "q=" + url.QueryEscape(payload)
	return e
}

func (g *Generator) spike() event.APIRequest {
	e := g.base("198.51.100.240", "GET", "/v1/catalog", 200, Spike)
	e.ResponseTimeMS = 8 + g.rng.Intn(15)
	return e
}

func (g *Generator) base(ip, method, endpoint string, status int, scenario Mode) event.APIRequest {
	agents := []string{"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 Chrome/126.0", "Mozilla/5.0 (iPhone; CPU iPhone OS 17_5 like Mac OS X) AppleWebKit/605.1.15", "SentinelMobile/4.2 (Android 14)", "curl/8.8.0"}
	return event.APIRequest{SchemaVersion: 1, ID: newID(), Timestamp: g.now().UTC(), SourceIP: ip, Endpoint: endpoint, Method: method, StatusCode: status, UserAgent: agents[g.rng.Intn(len(agents))], ResponseTimeMS: 12 + g.rng.Intn(240), Scenario: string(scenario)}
}

func ParseMode(value string) (Mode, error) {
	normalized := Mode(strings.ToLower(strings.TrimSpace(value)))
	for _, mode := range ValidModes {
		if normalized == mode {
			return normalized, nil
		}
	}
	return "", fmt.Errorf("invalid mode %q (valid: normal, credential-stuffing, scraping, injection, spike, mixed)", value)
}

func newID() string {
	bytes := make([]byte, 16)
	if _, err := rand.Read(bytes); err != nil {
		return fmt.Sprintf("fallback-%d", time.Now().UnixNano())
	}
	return hex.EncodeToString(bytes)
}

func randomPassword(rng *mathrand.Rand) string {
	words := []string{"welcome", "password", "football", "sunshine", "dragon"}
	return fmt.Sprintf("%s%d", words[rng.Intn(len(words))], 10+rng.Intn(9990))
}
