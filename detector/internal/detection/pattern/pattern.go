package pattern

import (
	"context"
	"fmt"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/redis/go-redis/v9"
	"github.com/sahraali252/sentinel/detector/internal/detection/window"
	"github.com/sahraali252/sentinel/detector/internal/model"
)

type Detector struct {
	counter            window.Counter
	redis              redis.UniversalClient
	failures           int
	failureWindow      time.Duration
	sequenceLength     int
	maxIDGap           int
	scrapeTTL          time.Duration
	credentialSeverity string
	scrapingSeverity   string
	signatureSeverity  string
	credentialEnabled  bool
	scrapingEnabled    bool
	signaturesEnabled  bool
}

type Options struct {
	Failures           int
	FailureWindow      time.Duration
	SequenceLength     int
	MaxIDGap           int
	ScrapeTTL          time.Duration
	CredentialSeverity string
	ScrapingSeverity   string
	SignatureSeverity  string
	CredentialEnabled  bool
	ScrapingEnabled    bool
	SignaturesEnabled  bool
}

func New(counter window.Counter, client redis.UniversalClient, options Options) *Detector {
	return &Detector{counter: counter, redis: client, failures: options.Failures, failureWindow: options.FailureWindow, sequenceLength: options.SequenceLength, maxIDGap: options.MaxIDGap, scrapeTTL: options.ScrapeTTL, credentialSeverity: options.CredentialSeverity, scrapingSeverity: options.ScrapingSeverity, signatureSeverity: options.SignatureSeverity, credentialEnabled: options.CredentialEnabled, scrapingEnabled: options.ScrapingEnabled, signaturesEnabled: options.SignaturesEnabled}
}

func (d *Detector) Check(ctx context.Context, e model.APIRequest) ([]model.Finding, error) {
	findings := make([]model.Finding, 0, 3)
	if d.signaturesEnabled {
		if finding := SignatureFinding(e, d.signatureSeverity); finding != nil {
			findings = append(findings, *finding)
		}
	}
	if d.credentialEnabled && e.StatusCode == 401 {
		count, err := d.counter.Add(ctx, e.SourceIP, e.ID, e.Timestamp, d.failureWindow)
		if err != nil {
			return nil, err
		}
		if count > int64(d.failures) {
			findings = append(findings, model.Finding{Rule: "credential_stuffing", Severity: d.credentialSeverity, Message: fmt.Sprintf("%d authentication failures in %s", count, d.failureWindow), Metadata: map[string]any{"failures": count, "limit": d.failures, "window_ms": d.failureWindow.Milliseconds()}})
		}
	}
	if d.scrapingEnabled {
		resourceID, ok := trailingResourceID(e.Endpoint)
		if ok {
			finding, err := d.checkSequence(ctx, e.SourceIP, resourceID)
			if err != nil {
				return nil, err
			}
			if finding != nil {
				findings = append(findings, *finding)
			}
		}
	}
	return findings, nil
}

var signatures = []struct {
	name       string
	expression *regexp.Regexp
}{
	{"sql_injection", regexp.MustCompile(`(?i)(union\s+(all\s+)?select|(?:'|%27)\s*(?:or|and)\s+\d+\s*=\s*\d+|drop\s+table|information_schema|--(?:\s|$))`)},
	{"xss", regexp.MustCompile(`(?i)(<\s*script\b|javascript\s*:|on(?:error|load|click)\s*=|<\s*img\b[^>]*onerror)`)},
}

func SignatureFinding(e model.APIRequest, severity string) *model.Finding {
	content := decode(e.Query) + " " + decode(e.Body)
	for _, signature := range signatures {
		if signature.expression.MatchString(content) {
			return &model.Finding{Rule: signature.name, Severity: severity, Message: "known malicious payload signature detected", Metadata: map[string]any{"location": payloadLocation(e)}}
		}
	}
	return nil
}

func decode(value string) string {
	decoded, err := url.QueryUnescape(value)
	if err != nil {
		return value
	}
	return decoded
}
func payloadLocation(e model.APIRequest) string {
	if e.Query != "" && e.Body != "" {
		return "query_and_body"
	}
	if e.Body != "" {
		return "body"
	}
	return "query"
}
func trailingResourceID(endpoint string) (int64, bool) {
	parts := strings.Split(strings.TrimSuffix(endpoint, "/"), "/")
	if len(parts) == 0 {
		return 0, false
	}
	id, err := strconv.ParseInt(parts[len(parts)-1], 10, 64)
	return id, err == nil
}

var scrapingScript = redis.NewScript(`
local last = tonumber(redis.call('HGET', KEYS[1], 'last') or '-1')
local count = tonumber(redis.call('HGET', KEYS[1], 'count') or '0')
local current = tonumber(ARGV[1])
local maxgap = tonumber(ARGV[2])
if last >= 0 and current > last and current - last <= maxgap then count = count + 1 else count = 1 end
redis.call('HSET', KEYS[1], 'last', current, 'count', count)
redis.call('PEXPIRE', KEYS[1], ARGV[3])
return count
`)

func (d *Detector) checkSequence(ctx context.Context, sourceIP string, resourceID int64) (*model.Finding, error) {
	count, err := scrapingScript.Run(ctx, d.redis, []string{"detect:scrape:" + sourceIP}, resourceID, d.maxIDGap, d.scrapeTTL.Milliseconds()).Int()
	if err != nil {
		return nil, fmt.Errorf("update scraping sequence: %w", err)
	}
	if count < d.sequenceLength {
		return nil, nil
	}
	return &model.Finding{Rule: "sequential_scraping", Severity: d.scrapingSeverity, Message: fmt.Sprintf("%d near-sequential resource IDs requested", count), Metadata: map[string]any{"sequence_length": count, "resource_id": resourceID, "max_gap": d.maxIDGap}}, nil
}
