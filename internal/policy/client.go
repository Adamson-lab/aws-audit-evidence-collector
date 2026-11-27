package policy

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"
)

type EmergencyAudit struct {
	Enabled       bool   `json:"enabled"`
	AuditID       string `json:"audit_id"`
	Justification string `json:"justification"`
}

type CheckInput struct {
	CorrelationID  string         `json:"correlation_id"`
	Collector      string         `json:"collector"`
	Role           string         `json:"role"`
	Framework      string         `json:"framework"`
	Region         string         `json:"region"`
	UTCHour        int            `json:"utc_hour"`
	EmergencyAudit EmergencyAudit `json:"emergency_audit"`
}

type Decision struct {
	Allowed bool   `json:"allowed"`
	Reason  string `json:"reason"`
}

type opaResponse struct {
	Result *Decision `json:"result"`
}

type Client struct {
	baseURL    string
	httpClient *http.Client
}

func NewClient(baseURL string, timeout time.Duration) *Client {
	if timeout <= 0 {
		timeout = 3 * time.Second
	}
	return &Client{
		baseURL: strings.TrimRight(baseURL, "/"),
		httpClient: &http.Client{
			Timeout: timeout,
		},
	}
}

func (c *Client) EvaluateAll(ctx context.Context, in CheckInput) (Decision, error) {
	sov, err := c.queryRule(ctx, "/v1/data/audit/sovereignty", in)
	if err != nil {
		return Decision{}, fmt.Errorf("sovereignty policy check failed: %w", err)
	}
	if !sov.Allowed {
		return sov, nil
	}

	win, err := c.queryRule(ctx, "/v1/data/audit/window", in)
	if err != nil {
		return Decision{}, fmt.Errorf("collection window policy check failed: %w", err)
	}
	return win, nil
}

func (c *Client) queryRule(ctx context.Context, path string, in CheckInput) (Decision, error) {
	raw, err := json.Marshal(map[string]any{"input": in})
	if err != nil {
		return Decision{}, fmt.Errorf("marshal opa input: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+path, bytes.NewReader(raw))
	if err != nil {
		return Decision{}, fmt.Errorf("build opa request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	if in.CorrelationID != "" {
		req.Header.Set("X-Correlation-ID", in.CorrelationID)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return Decision{}, fmt.Errorf("opa request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return Decision{}, fmt.Errorf("opa returned status %d", resp.StatusCode)
	}

	var env opaResponse
	if err := json.NewDecoder(resp.Body).Decode(&env); err != nil {
		return Decision{}, fmt.Errorf("decode opa response: %w", err)
	}
	if env.Result == nil {
		return Decision{}, fmt.Errorf("opa response missing result")
	}
	return *env.Result, nil
}
