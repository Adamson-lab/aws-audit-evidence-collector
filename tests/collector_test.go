package tests

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/s3"

	"github.com/Adamson-lab/aws-audit-evidence-collector/internal/awsevidence"
	"github.com/Adamson-lab/aws-audit-evidence-collector/internal/policy"
	"github.com/Adamson-lab/aws-audit-evidence-collector/internal/server"
	"github.com/Adamson-lab/aws-audit-evidence-collector/internal/webhook"
)

func TestWebhookSignatureAndReplayWindow(t *testing.T) {
	secret := "unit-test-secret"
	v := webhook.NewVerifier(secret, 5*time.Minute)
	body := []byte(`{"framework":"fedramp","region":"us-east-1"}`)
	now := time.Now().UTC().Unix()

	validSig := webhook.ComputeSignature([]byte(secret), now, body)
	if err := v.Verify(validSig, strconv.FormatInt(now, 10), body); err != nil {
		t.Fatalf("expected valid signature to pass, got: %v", err)
	}

	if err := v.Verify("sha256=0000", strconv.FormatInt(now, 10), body); !errors.Is(err, webhook.ErrInvalidSignature) {
		t.Fatalf("expected ErrInvalidSignature, got: %v", err)
	}

	staleTS := now - 400
	staleSig := webhook.ComputeSignature([]byte(secret), staleTS, body)
	if err := v.Verify(staleSig, strconv.FormatInt(staleTS, 10), body); !errors.Is(err, webhook.ErrTimestampSkew) {
		t.Fatalf("expected ErrTimestampSkew, got: %v", err)
	}
}

func TestPolicyClientSovereigntyAndWindow(t *testing.T) {
	opaStub := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Input policy.CheckInput `json:"input"`
		}
		_ = json.NewDecoder(r.Body).Decode(&req)

		switch r.URL.Path {
		case "/v1/data/audit/sovereignty":
			allowed := !(req.Input.Framework == "fedramp" && req.Input.Region == "eu-central-1")
			reason := "allowed: target region complies with framework residency"
			if !allowed {
				reason = "denied: bucket region violates data residency policy"
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"result": policy.Decision{Allowed: allowed, Reason: reason}})
		case "/v1/data/audit/window":
			allowed := (req.Input.UTCHour >= 4 && req.Input.UTCHour <= 23) || req.Input.EmergencyAudit.Enabled
			reason := "allowed within scheduled UTC collection window"
			if !allowed {
				reason = "denied: evidence collection outside UTC window without active audit override"
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"result": policy.Decision{Allowed: allowed, Reason: reason}})
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer opaStub.Close()

	client := policy.NewClient(opaStub.URL, 2*time.Second)
	ctx := context.Background()

	deniedSov, err := client.EvaluateAll(ctx, policy.CheckInput{
		Role:      "compliance-auditor",
		Framework: "fedramp",
		Region:    "eu-central-1",
		UTCHour:   12,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if deniedSov.Allowed {
		t.Fatalf("expected fedramp in eu-central-1 to be denied")
	}

	allowedBG, err := client.EvaluateAll(ctx, policy.CheckInput{
		Role:      "compliance-auditor",
		Framework: "fedramp",
		Region:    "us-east-1",
		UTCHour:   2,
		EmergencyAudit: policy.EmergencyAudit{
			Enabled:       true,
			AuditID:       "AUD-2026-44",
			Justification: "Regulatory exam snapshot requested by external auditor",
		},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !allowedBG.Allowed {
		t.Fatalf("expected emergency audit override to allow collection")
	}
}

func TestEndToEndEvidenceCollectionWithLocalStackAndOPA(t *testing.T) {
	awsEndpoint := os.Getenv("AWS_ENDPOINT_URL")
	opaURL := os.Getenv("OPA_URL")
	if awsEndpoint == "" || opaURL == "" {
		t.Skip("AWS_ENDPOINT_URL or OPA_URL not set; skipping live container test")
	}

	httpClient := &http.Client{Timeout: 2 * time.Second}
	if _, err := httpClient.Get(awsEndpoint + "/_localstack/health"); err != nil {
		t.Skipf("LocalStack unavailable at %s: %v", awsEndpoint, err)
	}
	if _, err := httpClient.Get(opaURL + "/health"); err != nil {
		t.Skipf("OPA unavailable at %s: %v", opaURL, err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	logger := slog.New(slog.NewJSONHandler(io.Discard, nil))
	bucket := fmt.Sprintf("audit-evidence-it-%d", time.Now().UnixNano())
	secret := "integration-audit-secret"

	// Seed an IAM user in LocalStack so the collector snapshots real state
	cfg, _ := config.LoadDefaultConfig(ctx,
		config.WithRegion("us-east-1"),
		config.WithCredentialsProvider(credentials.NewStaticCredentialsProvider("test", "test", "")),
	)
	rawIAM := iam.NewFromConfig(cfg, func(o *iam.Options) { o.BaseEndpoint = aws.String(awsEndpoint) })
	rawS3 := s3.NewFromConfig(cfg, func(o *s3.Options) {
		o.BaseEndpoint = aws.String(awsEndpoint)
		o.UsePathStyle = true
	})

	testUser := fmt.Sprintf("auditor-subject-%d", time.Now().UnixNano())
	_, err := rawIAM.CreateUser(ctx, &iam.CreateUserInput{UserName: aws.String(testUser)})
	if err != nil {
		t.Fatalf("create test IAM user in LocalStack: %v", err)
	}
	defer func() {
		_, _ = rawIAM.DeleteUser(context.Background(), &iam.DeleteUserInput{UserName: aws.String(testUser)})
	}()

	collector, err := awsevidence.NewCollector(ctx, "us-east-1", awsEndpoint, bucket, logger)
	if err != nil {
		t.Fatalf("new collector: %v", err)
	}

	h := server.NewHandler(
		webhook.NewVerifier(secret, 5*time.Minute),
		policy.NewClient(opaURL, 3*time.Second),
		collector,
		nil,
		logger,
	)
	h.SetClock(func() time.Time { return time.Date(2026, 11, 27, 15, 0, 0, 0, time.UTC) })
	ts := httptest.NewServer(h.Routes())
	defer ts.Close()

	postSigned := func(sigOverride string, payload server.CollectRequest) (*http.Response, []byte) {
		raw, _ := json.Marshal(payload)
		unixTS := time.Now().UTC().Unix()
		sig := webhook.ComputeSignature([]byte(secret), unixTS, raw)
		if sigOverride != "" {
			sig = sigOverride
		}
		req, _ := http.NewRequest(http.MethodPost, ts.URL+"/v1/evidence/collect", bytes.NewReader(raw))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-Timestamp", strconv.FormatInt(unixTS, 10))
		req.Header.Set("X-Signature-256", sig)
		resp, err := httpClient.Do(req)
		if err != nil {
			t.Fatalf("post request failed: %v", err)
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		return resp, b
	}

	// 1. Invalid HMAC signature -> 401 Unauthorized
	resp401, _ := postSigned("sha256=bad", server.CollectRequest{
		Collector: "scheduler",
		Role:      "compliance-auditor",
		Framework: "fedramp",
		Region:    "us-east-1",
	})
	if resp401.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected 401 Unauthorized, got %d", resp401.StatusCode)
	}

	// 2. FedRAMP collection targeting eu-central-1 -> 403 Forbidden from OPA sovereignty policy
	resp403, _ := postSigned("", server.CollectRequest{
		Collector: "scheduler",
		Role:      "compliance-auditor",
		Framework: "fedramp",
		Region:    "eu-central-1",
	})
	if resp403.StatusCode != http.StatusForbidden {
		t.Fatalf("expected 403 Forbidden for fedramp in eu-central-1, got %d", resp403.StatusCode)
	}

	// 3. Valid FedRAMP collection in us-east-1 -> 200 OK + verify bundle exists in LocalStack S3
	resp200, body200 := postSigned("", server.CollectRequest{
		Collector: "scheduler",
		Role:      "compliance-auditor",
		Framework: "fedramp",
		Region:    "us-east-1",
	})
	if resp200.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 OK, got %d: %s", resp200.StatusCode, string(body200))
	}

	var out server.CollectResponse
	if err := json.Unmarshal(body200, &out); err != nil || out.Bundle == nil {
		t.Fatalf("invalid collect response: %v", err)
	}
	if len(out.Bundle.SHA256Digest) != 64 {
		t.Fatalf("expected 64-char sha256 digest, got %q", out.Bundle.SHA256Digest)
	}

	s3Obj, err := rawS3.GetObject(ctx, &s3.GetObjectInput{
		Bucket: aws.String(bucket),
		Key:    aws.String(out.Bundle.S3Key),
	})
	if err != nil {
		t.Fatalf("expected evidence object %s in LocalStack S3, got error: %v", out.Bundle.S3Key, err)
	}
	_ = s3Obj.Body.Close()
}

func BenchmarkHMACAndPolicyEvaluation(b *testing.B) {
	opaStub := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"result": policy.Decision{Allowed: true, Reason: "allowed"},
		})
	}))
	defer opaStub.Close()

	secret := "bench-audit-secret"
	v := webhook.NewVerifier(secret, 5*time.Minute)
	pc := policy.NewClient(opaStub.URL, 2*time.Second)
	payload := []byte(`{"role":"compliance-auditor","framework":"fedramp","region":"us-east-1"}`)
	ctx := context.Background()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		nowTS := time.Now().UTC().Unix()
		sig := webhook.ComputeSignature([]byte(secret), nowTS, payload)
		if err := v.Verify(sig, strconv.FormatInt(nowTS, 10), payload); err != nil {
			b.Fatalf("verify failed: %v", err)
		}
		if _, err := pc.EvaluateAll(ctx, policy.CheckInput{
			Role:      "compliance-auditor",
			Framework: "fedramp",
			Region:    "us-east-1",
			UTCHour:   12,
		}); err != nil {
			b.Fatalf("policy failed: %v", err)
		}
	}
}
