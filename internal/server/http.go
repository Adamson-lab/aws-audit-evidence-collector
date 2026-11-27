package server

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/Adamson-lab/aws-audit-evidence-collector/internal/awsevidence"
	"github.com/Adamson-lab/aws-audit-evidence-collector/internal/policy"
	"github.com/Adamson-lab/aws-audit-evidence-collector/internal/webhook"
)

type CollectRequest struct {
	CorrelationID  string                `json:"correlation_id"`
	Collector      string                `json:"collector"`
	Role           string                `json:"role"`
	Framework      string                `json:"framework"`
	Region         string                `json:"region"`
	EmergencyAudit policy.EmergencyAudit `json:"emergency_audit"`
}

type CollectResponse struct {
	CorrelationID string                      `json:"correlation_id"`
	Status        string                      `json:"status"`
	PolicyReason  string                      `json:"policy_reason"`
	Bundle        *awsevidence.EvidenceBundle `json:"bundle,omitempty"`
}

type HealthCheck func(ctx context.Context) (localstackOK bool, opaOK bool)

type Handler struct {
	verifier  *webhook.Verifier
	policy    *policy.Client
	collector *awsevidence.Collector
	health    HealthCheck
	logger    *slog.Logger
	nowUTC    func() time.Time
}

func NewHandler(
	verifier *webhook.Verifier,
	policyClient *policy.Client,
	collector *awsevidence.Collector,
	health HealthCheck,
	logger *slog.Logger,
) *Handler {
	if logger == nil {
		logger = slog.Default()
	}
	return &Handler{
		verifier:  verifier,
		policy:    policyClient,
		collector: collector,
		health:    health,
		logger:    logger,
		nowUTC:    func() time.Time { return time.Now().UTC() },
	}
}

func (h *Handler) SetClock(fn func() time.Time) {
	h.nowUTC = fn
}

func (h *Handler) Routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", h.handleHealth)
	mux.HandleFunc("POST /v1/evidence/collect", h.handleCollect)
	return mux
}

func (h *Handler) handleHealth(w http.ResponseWriter, r *http.Request) {
	lsOK, opaOK := true, true
	if h.health != nil {
		ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
		defer cancel()
		lsOK, opaOK = h.health(ctx)
	}
	status := "ok"
	code := http.StatusOK
	if !lsOK || !opaOK {
		status = "degraded"
		code = http.StatusServiceUnavailable
	}
	writeJSON(w, code, map[string]any{
		"status":     status,
		"localstack": lsOK,
		"opa":        opaOK,
		"timestamp":  h.nowUTC().Format(time.RFC3339),
	})
}

func (h *Handler) handleCollect(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "failed to read request body"})
		return
	}

	if err := h.verifier.Verify(r.Header.Get("X-Signature-256"), r.Header.Get("X-Timestamp"), body); err != nil {
		h.logger.Warn("rejected unauthenticated collection request", "error", err.Error())
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": err.Error()})
		return
	}

	var req CollectRequest
	if err := json.Unmarshal(body, &req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid json payload"})
		return
	}
	if req.CorrelationID == "" {
		req.CorrelationID = r.Header.Get("X-Correlation-ID")
	}
	if req.CorrelationID == "" {
		req.CorrelationID = fmt.Sprintf("audit-%d", h.nowUTC().UnixNano())
	}
	if strings.TrimSpace(req.Framework) == "" {
		req.Framework = "commercial"
	}
	if strings.TrimSpace(req.Region) == "" {
		req.Region = "us-east-1"
	}

	decision, err := h.policy.EvaluateAll(r.Context(), policy.CheckInput{
		CorrelationID:  req.CorrelationID,
		Collector:      req.Collector,
		Role:           req.Role,
		Framework:      req.Framework,
		Region:         req.Region,
		UTCHour:        h.nowUTC().Hour(),
		EmergencyAudit: req.EmergencyAudit,
	})
	if err != nil {
		h.logger.Error("opa policy check failed", "correlation_id", req.CorrelationID, "error", err.Error())
		writeJSON(w, http.StatusBadGateway, map[string]string{"error": "policy engine unavailable"})
		return
	}

	if !decision.Allowed {
		h.logger.Info("evidence collection denied by policy",
			"correlation_id", req.CorrelationID,
			"role", req.Role,
			"framework", req.Framework,
			"region", req.Region,
			"reason", decision.Reason,
		)
		writeJSON(w, http.StatusForbidden, CollectResponse{
			CorrelationID: req.CorrelationID,
			Status:        "denied",
			PolicyReason:  decision.Reason,
		})
		return
	}

	bundle, err := h.collector.CollectAndStore(r.Context(), req.CorrelationID, req.Framework, req.Region, req.EmergencyAudit.Enabled)
	if err != nil {
		h.logger.Error("evidence collection failed", "correlation_id", req.CorrelationID, "error", err.Error())
		writeJSON(w, http.StatusBadGateway, map[string]string{"error": err.Error()})
		return
	}

	h.logger.Info("collected and stored audit evidence bundle",
		"correlation_id", req.CorrelationID,
		"bundle_id", bundle.BundleID,
		"s3_key", bundle.S3Key,
		"sha256_digest", bundle.SHA256Digest,
	)

	writeJSON(w, http.StatusOK, CollectResponse{
		CorrelationID: req.CorrelationID,
		Status:        "collected",
		PolicyReason:  decision.Reason,
		Bundle:        &bundle,
	})
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
