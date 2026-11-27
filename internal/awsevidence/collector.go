package awsevidence

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"math"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/cloudtrail"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/smithy-go"
	smithyhttp "github.com/aws/smithy-go/transport/http"
)

type IAMClient struct {
	*iam.Client
}

type S3Client struct {
	*s3.Client
}

type CloudTrailClient struct {
	*cloudtrail.Client
}

type Collector struct {
	iam        *iam.Client
	s3         *s3.Client
	cloudtrail *cloudtrail.Client
	bucket     string
	maxRetries int
	baseDelay  time.Duration
	maxDelay   time.Duration
	logger     *slog.Logger
}

type EvidenceBundle struct {
	BundleID        string            `json:"bundle_id"`
	CorrelationID   string            `json:"correlation_id"`
	Framework       string            `json:"framework"`
	Region          string            `json:"region"`
	CollectedAtUTC  string            `json:"collected_at_utc"`
	IAMUserCount    int               `json:"iam_user_count"`
	IAMRoleCount    int               `json:"iam_role_count"`
	CloudTrailCount int               `json:"cloudtrail_event_count"`
	Users           []string          `json:"users"`
	Roles           []string          `json:"roles"`
	RecentEvents    []string          `json:"recent_events"`
	SHA256Digest    string            `json:"sha256_digest"`
	S3Key           string            `json:"s3_key"`
	GraceExtended   bool              `json:"grace_extended"`
	Metadata        map[string]string `json:"metadata"`
}

func NewCollector(ctx context.Context, region, endpointURL, bucket string, logger *slog.Logger) (*Collector, error) {
	if region == "" {
		region = "us-east-1"
	}
	if bucket == "" {
		bucket = "compliance-audit-evidence"
	}
	if logger == nil {
		logger = slog.Default()
	}

	opts := []func(*config.LoadOptions) error{
		config.WithRegion(region),
	}
	if endpointURL != "" {
		opts = append(opts, config.WithCredentialsProvider(credentials.NewStaticCredentialsProvider("test", "test", "")))
	}

	cfg, err := config.LoadDefaultConfig(ctx, opts...)
	if err != nil {
		return nil, fmt.Errorf("load aws config: %w", err)
	}

	var iamOpts []func(*iam.Options)
	var s3Opts []func(*s3.Options)
	var ctOpts []func(*cloudtrail.Options)
	if endpointURL != "" {
		iamOpts = append(iamOpts, func(o *iam.Options) { o.BaseEndpoint = aws.String(endpointURL) })
		s3Opts = append(s3Opts, func(o *s3.Options) {
			o.BaseEndpoint = aws.String(endpointURL)
			o.UsePathStyle = true
		})
		ctOpts = append(ctOpts, func(o *cloudtrail.Options) { o.BaseEndpoint = aws.String(endpointURL) })
	}

	return &Collector{
		iam:        iam.NewFromConfig(cfg, iamOpts...),
		s3:         s3.NewFromConfig(cfg, s3Opts...),
		cloudtrail: cloudtrail.NewFromConfig(cfg, ctOpts...),
		bucket:     bucket,
		maxRetries: 4,
		baseDelay:  100 * time.Millisecond,
		maxDelay:   2 * time.Second,
		logger:     logger,
	}, nil
}

func isRetryable(err error) bool {
	if err == nil {
		return false
	}
	var apiErr smithy.APIError
	if errors.As(err, &apiErr) {
		code := apiErr.ErrorCode()
		if code == "Throttling" || code == "ThrottlingException" || code == "RequestLimitExceeded" || code == "ServiceUnavailable" {
			return true
		}
	}
	var respErr *smithyhttp.ResponseError
	if errors.As(err, &respErr) {
		status := respErr.HTTPStatusCode()
		if status == 429 || status == 503 || status == 502 || status == 504 {
			return true
		}
	}
	msg := err.Error()
	return strings.Contains(msg, "ThrottlingException") || strings.Contains(msg, "503")
}

func (c *Collector) withRetry(ctx context.Context, correlationID, op string, fn func() error) error {
	var lastErr error
	for attempt := 1; attempt <= c.maxRetries; attempt++ {
		lastErr = fn()
		if lastErr == nil {
			return nil
		}
		if !isRetryable(lastErr) || attempt == c.maxRetries {
			return lastErr
		}
		// AWS IAM/CloudTrail APIs throttle bursts during audit snapshots; cap backoff so HTTP callers do not time out
		backoff := time.Duration(float64(c.baseDelay) * math.Pow(2, float64(attempt-1)))
		if backoff > c.maxDelay {
			backoff = c.maxDelay
		}
		c.logger.Warn("retrying aws api call",
			"correlation_id", correlationID,
			"operation", op,
			"attempt", attempt,
			"backoff_ms", backoff.Milliseconds(),
			"error", lastErr.Error(),
		)
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(backoff):
		}
	}
	return lastErr
}

func (c *Collector) EnsureBucket(ctx context.Context) error {
	_, err := c.s3.HeadBucket(ctx, &s3.HeadBucketInput{Bucket: aws.String(c.bucket)})
	if err == nil {
		return nil
	}
	_, err = c.s3.CreateBucket(ctx, &s3.CreateBucketInput{Bucket: aws.String(c.bucket)})
	if err != nil && !strings.Contains(err.Error(), "BucketAlreadyOwnedByYou") {
		return fmt.Errorf("create evidence bucket %s: %w", c.bucket, err)
	}
	return nil
}

func (c *Collector) CollectAndStore(ctx context.Context, correlationID, framework, region string, emergencyActive bool) (EvidenceBundle, error) {
	if err := c.EnsureBucket(ctx); err != nil {
		return EvidenceBundle{}, err
	}

	var usersOut *iam.ListUsersOutput
	if err := c.withRetry(ctx, correlationID, "iam:ListUsers", func() error {
		var err error
		usersOut, err = c.iam.ListUsers(ctx, &iam.ListUsersInput{})
		return err
	}); err != nil {
		return EvidenceBundle{}, fmt.Errorf("list iam users: %w", err)
	}

	var rolesOut *iam.ListRolesOutput
	if err := c.withRetry(ctx, correlationID, "iam:ListRoles", func() error {
		var err error
		rolesOut, err = c.iam.ListRoles(ctx, &iam.ListRolesInput{})
		return err
	}); err != nil {
		return EvidenceBundle{}, fmt.Errorf("list iam roles: %w", err)
	}

	var ctOut *cloudtrail.LookupEventsOutput
	if err := c.withRetry(ctx, correlationID, "cloudtrail:LookupEvents", func() error {
		var err error
		ctOut, err = c.cloudtrail.LookupEvents(ctx, &cloudtrail.LookupEventsInput{
			MaxResults: aws.Int32(25),
		})
		return err
	}); err != nil {
		return EvidenceBundle{}, fmt.Errorf("lookup cloudtrail events: %w", err)
	}

	var userNames []string
	for _, u := range usersOut.Users {
		if u.UserName != nil {
			userNames = append(userNames, *u.UserName)
		}
	}

	var roleNames []string
	for _, r := range rolesOut.Roles {
		if r.RoleName != nil {
			roleNames = append(roleNames, *r.RoleName)
		}
	}

	var eventNames []string
	for _, ev := range ctOut.Events {
		if ev.EventName != nil {
			eventNames = append(eventNames, *ev.EventName)
		}
	}

	nowUTC := time.Now().UTC()
	bundleID := fmt.Sprintf("ev-%s-%d", framework, nowUTC.UnixNano())
	s3Key := fmt.Sprintf("%s/%s/%s.json", framework, nowUTC.Format("2006-01-02"), bundleID)

	bundle := EvidenceBundle{
		BundleID:        bundleID,
		CorrelationID:   correlationID,
		Framework:       framework,
		Region:          region,
		CollectedAtUTC:  nowUTC.Format(time.RFC3339),
		IAMUserCount:    len(userNames),
		IAMRoleCount:    len(roleNames),
		CloudTrailCount: len(eventNames),
		Users:           userNames,
		Roles:           roleNames,
		RecentEvents:    eventNames,
		S3Key:           s3Key,
		GraceExtended:   emergencyActive,
		Metadata: map[string]string{
			"framework":      framework,
			"region":         region,
			"correlation_id": correlationID,
		},
	}

	canonical, err := json.Marshal(bundle)
	if err != nil {
		return EvidenceBundle{}, fmt.Errorf("marshal evidence bundle: %w", err)
	}
	sum := sha256.Sum256(canonical)
	bundle.SHA256Digest = hex.EncodeToString(sum[:])

	finalPayload, err := json.MarshalIndent(bundle, "", "  ")
	if err != nil {
		return EvidenceBundle{}, fmt.Errorf("marshal signed bundle: %w", err)
	}

	if err := c.withRetry(ctx, correlationID, "s3:PutObject", func() error {
		_, err := c.s3.PutObject(ctx, &s3.PutObjectInput{
			Bucket:      aws.String(c.bucket),
			Key:         aws.String(s3Key),
			Body:        bytes.NewReader(finalPayload),
			ContentType: aws.String("application/json"),
			Metadata: map[string]string{
				"sha256-digest":  bundle.SHA256Digest,
				"correlation-id": correlationID,
			},
		})
		return err
	}); err != nil {
		return EvidenceBundle{}, fmt.Errorf("upload evidence bundle to s3: %w", err)
	}

	return bundle, nil
}
