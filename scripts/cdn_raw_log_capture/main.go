// cdn_raw_log_capture exercises the live Yandex Cloud CDN Raw Logs API against
// a real resource and snapshots the requests + responses as JSON fixtures.
// Those fixtures are then consumed by the cdn_raw_log golden tests so the unit
// tests can be diffed against real API shapes.
//
// Usage:
//
//	YC_TOKEN=<oauth-token>             # or YC_IAM_TOKEN=<iam-token>
//	YC_CDN_RESOURCE_ID=<cdn-resource-id>
//	YC_BUCKET_NAME=<object-storage-bucket>
//	[YC_BUCKET_REGION=ru-central1]
//	[YC_FILE_PREFIX=cdn-logs]        # NB: API rejects values ending with '/'
//	[YC_FIXTURES_DIR=yandex-framework/services/cdn_raw_log/testdata/fixtures]
//	[YC_KEEP_ACTIVATED=1]              # skip the final Deactivate
//	go run ./scripts/cdn_raw_log_capture
//
// The script performs this lifecycle on the live API:
//
//	Get → Activate → Wait → Get → Update → Wait → Get → Deactivate → Wait → Get
//
// Each call's request and response (or error) are written as protojson to
// <YC_FIXTURES_DIR>/NN_<step>.json. Skip the final Deactivate by setting
// YC_KEEP_ACTIVATED=1 (useful when you want to keep raw logs running on the
// CDN resource after capture).
package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/yandex-cloud/go-genproto/yandex/cloud/cdn/v1"
	ycsdk "github.com/yandex-cloud/go-sdk"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
)

const defaultFixturesDir = "yandex-framework/services/cdn_raw_log/testdata/fixtures"

func main() {
	if err := run(); err != nil {
		log.Fatalf("capture failed: %v", err)
	}
}

func run() error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()

	cfg, err := readConfig()
	if err != nil {
		return err
	}

	if err := os.MkdirAll(cfg.fixturesDir, 0o755); err != nil {
		return fmt.Errorf("mkdir fixtures dir: %w", err)
	}

	sdk, err := ycsdk.Build(ctx, ycsdk.Config{Credentials: cfg.credentials})
	if err != nil {
		return fmt.Errorf("build SDK: %w", err)
	}
	rawLogs := sdk.CDN().RawLogs()

	steps := []captureStep{
		{
			name: "01_get_initial",
			run: func() (proto.Message, proto.Message, error) {
				req := &cdn.GetRawLogsRequest{ResourceId: cfg.resourceID}
				resp, err := rawLogs.Get(ctx, req)
				return req, resp, err
			},
			// Initial Get is allowed to fail with NotFound (raw logs not yet activated).
			allowNotFound: true,
		},
		{
			name: "02_activate",
			run: func() (proto.Message, proto.Message, error) {
				req := &cdn.ActivateRawLogsRequest{
					ResourceId: cfg.resourceID,
					Settings: &cdn.RawLogsSettings{
						BucketName:   cfg.bucketName,
						BucketRegion: cfg.bucketRegion,
						FilePrefix:   cfg.filePrefix,
					},
				}
				op, err := sdk.WrapOperation(rawLogs.Activate(ctx, req))
				if err != nil {
					return req, nil, err
				}
				if err := op.Wait(ctx); err != nil {
					return req, op.Proto(), err
				}
				return req, op.Proto(), nil
			},
		},
		{
			name: "03_get_after_activate",
			run: func() (proto.Message, proto.Message, error) {
				req := &cdn.GetRawLogsRequest{ResourceId: cfg.resourceID}
				resp, err := rawLogs.Get(ctx, req)
				return req, resp, err
			},
		},
		{
			name: "04_update",
			run: func() (proto.Message, proto.Message, error) {
				req := &cdn.UpdateRawLogsRequest{
					ResourceId: cfg.resourceID,
					Settings: &cdn.RawLogsSettings{
						BucketName:   cfg.bucketName,
						BucketRegion: cfg.bucketRegion,
						FilePrefix:   cfg.filePrefix + "-v2",
					},
				}
				op, err := sdk.WrapOperation(rawLogs.Update(ctx, req))
				if err != nil {
					return req, nil, err
				}
				if err := op.Wait(ctx); err != nil {
					return req, op.Proto(), err
				}
				return req, op.Proto(), nil
			},
		},
		{
			name: "05_get_after_update",
			run: func() (proto.Message, proto.Message, error) {
				req := &cdn.GetRawLogsRequest{ResourceId: cfg.resourceID}
				resp, err := rawLogs.Get(ctx, req)
				return req, resp, err
			},
		},
	}

	if !cfg.keepActivated {
		steps = append(steps,
			captureStep{
				name: "06_deactivate",
				run: func() (proto.Message, proto.Message, error) {
					req := &cdn.DeactivateRawLogsRequest{ResourceId: cfg.resourceID}
					op, err := sdk.WrapOperation(rawLogs.Deactivate(ctx, req))
					if err != nil {
						return req, nil, err
					}
					if err := op.Wait(ctx); err != nil {
						return req, op.Proto(), err
					}
					return req, op.Proto(), nil
				},
			},
			captureStep{
				name: "07_get_after_deactivate",
				run: func() (proto.Message, proto.Message, error) {
					req := &cdn.GetRawLogsRequest{ResourceId: cfg.resourceID}
					resp, err := rawLogs.Get(ctx, req)
					return req, resp, err
				},
				allowNotFound: true,
			},
		)
	} else {
		log.Printf("YC_KEEP_ACTIVATED=1 set — skipping Deactivate (raw logs will remain ACTIVE on %s)", cfg.resourceID)
	}

	for _, step := range steps {
		log.Printf("running %s", step.name)
		req, resp, callErr := step.run()
		if err := writeFixture(cfg.fixturesDir, step.name, req, resp, callErr); err != nil {
			return fmt.Errorf("%s: %w", step.name, err)
		}
		if callErr != nil && !(step.allowNotFound && status.Code(callErr) == codes.NotFound) {
			return fmt.Errorf("%s: %w", step.name, callErr)
		}
	}

	log.Printf("done — fixtures written to %s", cfg.fixturesDir)
	return nil
}

type captureStep struct {
	name          string
	run           func() (req, resp proto.Message, err error)
	allowNotFound bool
}

type captureConfig struct {
	credentials   ycsdk.Credentials
	resourceID    string
	bucketName    string
	bucketRegion  string
	filePrefix    string
	fixturesDir   string
	keepActivated bool
}

func readConfig() (*captureConfig, error) {
	resourceID := os.Getenv("YC_CDN_RESOURCE_ID")
	if resourceID == "" {
		return nil, errors.New("YC_CDN_RESOURCE_ID is required")
	}
	bucketName := os.Getenv("YC_BUCKET_NAME")
	if bucketName == "" {
		return nil, errors.New("YC_BUCKET_NAME is required (the Object Storage bucket to receive logs)")
	}

	region := os.Getenv("YC_BUCKET_REGION")
	if region == "" {
		region = "ru-central1"
	}
	prefix := os.Getenv("YC_FILE_PREFIX")
	if prefix == "" {
		// API rejects prefixes that end with '/'; pick something that does not.
		prefix = "capture"
	}
	dir := os.Getenv("YC_FIXTURES_DIR")
	if dir == "" {
		dir = defaultFixturesDir
	}

	creds, err := buildCredentials()
	if err != nil {
		return nil, err
	}

	return &captureConfig{
		credentials:   creds,
		resourceID:    resourceID,
		bucketName:    bucketName,
		bucketRegion:  region,
		filePrefix:    prefix,
		fixturesDir:   dir,
		keepActivated: strings.EqualFold(os.Getenv("YC_KEEP_ACTIVATED"), "1") || strings.EqualFold(os.Getenv("YC_KEEP_ACTIVATED"), "true"),
	}, nil
}

func buildCredentials() (ycsdk.Credentials, error) {
	if t := os.Getenv("YC_IAM_TOKEN"); t != "" {
		return ycsdk.NewIAMTokenCredentials(t), nil
	}
	if t := os.Getenv("YC_TOKEN"); t != "" {
		return ycsdk.OAuthToken(t), nil
	}
	return nil, errors.New("either YC_TOKEN (OAuth) or YC_IAM_TOKEN (IAM) must be set")
}

// fixturePayload is what each NN_<step>.json file contains: human-readable
// metadata + protojson-encoded request/response.
type fixturePayload struct {
	Step     string `json:"step"`
	Request  any    `json:"request,omitempty"`
	Response any    `json:"response,omitempty"`
	GRPCCode string `json:"grpc_code,omitempty"`
	Error    string `json:"error,omitempty"`
}

func writeFixture(dir, name string, req, resp proto.Message, callErr error) error {
	payload := fixturePayload{Step: name}
	if req != nil {
		raw, err := marshalProto(req)
		if err != nil {
			return err
		}
		payload.Request = raw
	}
	if resp != nil {
		raw, err := marshalProto(resp)
		if err != nil {
			return err
		}
		payload.Response = raw
	}
	if callErr != nil {
		payload.Error = callErr.Error()
		payload.GRPCCode = status.Code(callErr).String()
	}

	out, err := marshalJSON(payload)
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dir, name+".json"), out, 0o644)
}

// marshalProto uses protojson so the output reflects the real proto shape
// (including any unknown fields the SDK exposes), then re-parses to a generic
// map so the outer struct can interleave proto fields with metadata cleanly.
func marshalProto(m proto.Message) (map[string]any, error) {
	raw, err := (protojson.MarshalOptions{EmitUnpopulated: true}).Marshal(m)
	if err != nil {
		return nil, fmt.Errorf("protojson marshal: %w", err)
	}
	var obj map[string]any
	if err := json.Unmarshal(raw, &obj); err != nil {
		return nil, fmt.Errorf("re-parse protojson: %w", err)
	}
	return obj, nil
}

func marshalJSON(v any) ([]byte, error) {
	return json.MarshalIndent(v, "", "  ")
}
