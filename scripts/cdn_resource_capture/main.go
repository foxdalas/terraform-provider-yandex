// cdn_resource_capture exercises the live Yandex Cloud CDN Resource API and
// snapshots requests + responses as JSON fixtures for the cdn_resource golden
// tests.
//
// Usage:
//
//	YC_TOKEN=<oauth-token>             # or YC_IAM_TOKEN=<iam-token>
//	YC_FOLDER_ID=<folder-id>
//	YC_ORIGIN_GROUP_ID=<existing-origin-group-id>
//	[YC_CNAME=tf-capture-<timestamp>.example.com]
//	[YC_FIXTURES_DIR=yandex-framework/services/cdn_resource/testdata/fixtures]
//	[YC_KEEP_RESOURCE=1]               # skip the final Delete
//	go run ./scripts/cdn_resource_capture
//
// Lifecycle exercised:
//
//	Create → Get → Update → Get → List → Delete → Get(NotFound)
package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/yandex-cloud/go-genproto/yandex/cloud/cdn/v1"
	ycsdk "github.com/yandex-cloud/go-sdk"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

const defaultFixturesDir = "yandex-framework/services/cdn_resource/testdata/fixtures"

func main() {
	if err := run(); err != nil {
		log.Fatalf("capture failed: %v", err)
	}
}

func run() error {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Minute)
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
	api := sdk.CDN().Resource()

	var createdResourceID string

	steps := []captureStep{
		{
			name: "01_create",
			run: func() (proto.Message, proto.Message, error) {
				req := &cdn.CreateResourceRequest{
					FolderId: cfg.folderID,
					Cname:    cfg.cname,
					Origin: &cdn.CreateResourceRequest_Origin{
						OriginVariant: &cdn.CreateResourceRequest_Origin_OriginGroupId{
							OriginGroupId: cfg.originGroupID,
						},
					},
					Active:         &wrapperspb.BoolValue{Value: true},
					OriginProtocol: cdn.OriginProtocol_HTTP,
				}
				op, err := sdk.WrapOperation(api.Create(ctx, req))
				if err != nil {
					return req, nil, err
				}
				if err := op.Wait(ctx); err != nil {
					return req, op.Proto(), err
				}
				if md, metaErr := op.Metadata(); metaErr == nil {
					if m, ok := md.(*cdn.CreateResourceMetadata); ok {
						createdResourceID = m.ResourceId
					}
				}
				return req, op.Proto(), nil
			},
		},
		{
			name: "02_get_after_create",
			run: func() (proto.Message, proto.Message, error) {
				if createdResourceID == "" {
					return nil, nil, errors.New("createdResourceID is unset; previous step likely failed")
				}
				req := &cdn.GetResourceRequest{ResourceId: createdResourceID}
				resp, err := api.Get(ctx, req)
				return req, resp, err
			},
		},
		{
			name: "03_update",
			run: func() (proto.Message, proto.Message, error) {
				req := &cdn.UpdateResourceRequest{
					ResourceId: createdResourceID,
					Active:     &wrapperspb.BoolValue{Value: false},
				}
				op, err := sdk.WrapOperation(api.Update(ctx, req))
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
			name: "04_get_after_update",
			run: func() (proto.Message, proto.Message, error) {
				req := &cdn.GetResourceRequest{ResourceId: createdResourceID}
				resp, err := api.Get(ctx, req)
				return req, resp, err
			},
		},
		{
			name: "05_list",
			run: func() (proto.Message, proto.Message, error) {
				req := &cdn.ListResourcesRequest{FolderId: cfg.folderID}
				resp, err := api.List(ctx, req)
				return req, resp, err
			},
		},
	}

	if !cfg.keepResource {
		steps = append(steps,
			captureStep{
				name: "06_delete",
				run: func() (proto.Message, proto.Message, error) {
					req := &cdn.DeleteResourceRequest{ResourceId: createdResourceID}
					op, err := sdk.WrapOperation(api.Delete(ctx, req))
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
				name: "07_get_after_delete",
				run: func() (proto.Message, proto.Message, error) {
					req := &cdn.GetResourceRequest{ResourceId: createdResourceID}
					resp, err := api.Get(ctx, req)
					return req, resp, err
				},
				allowNotFound: true,
			},
		)
	} else {
		log.Printf("YC_KEEP_RESOURCE=1 set — skipping Delete (resource id=%s remains)", createdResourceID)
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
	folderID      string
	originGroupID int64
	cname         string
	fixturesDir   string
	keepResource  bool
}

func readConfig() (*captureConfig, error) {
	folderID := os.Getenv("YC_FOLDER_ID")
	if folderID == "" {
		return nil, errors.New("YC_FOLDER_ID is required")
	}

	originGroupIDStr := os.Getenv("YC_ORIGIN_GROUP_ID")
	if originGroupIDStr == "" {
		return nil, errors.New("YC_ORIGIN_GROUP_ID is required")
	}
	originGroupID, err := strconv.ParseInt(originGroupIDStr, 10, 64)
	if err != nil {
		return nil, fmt.Errorf("invalid YC_ORIGIN_GROUP_ID %q: %w", originGroupIDStr, err)
	}

	cname := os.Getenv("YC_CNAME")
	if cname == "" {
		cname = fmt.Sprintf("tf-capture-%d.example.com", time.Now().Unix())
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
		folderID:      folderID,
		originGroupID: originGroupID,
		cname:         cname,
		fixturesDir:   dir,
		keepResource:  strings.EqualFold(os.Getenv("YC_KEEP_RESOURCE"), "1") || strings.EqualFold(os.Getenv("YC_KEEP_RESOURCE"), "true"),
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
	out, err := json.MarshalIndent(payload, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dir, name+".json"), out, 0o644)
}

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
