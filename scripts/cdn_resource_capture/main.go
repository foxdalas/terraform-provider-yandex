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
//	Create → Get
//	→ Update#1 (enable every option, "on"/value variants) → Get
//	→ Update#2 (flip booleans to false, alternate oneof variants & enums) → Get
//	→ Update#3 (disable/clear options, scalars reset) → Get
//	→ List → Delete → Get(NotFound)
//
// The three updates deliberately span the full ResourceOptions surface with
// contrasting values so the golden tests catch round-trip bugs — notably the
// tristate booleans (e.g. slice) where a sent {Enabled:true, Value:false} comes
// back disabled.
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

	// Wipe stale *.json fixtures so a renumbered/shrunk lifecycle never leaves
	// orphans behind (e.g. an old 05_list.json next to a new 05_update.json).
	if err := cleanFixtures(cfg.fixturesDir); err != nil {
		return fmt.Errorf("clean fixtures dir: %w", err)
	}

	sdk, err := ycsdk.Build(ctx, ycsdk.Config{Credentials: cfg.credentials})
	if err != nil {
		return fmt.Errorf("build SDK: %w", err)
	}
	api := sdk.CDN().Resource()

	var createdResourceID string

	// doUpdate sends an Update and waits, returning (request, operation, err) for
	// the fixture. Keeps the three update steps free of boilerplate.
	doUpdate := func(req *cdn.UpdateResourceRequest) (proto.Message, proto.Message, error) {
		op, err := sdk.WrapOperation(api.Update(ctx, req))
		if err != nil {
			return req, nil, err
		}
		if err := op.Wait(ctx); err != nil {
			return req, op.Proto(), err
		}
		return req, op.Proto(), nil
	}
	getResource := func() (proto.Message, proto.Message, error) {
		req := &cdn.GetResourceRequest{ResourceId: createdResourceID}
		resp, err := api.Get(ctx, req)
		return req, resp, err
	}

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
				return doUpdate(updateAllOn(createdResourceID))
			},
		},
		{
			name: "04_get_after_update",
			run:  getResource,
		},
		{
			name: "05_update",
			run: func() (proto.Message, proto.Message, error) {
				return doUpdate(updateAllFlipped(createdResourceID))
			},
		},
		{
			name: "06_get_after_update_2",
			run:  getResource,
		},
		{
			name: "07_update",
			run: func() (proto.Message, proto.Message, error) {
				return doUpdate(updateAllOff(createdResourceID))
			},
		},
		{
			name: "08_get_after_update_3",
			run:  getResource,
		},
		{
			name: "09_list",
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
				name: "10_delete",
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
				name: "11_get_after_delete",
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

// cleanFixtures removes every *.json file directly under dir. Non-JSON files
// and subdirectories are left untouched.
func cleanFixtures(dir string) error {
	matches, err := filepath.Glob(filepath.Join(dir, "*.json"))
	if err != nil {
		return err
	}
	for _, path := range matches {
		if err := os.Remove(path); err != nil {
			return fmt.Errorf("remove %s: %w", path, err)
		}
	}
	if len(matches) > 0 {
		log.Printf("removed %d stale fixture(s) in %s", len(matches), dir)
	}
	return nil
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

// --- Option constructors -----------------------------------------------------
//
// Small helpers so the update builders below read like the option matrix they
// represent rather than nested struct literals.

func boolOpt(v bool) *cdn.ResourceOptions_BoolOption {
	return &cdn.ResourceOptions_BoolOption{Enabled: true, Value: v}
}

func strOpt(v string) *cdn.ResourceOptions_StringOption {
	return &cdn.ResourceOptions_StringOption{Enabled: true, Value: v}
}

func int64Opt(v int64) *cdn.ResourceOptions_Int64Option {
	return &cdn.ResourceOptions_Int64Option{Enabled: true, Value: v}
}

func strListOpt(vals ...string) *cdn.ResourceOptions_StringsListOption {
	return &cdn.ResourceOptions_StringsListOption{Enabled: true, Value: vals}
}

func strMapOpt(m map[string]string) *cdn.ResourceOptions_StringsMapOption {
	return &cdn.ResourceOptions_StringsMapOption{Enabled: true, Value: m}
}

// disabledBool / disabledList express the "turn this option off" case the API
// represents as Enabled:false.
func disabledBool() *cdn.ResourceOptions_BoolOption {
	return &cdn.ResourceOptions_BoolOption{Enabled: false}
}

func disabledList() *cdn.ResourceOptions_StringsListOption {
	return &cdn.ResourceOptions_StringsListOption{Enabled: false}
}

func disabledMap() *cdn.ResourceOptions_StringsMapOption {
	return &cdn.ResourceOptions_StringsMapOption{Enabled: false}
}

// --- Update builders ---------------------------------------------------------

// updateAllOn enables (almost) every option with concrete "on"/value variants,
// using the FIRST option of each mutually-exclusive oneof group (gzip, redirect
// http→https, forward host header, ignore query string, edge cache default).
func updateAllOn(resourceID string) *cdn.UpdateResourceRequest {
	return &cdn.UpdateResourceRequest{
		ResourceId:     resourceID,
		Active:         &wrapperspb.BoolValue{Value: true},
		OriginProtocol: cdn.OriginProtocol_HTTPS,
		Labels:         map[string]string{"env": "capture", "tier": "gold"},
		Options: &cdn.ResourceOptions{
			EdgeCacheSettings: &cdn.ResourceOptions_EdgeCacheSettings{
				Enabled:       true,
				ValuesVariant: &cdn.ResourceOptions_EdgeCacheSettings_DefaultValue{DefaultValue: 345600},
			},
			BrowserCacheSettings: int64Opt(3600),
			QueryParamsOptions: &cdn.ResourceOptions_QueryParamsOptions{
				QueryParamsVariant: &cdn.ResourceOptions_QueryParamsOptions_IgnoreQueryString{
					IgnoreQueryString: boolOpt(true),
				},
			},
			Slice: boolOpt(true),
			CompressionOptions: &cdn.ResourceOptions_CompressionOptions{
				CompressionVariant: &cdn.ResourceOptions_CompressionOptions_GzipOn{GzipOn: boolOpt(true)},
			},
			HostOptions: &cdn.ResourceOptions_HostOptions{
				HostVariant: &cdn.ResourceOptions_HostOptions_ForwardHostHeader{
					ForwardHostHeader: boolOpt(true),
				},
			},
			StaticHeaders:           strMapOpt(map[string]string{"x-static-response": "from-cdn"}),
			Cors:                    strListOpt("*"),
			Stale:                   strListOpt("error", "http_503"),
			ProxyCacheMethodsSet:    boolOpt(true),
			DisableProxyForceRanges: boolOpt(true),
			StaticRequestHeaders:    strMapOpt(map[string]string{"x-req-header": "v1"}),
			CustomServerName:        strOpt("capture.example.com"),
			IgnoreCookie:            boolOpt(true),
			Rewrite: &cdn.ResourceOptions_RewriteOption{
				Enabled: true, Body: "/old/(.*) /new/$1", Flag: cdn.RewriteFlag_BREAK,
			},
			IpAddressAcl: &cdn.ResourceOptions_IPAddressACLOption{
				Enabled: true, PolicyType: cdn.PolicyType_POLICY_TYPE_ALLOW, ExceptedValues: []string{"192.0.2.0/24"},
			},
			FollowRedirects: &cdn.ResourceOptions_FollowRedirectsOption{
				Enabled: true, Codes: []int64{301, 302}, UseCustomHost: true,
			},
			HeaderFilter: &cdn.ResourceOptions_HeaderFilterOption{
				Enabled: true, Headers: []string{"x-keep-this"},
			},
			GeoAcl: &cdn.ResourceOptions_GeoACLOption{
				Enabled: true, Mode: cdn.ResourceOptions_GeoACLOption_MODE_ALLOW, Countries: []string{"US", "DE"},
			},
			ReferrerAcl: &cdn.ResourceOptions_ReferrerACLOption{
				Enabled: true, Mode: cdn.ResourceOptions_ReferrerACLOption_MODE_ALLOW, Referrers: []string{"example.com"},
			},
			StaticResponse: &cdn.ResourceOptions_StaticResponseOption{
				Enabled: true, Code: 200, Content: "served-by-cdn",
			},
			SecureKey: &cdn.ResourceOptions_SecureKeyOption{
				Enabled: true, Key: "capture-secure-key-01", Type: cdn.SecureKeyURLType_DISABLE_IP_SIGNING,
			},
		},
	}
}

// updateAllFlipped contrasts updateAllOn: booleans go to false (the tristate
// round-trip that bites slice), the SECOND oneof variant of each group is used
// (fetch_compressed, redirect https→http, host string, query blacklist, edge
// cache simple+custom values), enums switch to deny, and scalars change.
func updateAllFlipped(resourceID string) *cdn.UpdateResourceRequest {
	return &cdn.UpdateResourceRequest{
		ResourceId:     resourceID,
		Active:         &wrapperspb.BoolValue{Value: false},
		OriginProtocol: cdn.OriginProtocol_MATCH,
		Labels:         map[string]string{"env": "capture", "tier": "silver"},
		Options: &cdn.ResourceOptions{
			EdgeCacheSettings: &cdn.ResourceOptions_EdgeCacheSettings{
				Enabled: true,
				ValuesVariant: &cdn.ResourceOptions_EdgeCacheSettings_Value{
					Value: &cdn.ResourceOptions_CachingTimes{
						SimpleValue:  600,
						CustomValues: map[string]int64{"404": 30, "500": 120},
					},
				},
			},
			BrowserCacheSettings: int64Opt(0),
			QueryParamsOptions: &cdn.ResourceOptions_QueryParamsOptions{
				QueryParamsVariant: &cdn.ResourceOptions_QueryParamsOptions_QueryParamsBlacklist{
					QueryParamsBlacklist: strListOpt("utm_source", "utm_medium"),
				},
			},
			Slice: boolOpt(false),
			CompressionOptions: &cdn.ResourceOptions_CompressionOptions{
				CompressionVariant: &cdn.ResourceOptions_CompressionOptions_FetchCompressed{
					FetchCompressed: boolOpt(true),
				},
			},
			HostOptions: &cdn.ResourceOptions_HostOptions{
				HostVariant: &cdn.ResourceOptions_HostOptions_Host{
					Host: strOpt("custom-host.example.com"),
				},
			},
			StaticHeaders:           strMapOpt(map[string]string{"x-static-response": "flipped"}),
			Cors:                    strListOpt("https://example.com"),
			Stale:                   strListOpt("http_404", "timeout"),
			ProxyCacheMethodsSet:    boolOpt(false),
			DisableProxyForceRanges: boolOpt(false),
			StaticRequestHeaders:    strMapOpt(map[string]string{"x-req-header": "v2"}),
			CustomServerName:        strOpt("flipped.example.com"),
			IgnoreCookie:            boolOpt(false),
			Rewrite: &cdn.ResourceOptions_RewriteOption{
				Enabled: true, Body: "/a/(.*) /b/$1", Flag: cdn.RewriteFlag_REDIRECT,
			},
			IpAddressAcl: &cdn.ResourceOptions_IPAddressACLOption{
				Enabled: true, PolicyType: cdn.PolicyType_POLICY_TYPE_DENY, ExceptedValues: []string{"203.0.113.0/24"},
			},
			FollowRedirects: &cdn.ResourceOptions_FollowRedirectsOption{
				Enabled: true, Codes: []int64{307, 308}, UseCustomHost: false,
			},
			HeaderFilter: &cdn.ResourceOptions_HeaderFilterOption{
				Enabled: true, Headers: []string{"x-keep-this", "x-and-this"},
			},
			GeoAcl: &cdn.ResourceOptions_GeoACLOption{
				Enabled: true, Mode: cdn.ResourceOptions_GeoACLOption_MODE_DENY, Countries: []string{"RU"},
			},
			ReferrerAcl: &cdn.ResourceOptions_ReferrerACLOption{
				Enabled: true, Mode: cdn.ResourceOptions_ReferrerACLOption_MODE_DENY, Referrers: []string{"*.spam.example"},
			},
			StaticResponse: &cdn.ResourceOptions_StaticResponseOption{
				Enabled: true, Code: 302, Content: "https://redirect.example.com",
			},
			SecureKey: &cdn.ResourceOptions_SecureKeyOption{
				Enabled: true, Key: "capture-secure-key-02", Type: cdn.SecureKeyURLType_ENABLE_IP_SIGNING,
			},
		},
	}
}

// updateAllOff drives the "disable / clear" path: every option that supports
// Enabled:false is turned off, lists/maps are cleared, scalars reset, brotli is
// used to cover the third compression variant, and labels are removed.
func updateAllOff(resourceID string) *cdn.UpdateResourceRequest {
	return &cdn.UpdateResourceRequest{
		ResourceId:     resourceID,
		Active:         &wrapperspb.BoolValue{Value: true},
		OriginProtocol: cdn.OriginProtocol_HTTP,
		RemoveLabels:   true,
		Options: &cdn.ResourceOptions{
			EdgeCacheSettings:    &cdn.ResourceOptions_EdgeCacheSettings{Enabled: false},
			BrowserCacheSettings: &cdn.ResourceOptions_Int64Option{Enabled: false},
			QueryParamsOptions: &cdn.ResourceOptions_QueryParamsOptions{
				QueryParamsVariant: &cdn.ResourceOptions_QueryParamsOptions_QueryParamsWhitelist{
					QueryParamsWhitelist: strListOpt("page"),
				},
			},
			Slice: disabledBool(),
			CompressionOptions: &cdn.ResourceOptions_CompressionOptions{
				CompressionVariant: &cdn.ResourceOptions_CompressionOptions_BrotliCompression{
					BrotliCompression: strListOpt("text/html", "application/json"),
				},
			},
			HostOptions: &cdn.ResourceOptions_HostOptions{
				HostVariant: &cdn.ResourceOptions_HostOptions_ForwardHostHeader{
					ForwardHostHeader: disabledBool(),
				},
			},
			StaticHeaders:           disabledMap(),
			Cors:                    disabledList(),
			Stale:                   disabledList(),
			ProxyCacheMethodsSet:    disabledBool(),
			DisableProxyForceRanges: disabledBool(),
			StaticRequestHeaders:    disabledMap(),
			CustomServerName:        &cdn.ResourceOptions_StringOption{Enabled: false},
			IgnoreCookie:            disabledBool(),
			Rewrite:                 &cdn.ResourceOptions_RewriteOption{Enabled: false},
			IpAddressAcl:            &cdn.ResourceOptions_IPAddressACLOption{Enabled: false},
			FollowRedirects:         &cdn.ResourceOptions_FollowRedirectsOption{Enabled: false},
			HeaderFilter:            &cdn.ResourceOptions_HeaderFilterOption{Enabled: false},
			GeoAcl:                  &cdn.ResourceOptions_GeoACLOption{Enabled: false},
			ReferrerAcl:             &cdn.ResourceOptions_ReferrerACLOption{Enabled: false},
			StaticResponse:          &cdn.ResourceOptions_StaticResponseOption{Enabled: false},
			SecureKey:               &cdn.ResourceOptions_SecureKeyOption{Enabled: false},
		},
	}
}
