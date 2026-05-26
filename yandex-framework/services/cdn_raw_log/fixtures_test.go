package cdn_raw_log

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/yandex-cloud/go-genproto/yandex/cloud/cdn/v1"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
)

// Fixtures-driven tests: replay captured API responses through the resource and
// verify the resulting state. Fixtures are produced by
// scripts/cdn_raw_log_capture and live under testdata/fixtures/. If that
// directory is empty (e.g. CI without credentials), these tests skip.
//
// The point is to keep the unit-test mocks honest: a real-API capture serves
// as ground truth for the response shapes the resource handles.

const fixturesDir = "testdata/fixtures"

// fixtureFile mirrors the structure written by the capture script.
type fixtureFile struct {
	Step     string          `json:"step"`
	Request  json.RawMessage `json:"request,omitempty"`
	Response json.RawMessage `json:"response,omitempty"`
	GRPCCode string          `json:"grpc_code,omitempty"`
	Error    string          `json:"error,omitempty"`
}

// loadFixture reads a single fixture from testdata/fixtures and skips the test
// if it is missing. It does not decode the proto payloads — callers do that
// against a typed proto.Message of their choosing.
func loadFixture(t *testing.T, name string) fixtureFile {
	t.Helper()
	path := filepath.Join(fixturesDir, name)
	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		t.Skipf("fixture %s not present — run `go run ./scripts/cdn_raw_log_capture` to generate it", path)
	}
	require.NoError(t, err, "read fixture %s", path)
	var f fixtureFile
	require.NoError(t, json.Unmarshal(data, &f), "unmarshal %s", path)
	return f
}

// decodeResponse unmarshals the fixture's protojson `response` field into the
// supplied typed proto.Message. The fixture stored the response as a generic
// JSON object, so we re-marshal that field and feed it through protojson.
func decodeResponse(t *testing.T, f fixtureFile, into proto.Message) {
	t.Helper()
	if len(f.Response) == 0 || string(f.Response) == "null" {
		t.Fatalf("fixture %s has no response payload", f.Step)
	}
	require.NoError(t, protojson.Unmarshal(f.Response, into),
		"protojson unmarshal of %s response", f.Step)
}

// TestGolden_Read_AgainstActivatedFixture replays the 03_get_after_activate
// fixture through the resource's Read flow and verifies the state matches.
// This is the most direct check that our model<->wire mapping is correct
// against a real API response shape.
func TestGolden_Read_AgainstActivatedFixture(t *testing.T) {
	f := loadFixture(t, "03_get_after_activate.json")
	if f.Error != "" {
		t.Skipf("fixture recorded an error (%s); expected a successful response", f.Error)
	}

	var apiResp cdn.GetRawLogsResponse
	decodeResponse(t, f, &apiResp)

	be := &fakeBackend{
		getFn: func(_ context.Context, _ *cdn.GetRawLogsRequest) (*cdn.GetRawLogsResponse, error) {
			return &apiResp, nil
		},
	}
	r := newResourceForTest(be)

	state := newState(t, CDNRawLogResource{
		ID:         types.StringValue("from-fixture"),
		ResourceID: types.StringValue("from-fixture"),
	})
	resp := resource.ReadResponse{State: state}
	r.Read(context.Background(), resource.ReadRequest{State: state}, &resp)

	require.False(t, resp.Diagnostics.HasError(), "%v", resp.Diagnostics)

	got := readState(t, resp.State)

	// Status maps via proto enum String().
	assert.Equal(t, apiResp.Status.String(), got.Status.ValueString())

	if apiResp.GetSettings() == nil {
		assert.Nil(t, got.Settings)
		return
	}
	require.NotNil(t, got.Settings)
	assert.Equal(t, apiResp.GetSettings().GetBucketName(), got.Settings.BucketName.ValueString())
	if apiResp.GetSettings().GetBucketRegion() != "" {
		assert.Equal(t, apiResp.GetSettings().GetBucketRegion(), got.Settings.BucketRegion.ValueString())
	} else {
		assert.True(t, got.Settings.BucketRegion.IsNull(), "empty region from API should leave state null")
	}
	if apiResp.GetSettings().GetFilePrefix() != "" {
		assert.Equal(t, apiResp.GetSettings().GetFilePrefix(), got.Settings.FilePrefix.ValueString())
	} else {
		assert.True(t, got.Settings.FilePrefix.IsNull(), "empty prefix from API should leave state null")
	}
}

// TestGolden_Lifecycle replays the full captured lifecycle end-to-end:
//   - Activate request shape derived from plan matches what the capture saw
//   - Create+Read produces the expected state after activate
//   - Update changes prefix exactly the same way the capture did
//   - Delete issues Deactivate for the same resource ID
//
// If any fixture is missing this test is skipped.
func TestGolden_Lifecycle(t *testing.T) {
	activateReqFx := loadFixture(t, "02_activate.json")
	afterActivate := loadFixture(t, "03_get_after_activate.json")
	updateReqFx := loadFixture(t, "04_update.json")
	afterUpdate := loadFixture(t, "05_get_after_update.json")

	var (
		wantActivate cdn.ActivateRawLogsRequest
		wantUpdate   cdn.UpdateRawLogsRequest
		respActivate cdn.GetRawLogsResponse
		respUpdate   cdn.GetRawLogsResponse
	)
	require.NoError(t, protojson.Unmarshal(activateReqFx.Request, &wantActivate))
	require.NoError(t, protojson.Unmarshal(updateReqFx.Request, &wantUpdate))
	decodeResponse(t, afterActivate, &respActivate)
	decodeResponse(t, afterUpdate, &respUpdate)

	resourceID := wantActivate.GetResourceId()
	getCalls := 0
	be := &fakeBackend{
		getFn: func(_ context.Context, _ *cdn.GetRawLogsRequest) (*cdn.GetRawLogsResponse, error) {
			getCalls++
			// 1st Get is post-Activate (Create flow), 2nd is post-Update.
			if getCalls == 1 {
				return &respActivate, nil
			}
			return &respUpdate, nil
		},
	}
	r := newResourceForTest(be)

	// --- Create (mimics the captured Activate) ---
	createPlan := newPlan(t, CDNRawLogResource{
		ResourceID: types.StringValue(resourceID),
		Settings: settingsFromProto(wantActivate.GetSettings()),
	})
	createResp := resource.CreateResponse{State: emptyState(t)}
	r.Create(context.Background(), resource.CreateRequest{Plan: createPlan}, &createResp)
	require.False(t, createResp.Diagnostics.HasError(), "%v", createResp.Diagnostics)
	require.Len(t, be.activateReqs, 1)
	assertActivateMatches(t, &wantActivate, be.activateReqs[0])

	stateAfterCreate := readState(t, createResp.State)
	assert.Equal(t, respActivate.Status.String(), stateAfterCreate.Status.ValueString())

	// --- Update (mimics the captured Update) ---
	updatePlan := newPlan(t, CDNRawLogResource{
		ID:         types.StringValue(resourceID),
		ResourceID: types.StringValue(resourceID),
		Status:     stateAfterCreate.Status,
		Settings:   settingsFromProto(wantUpdate.GetSettings()),
	})
	updateResp := resource.UpdateResponse{State: createResp.State}
	r.Update(context.Background(), resource.UpdateRequest{
		Plan:  updatePlan,
		State: createResp.State,
	}, &updateResp)
	require.False(t, updateResp.Diagnostics.HasError(), "%v", updateResp.Diagnostics)
	require.Len(t, be.updateReqs, 1)
	assertUpdateMatches(t, &wantUpdate, be.updateReqs[0])

	stateAfterUpdate := readState(t, updateResp.State)
	if respUpdate.GetSettings() != nil {
		assert.Equal(t, respUpdate.GetSettings().GetFilePrefix(), stateAfterUpdate.Settings.FilePrefix.ValueString())
	}

	// --- Delete ---
	deleteResp := resource.DeleteResponse{State: updateResp.State}
	r.Delete(context.Background(), resource.DeleteRequest{State: updateResp.State}, &deleteResp)
	require.False(t, deleteResp.Diagnostics.HasError(), "%v", deleteResp.Diagnostics)
	require.Len(t, be.deactivateReqs, 1)
	assert.Equal(t, resourceID, be.deactivateReqs[0].GetResourceId())
}

// settingsFromProto converts a proto RawLogsSettings (as captured from the API)
// into the resource model's Settings — used to drive the Plan in lifecycle
// tests.
func settingsFromProto(s *cdn.RawLogsSettings) *Settings {
	if s == nil {
		return nil
	}
	out := &Settings{
		BucketName: types.StringValue(s.GetBucketName()),
	}
	if s.GetBucketRegion() != "" {
		out.BucketRegion = types.StringValue(s.GetBucketRegion())
	} else {
		out.BucketRegion = types.StringNull()
	}
	if s.GetFilePrefix() != "" {
		out.FilePrefix = types.StringValue(s.GetFilePrefix())
	} else {
		out.FilePrefix = types.StringNull()
	}
	return out
}

func assertActivateMatches(t *testing.T, want, got *cdn.ActivateRawLogsRequest) {
	t.Helper()
	assert.Equal(t, want.GetResourceId(), got.GetResourceId(), "Activate.ResourceId")
	assertSettingsMatch(t, "Activate.Settings", want.GetSettings(), got.GetSettings())
}

func assertUpdateMatches(t *testing.T, want, got *cdn.UpdateRawLogsRequest) {
	t.Helper()
	assert.Equal(t, want.GetResourceId(), got.GetResourceId(), "Update.ResourceId")
	assertSettingsMatch(t, "Update.Settings", want.GetSettings(), got.GetSettings())
}

func assertSettingsMatch(t *testing.T, label string, want, got *cdn.RawLogsSettings) {
	t.Helper()
	if want == nil {
		assert.Nil(t, got, "%s should be nil", label)
		return
	}
	require.NotNil(t, got, "%s should not be nil", label)
	assert.Equal(t, want.GetBucketName(), got.GetBucketName(), "%s.BucketName", label)
	assert.Equal(t, want.GetBucketRegion(), got.GetBucketRegion(), "%s.BucketRegion", label)
	assert.Equal(t, want.GetFilePrefix(), got.GetFilePrefix(), "%s.FilePrefix", label)
}
