package cdn_raw_log

import (
	"context"
	"errors"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/yandex-cloud/go-genproto/yandex/cloud/cdn/v1"
	"google.golang.org/grpc/codes"
	grpcstatus "google.golang.org/grpc/status"
)

// fakeBackend is an in-memory implementation of rawLogsBackend for unit tests.
// Each method can be overridden by the corresponding *Fn field; calls are
// recorded so tests can assert request shape.
type fakeBackend struct {
	activateFn   func(ctx context.Context, req *cdn.ActivateRawLogsRequest) error
	deactivateFn func(ctx context.Context, req *cdn.DeactivateRawLogsRequest) error
	updateFn     func(ctx context.Context, req *cdn.UpdateRawLogsRequest) error
	getFn        func(ctx context.Context, req *cdn.GetRawLogsRequest) (*cdn.GetRawLogsResponse, error)

	activateReqs   []*cdn.ActivateRawLogsRequest
	deactivateReqs []*cdn.DeactivateRawLogsRequest
	updateReqs     []*cdn.UpdateRawLogsRequest
	getReqs        []*cdn.GetRawLogsRequest
}

func (f *fakeBackend) Activate(ctx context.Context, req *cdn.ActivateRawLogsRequest) error {
	f.activateReqs = append(f.activateReqs, req)
	if f.activateFn != nil {
		return f.activateFn(ctx, req)
	}
	return nil
}

func (f *fakeBackend) Deactivate(ctx context.Context, req *cdn.DeactivateRawLogsRequest) error {
	f.deactivateReqs = append(f.deactivateReqs, req)
	if f.deactivateFn != nil {
		return f.deactivateFn(ctx, req)
	}
	return nil
}

func (f *fakeBackend) Update(ctx context.Context, req *cdn.UpdateRawLogsRequest) error {
	f.updateReqs = append(f.updateReqs, req)
	if f.updateFn != nil {
		return f.updateFn(ctx, req)
	}
	return nil
}

func (f *fakeBackend) Get(ctx context.Context, req *cdn.GetRawLogsRequest) (*cdn.GetRawLogsResponse, error) {
	f.getReqs = append(f.getReqs, req)
	if f.getFn != nil {
		return f.getFn(ctx, req)
	}
	return nil, errors.New("getFn not configured")
}

// newResourceForTest returns a resource wired with the given fake backend.
// providerConfig is left nil; tests must never go through api() with a nil backend.
func newResourceForTest(b rawLogsBackend) *cdnRawLogResource {
	return &cdnRawLogResource{backend: b}
}

// newPlan / newState build a tfsdk.Plan / State pre-populated with the given model
// against the resource schema. Each helper panics on failure — they are test-only
// fixtures and any failure here is a test-author bug, not something to report
// as a diag.
func newPlan(t *testing.T, m CDNRawLogResource) tfsdk.Plan {
	t.Helper()
	ctx := context.Background()
	schemaObj := CDNRawLogResourceSchema(ctx)
	p := tfsdk.Plan{Schema: schemaObj}
	diags := p.Set(ctx, &m)
	require.False(t, diags.HasError(), "plan.Set diagnostics: %v", diags)
	return p
}

func newState(t *testing.T, m CDNRawLogResource) tfsdk.State {
	t.Helper()
	ctx := context.Background()
	schemaObj := CDNRawLogResourceSchema(ctx)
	s := tfsdk.State{Schema: schemaObj}
	diags := s.Set(ctx, &m)
	require.False(t, diags.HasError(), "state.Set diagnostics: %v", diags)
	return s
}

// emptyState returns a tfsdk.State with the schema populated but raw value
// initialised to a fully null object — the shape Terraform produces when a
// resource is being created.
func emptyState(t *testing.T) tfsdk.State {
	t.Helper()
	return newState(t, CDNRawLogResource{
		ID:         types.StringNull(),
		ResourceID: types.StringNull(),
		Status:     types.StringNull(),
	})
}

// readState pulls a typed model back out of a populated state.
func readState(t *testing.T, s tfsdk.State) CDNRawLogResource {
	t.Helper()
	var m CDNRawLogResource
	diags := s.Get(context.Background(), &m)
	require.False(t, diags.HasError(), "state.Get diagnostics: %v", diags)
	return m
}

// rawLogsResponse builds a canned Get response. resourceID is accepted for
// caller readability — GetRawLogsResponse itself does not carry it.
func rawLogsResponse(_ /*resourceID*/, bucket, region, prefix string, st cdn.RawLogsStatus) *cdn.GetRawLogsResponse {
	return &cdn.GetRawLogsResponse{
		Status: st,
		Settings: &cdn.RawLogsSettings{
			BucketName:   bucket,
			BucketRegion: region,
			FilePrefix:   prefix,
		},
	}
}

// -----------------------------------------------------------------------------
// Create
// -----------------------------------------------------------------------------

func TestCreate_FullSettings(t *testing.T) {
	ctx := context.Background()
	be := &fakeBackend{
		getFn: func(_ context.Context, req *cdn.GetRawLogsRequest) (*cdn.GetRawLogsResponse, error) {
			return rawLogsResponse(req.ResourceId, "my-bucket", "ru-central1", "cdn/", cdn.RawLogsStatus_RAW_LOGS_STATUS_OK), nil
		},
	}
	r := newResourceForTest(be)

	plan := newPlan(t, CDNRawLogResource{
		ResourceID: types.StringValue("res-1"),
		Settings: &Settings{
			BucketName:   types.StringValue("my-bucket"),
			BucketRegion: types.StringValue("ru-central1"),
			FilePrefix:   types.StringValue("cdn/"),
		},
	})

	resp := resource.CreateResponse{State: emptyState(t)}
	r.Create(ctx, resource.CreateRequest{Plan: plan}, &resp)

	require.False(t, resp.Diagnostics.HasError(), "diagnostics: %v", resp.Diagnostics)
	require.Len(t, be.activateReqs, 1)
	require.Len(t, be.getReqs, 1)

	got := be.activateReqs[0]
	assert.Equal(t, "res-1", got.ResourceId)
	require.NotNil(t, got.Settings)
	assert.Equal(t, "my-bucket", got.Settings.BucketName)
	assert.Equal(t, "ru-central1", got.Settings.BucketRegion)
	assert.Equal(t, "cdn/", got.Settings.FilePrefix)

	final := readState(t, resp.State)
	assert.Equal(t, "res-1", final.ID.ValueString())
	assert.Equal(t, "res-1", final.ResourceID.ValueString())
	assert.Equal(t, "RAW_LOGS_STATUS_OK", final.Status.ValueString(),
		"resource exposes the proto enum name directly (NB: schema docstring says 'ACTIVE' but the code emits the proto name)")
	require.NotNil(t, final.Settings)
	assert.Equal(t, "my-bucket", final.Settings.BucketName.ValueString())
	assert.Equal(t, "ru-central1", final.Settings.BucketRegion.ValueString())
	assert.Equal(t, "cdn/", final.Settings.FilePrefix.ValueString())
}

func TestCreate_DefaultsBucketRegion_WhenNull(t *testing.T) {
	ctx := context.Background()
	be := &fakeBackend{
		getFn: func(_ context.Context, req *cdn.GetRawLogsRequest) (*cdn.GetRawLogsResponse, error) {
			return rawLogsResponse(req.ResourceId, "b", "ru-central1", "", cdn.RawLogsStatus_RAW_LOGS_STATUS_OK), nil
		},
	}
	r := newResourceForTest(be)

	plan := newPlan(t, CDNRawLogResource{
		ResourceID: types.StringValue("res-2"),
		Settings: &Settings{
			BucketName:   types.StringValue("b"),
			BucketRegion: types.StringNull(),
			FilePrefix:   types.StringNull(),
		},
	})

	resp := resource.CreateResponse{State: emptyState(t)}
	r.Create(ctx, resource.CreateRequest{Plan: plan}, &resp)

	require.False(t, resp.Diagnostics.HasError(), "%v", resp.Diagnostics)
	require.Len(t, be.activateReqs, 1)
	assert.Equal(t, "ru-central1", be.activateReqs[0].Settings.BucketRegion,
		"null BucketRegion should default to ru-central1 on activate")
}

func TestCreate_NilSettings(t *testing.T) {
	ctx := context.Background()
	be := &fakeBackend{
		getFn: func(_ context.Context, req *cdn.GetRawLogsRequest) (*cdn.GetRawLogsResponse, error) {
			_ = req
			return &cdn.GetRawLogsResponse{Status: cdn.RawLogsStatus_RAW_LOGS_STATUS_OK}, nil
		},
	}
	r := newResourceForTest(be)

	plan := newPlan(t, CDNRawLogResource{
		ResourceID: types.StringValue("res-3"),
		Settings:   nil,
	})

	resp := resource.CreateResponse{State: emptyState(t)}
	r.Create(ctx, resource.CreateRequest{Plan: plan}, &resp)

	require.False(t, resp.Diagnostics.HasError(), "%v", resp.Diagnostics)
	require.Len(t, be.activateReqs, 1)
	assert.Nil(t, be.activateReqs[0].Settings, "nil plan.Settings should yield nil Settings on the wire")
}

func TestCreate_ActivateFails_DiagAdded(t *testing.T) {
	ctx := context.Background()
	be := &fakeBackend{
		activateFn: func(_ context.Context, _ *cdn.ActivateRawLogsRequest) error {
			return errors.New("api refused")
		},
	}
	r := newResourceForTest(be)

	plan := newPlan(t, CDNRawLogResource{
		ResourceID: types.StringValue("res-4"),
		Settings:   &Settings{BucketName: types.StringValue("b")},
	})

	resp := resource.CreateResponse{State: emptyState(t)}
	r.Create(ctx, resource.CreateRequest{Plan: plan}, &resp)

	require.True(t, resp.Diagnostics.HasError())
	assert.Empty(t, be.getReqs, "Get must not be called when Activate fails")
	d := resp.Diagnostics[0]
	assert.Contains(t, d.Summary(), "Error activating CDN Raw Logs")
	assert.Contains(t, d.Detail(), "api refused")
}

func TestCreate_GetAfterActivateFails_DiagAdded(t *testing.T) {
	ctx := context.Background()
	be := &fakeBackend{
		getFn: func(_ context.Context, _ *cdn.GetRawLogsRequest) (*cdn.GetRawLogsResponse, error) {
			return nil, errors.New("internal")
		},
	}
	r := newResourceForTest(be)

	plan := newPlan(t, CDNRawLogResource{
		ResourceID: types.StringValue("res-5"),
		Settings:   &Settings{BucketName: types.StringValue("b")},
	})

	resp := resource.CreateResponse{State: emptyState(t)}
	r.Create(ctx, resource.CreateRequest{Plan: plan}, &resp)

	require.True(t, resp.Diagnostics.HasError())
	assert.Equal(t, "Error reading CDN Raw Log", resp.Diagnostics[0].Summary())
	assert.Len(t, be.activateReqs, 1)
}

// -----------------------------------------------------------------------------
// Read
// -----------------------------------------------------------------------------

func TestRead_Success(t *testing.T) {
	ctx := context.Background()
	be := &fakeBackend{
		getFn: func(_ context.Context, req *cdn.GetRawLogsRequest) (*cdn.GetRawLogsResponse, error) {
			return rawLogsResponse(req.ResourceId, "bk", "us-east-1", "p/", cdn.RawLogsStatus_RAW_LOGS_STATUS_OK), nil
		},
	}
	r := newResourceForTest(be)

	state := newState(t, CDNRawLogResource{
		ID:         types.StringValue("res-6"),
		ResourceID: types.StringValue("res-6"),
	})
	resp := resource.ReadResponse{State: state}
	r.Read(ctx, resource.ReadRequest{State: state}, &resp)

	require.False(t, resp.Diagnostics.HasError(), "%v", resp.Diagnostics)
	m := readState(t, resp.State)
	assert.Equal(t, "RAW_LOGS_STATUS_OK", m.Status.ValueString())
	require.NotNil(t, m.Settings)
	assert.Equal(t, "bk", m.Settings.BucketName.ValueString())
	assert.Equal(t, "us-east-1", m.Settings.BucketRegion.ValueString())
}

func TestRead_NotFound_RemovesResource(t *testing.T) {
	ctx := context.Background()
	be := &fakeBackend{
		getFn: func(_ context.Context, _ *cdn.GetRawLogsRequest) (*cdn.GetRawLogsResponse, error) {
			return nil, grpcstatus.Error(codes.NotFound, "gone")
		},
	}
	r := newResourceForTest(be)

	state := newState(t, CDNRawLogResource{
		ID:         types.StringValue("res-7"),
		ResourceID: types.StringValue("res-7"),
	})
	resp := resource.ReadResponse{State: state}
	r.Read(ctx, resource.ReadRequest{State: state}, &resp)

	require.False(t, resp.Diagnostics.HasError())
	assert.True(t, resp.State.Raw.IsNull(), "state should be cleared after NotFound")
}

func TestRead_OtherError_AddsDiag(t *testing.T) {
	ctx := context.Background()
	be := &fakeBackend{
		getFn: func(_ context.Context, _ *cdn.GetRawLogsRequest) (*cdn.GetRawLogsResponse, error) {
			return nil, grpcstatus.Error(codes.Internal, "boom")
		},
	}
	r := newResourceForTest(be)

	state := newState(t, CDNRawLogResource{
		ID:         types.StringValue("res-8"),
		ResourceID: types.StringValue("res-8"),
	})
	resp := resource.ReadResponse{State: state}
	r.Read(ctx, resource.ReadRequest{State: state}, &resp)

	require.True(t, resp.Diagnostics.HasError())
	assert.Equal(t, "Error reading CDN Raw Log", resp.Diagnostics[0].Summary())
}

// -----------------------------------------------------------------------------
// Update
// -----------------------------------------------------------------------------

func TestUpdate_ChangesBucket(t *testing.T) {
	ctx := context.Background()
	be := &fakeBackend{
		getFn: func(_ context.Context, req *cdn.GetRawLogsRequest) (*cdn.GetRawLogsResponse, error) {
			return rawLogsResponse(req.ResourceId, "new-bucket", "ru-central1", "logs/", cdn.RawLogsStatus_RAW_LOGS_STATUS_OK), nil
		},
	}
	r := newResourceForTest(be)

	state := newState(t, CDNRawLogResource{
		ID:         types.StringValue("res-9"),
		ResourceID: types.StringValue("res-9"),
		Status:     types.StringValue("ACTIVE"),
		Settings: &Settings{
			BucketName:   types.StringValue("old-bucket"),
			BucketRegion: types.StringValue("ru-central1"),
			FilePrefix:   types.StringValue("logs/"),
		},
	})
	plan := newPlan(t, CDNRawLogResource{
		ID:         types.StringValue("res-9"),
		ResourceID: types.StringValue("res-9"),
		Status:     types.StringValue("ACTIVE"),
		Settings: &Settings{
			BucketName:   types.StringValue("new-bucket"),
			BucketRegion: types.StringValue("ru-central1"),
			FilePrefix:   types.StringValue("logs/"),
		},
	})

	resp := resource.UpdateResponse{State: state}
	r.Update(ctx, resource.UpdateRequest{Plan: plan, State: state}, &resp)

	require.False(t, resp.Diagnostics.HasError(), "%v", resp.Diagnostics)
	require.Len(t, be.updateReqs, 1)
	assert.Equal(t, "new-bucket", be.updateReqs[0].Settings.BucketName)
	m := readState(t, resp.State)
	assert.Equal(t, "new-bucket", m.Settings.BucketName.ValueString())
}

func TestUpdate_APIError(t *testing.T) {
	ctx := context.Background()
	be := &fakeBackend{
		updateFn: func(_ context.Context, _ *cdn.UpdateRawLogsRequest) error {
			return errors.New("permission denied")
		},
	}
	r := newResourceForTest(be)

	state := newState(t, CDNRawLogResource{
		ResourceID: types.StringValue("res-10"),
		Settings:   &Settings{BucketName: types.StringValue("b")},
	})
	plan := newPlan(t, CDNRawLogResource{
		ResourceID: types.StringValue("res-10"),
		Settings:   &Settings{BucketName: types.StringValue("b2")},
	})

	resp := resource.UpdateResponse{State: state}
	r.Update(ctx, resource.UpdateRequest{Plan: plan, State: state}, &resp)

	require.True(t, resp.Diagnostics.HasError())
	assert.Empty(t, be.getReqs, "Get must not be called when Update fails")
	assert.Equal(t, "Error updating CDN Raw Logs", resp.Diagnostics[0].Summary())
}

func TestUpdate_GetAfterUpdateFails(t *testing.T) {
	ctx := context.Background()
	be := &fakeBackend{
		getFn: func(_ context.Context, _ *cdn.GetRawLogsRequest) (*cdn.GetRawLogsResponse, error) {
			return nil, errors.New("internal")
		},
	}
	r := newResourceForTest(be)

	state := newState(t, CDNRawLogResource{
		ResourceID: types.StringValue("res-11"),
		Settings:   &Settings{BucketName: types.StringValue("b")},
	})
	plan := newPlan(t, CDNRawLogResource{
		ResourceID: types.StringValue("res-11"),
		Settings:   &Settings{BucketName: types.StringValue("b2")},
	})

	resp := resource.UpdateResponse{State: state}
	r.Update(ctx, resource.UpdateRequest{Plan: plan, State: state}, &resp)

	require.True(t, resp.Diagnostics.HasError())
	assert.Equal(t, "Error reading CDN Raw Log", resp.Diagnostics[0].Summary())
	assert.Len(t, be.updateReqs, 1)
}

// -----------------------------------------------------------------------------
// Delete
// -----------------------------------------------------------------------------

func TestDelete_Success(t *testing.T) {
	ctx := context.Background()
	be := &fakeBackend{}
	r := newResourceForTest(be)

	state := newState(t, CDNRawLogResource{
		ResourceID: types.StringValue("res-12"),
		Settings:   &Settings{BucketName: types.StringValue("b")},
	})
	resp := resource.DeleteResponse{State: state}
	r.Delete(ctx, resource.DeleteRequest{State: state}, &resp)

	require.False(t, resp.Diagnostics.HasError(), "%v", resp.Diagnostics)
	require.Len(t, be.deactivateReqs, 1)
	assert.Equal(t, "res-12", be.deactivateReqs[0].ResourceId)
}

func TestDelete_NotFound_NoError(t *testing.T) {
	ctx := context.Background()
	be := &fakeBackend{
		deactivateFn: func(_ context.Context, _ *cdn.DeactivateRawLogsRequest) error {
			return grpcstatus.Error(codes.NotFound, "already gone")
		},
	}
	r := newResourceForTest(be)

	state := newState(t, CDNRawLogResource{
		ResourceID: types.StringValue("res-13"),
		Settings:   &Settings{BucketName: types.StringValue("b")},
	})
	resp := resource.DeleteResponse{State: state}
	r.Delete(ctx, resource.DeleteRequest{State: state}, &resp)

	require.False(t, resp.Diagnostics.HasError(), "NotFound on Deactivate must be swallowed; got %v", resp.Diagnostics)
}

func TestDelete_OtherError(t *testing.T) {
	ctx := context.Background()
	be := &fakeBackend{
		deactivateFn: func(_ context.Context, _ *cdn.DeactivateRawLogsRequest) error {
			return grpcstatus.Error(codes.Internal, "boom")
		},
	}
	r := newResourceForTest(be)

	state := newState(t, CDNRawLogResource{
		ResourceID: types.StringValue("res-14"),
		Settings:   &Settings{BucketName: types.StringValue("b")},
	})
	resp := resource.DeleteResponse{State: state}
	r.Delete(ctx, resource.DeleteRequest{State: state}, &resp)

	require.True(t, resp.Diagnostics.HasError())
	assert.Equal(t, "Error deactivating CDN Raw Logs", resp.Diagnostics[0].Summary())
}

// -----------------------------------------------------------------------------
// ImportState
// -----------------------------------------------------------------------------

func TestImportState_SetsResourceID(t *testing.T) {
	ctx := context.Background()
	r := newResourceForTest(&fakeBackend{})

	resp := resource.ImportStateResponse{State: emptyState(t)}
	r.ImportState(ctx, resource.ImportStateRequest{ID: "imported-res"}, &resp)

	require.False(t, resp.Diagnostics.HasError(), "%v", resp.Diagnostics)
	var got types.String
	diags := resp.State.GetAttribute(ctx, path.Root("resource_id"), &got)
	require.False(t, diags.HasError(), "%v", diags)
	assert.Equal(t, "imported-res", got.ValueString())
}

// -----------------------------------------------------------------------------
// rawLogsSettingsFromPlan (pure helper, can be tested directly)
// -----------------------------------------------------------------------------

func TestRawLogsSettingsFromPlan_Nil(t *testing.T) {
	assert.Nil(t, rawLogsSettingsFromPlan(nil))
}

func TestRawLogsSettingsFromPlan_DefaultsRegion(t *testing.T) {
	got := rawLogsSettingsFromPlan(&Settings{
		BucketName:   types.StringValue("b"),
		BucketRegion: types.StringNull(),
		FilePrefix:   types.StringValue("p/"),
	})
	require.NotNil(t, got)
	assert.Equal(t, "b", got.BucketName)
	assert.Equal(t, "ru-central1", got.BucketRegion)
	assert.Equal(t, "p/", got.FilePrefix)
}

func TestRawLogsSettingsFromPlan_KeepsRegion(t *testing.T) {
	got := rawLogsSettingsFromPlan(&Settings{
		BucketName:   types.StringValue("b"),
		BucketRegion: types.StringValue("eu-west-1"),
		FilePrefix:   types.StringValue(""),
	})
	require.NotNil(t, got)
	assert.Equal(t, "eu-west-1", got.BucketRegion)
}

// -----------------------------------------------------------------------------
// file_prefix validator
// -----------------------------------------------------------------------------

func TestFilePrefixValidator(t *testing.T) {
	cases := []struct {
		in    string
		valid bool
	}{
		{"", true},
		{"capture", true},
		{"cdn-logs", true},
		{"cdn/logs", true},      // slash in the middle is fine
		{"a/b/c", true},         // multiple slashes in the middle is fine
		{"/", false},            // bare slash is trailing
		{"trailing/", false},    // classic case from the API rejection
		{"deep/path/", false},   // any trailing slash
		{"trailing//", false},   // double trailing slash
	}
	for _, tc := range cases {
		got := filePrefixNoTrailingSlash.MatchString(tc.in)
		if got != tc.valid {
			t.Errorf("filePrefixNoTrailingSlash(%q) = %v, want %v", tc.in, got, tc.valid)
		}
	}
}
