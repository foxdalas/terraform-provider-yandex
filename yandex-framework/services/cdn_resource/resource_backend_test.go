package cdn_resource

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/hashicorp/terraform-plugin-framework-timeouts/resource/timeouts"
	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/yandex-cloud/go-genproto/yandex/cloud/cdn/v1"
	"github.com/yandex-cloud/terraform-provider-yandex/yandex-framework/provider/config"
	"google.golang.org/grpc/codes"
	grpcstatus "google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// fakeResourceBackend is an in-memory implementation of resourceBackend for tests.
type fakeResourceBackend struct {
	createFn func(ctx context.Context, req *cdn.CreateResourceRequest) (string, error)
	getFn    func(ctx context.Context, req *cdn.GetResourceRequest) (*cdn.Resource, error)
	updateFn func(ctx context.Context, req *cdn.UpdateResourceRequest) error
	deleteFn func(ctx context.Context, req *cdn.DeleteResourceRequest) error
	listFn   func(ctx context.Context, req *cdn.ListResourcesRequest) ([]*cdn.Resource, error)

	originGroupListFn func(ctx context.Context, req *cdn.ListOriginGroupsRequest) ([]*cdn.OriginGroup, error)

	shieldingGetFn        func(ctx context.Context, req *cdn.GetShieldingDetailsRequest) (*cdn.ShieldingDetails, error)
	shieldingActivateFn   func(ctx context.Context, req *cdn.ActivateShieldingRequest) error
	shieldingDeactivateFn func(ctx context.Context, req *cdn.DeactivateShieldingRequest) error

	createReqs []*cdn.CreateResourceRequest
	getReqs    []*cdn.GetResourceRequest
	updateReqs []*cdn.UpdateResourceRequest
	deleteReqs []*cdn.DeleteResourceRequest
	listReqs   []*cdn.ListResourcesRequest

	originGroupListReqs []*cdn.ListOriginGroupsRequest

	shieldingGetReqs        []*cdn.GetShieldingDetailsRequest
	shieldingActivateReqs   []*cdn.ActivateShieldingRequest
	shieldingDeactivateReqs []*cdn.DeactivateShieldingRequest
}

func (f *fakeResourceBackend) Create(ctx context.Context, req *cdn.CreateResourceRequest) (string, error) {
	f.createReqs = append(f.createReqs, req)
	if f.createFn != nil {
		return f.createFn(ctx, req)
	}
	return "", errors.New("createFn not configured")
}

func (f *fakeResourceBackend) Get(ctx context.Context, req *cdn.GetResourceRequest) (*cdn.Resource, error) {
	f.getReqs = append(f.getReqs, req)
	if f.getFn != nil {
		return f.getFn(ctx, req)
	}
	return nil, errors.New("getFn not configured")
}

func (f *fakeResourceBackend) Update(ctx context.Context, req *cdn.UpdateResourceRequest) error {
	f.updateReqs = append(f.updateReqs, req)
	if f.updateFn != nil {
		return f.updateFn(ctx, req)
	}
	return nil
}

func (f *fakeResourceBackend) Delete(ctx context.Context, req *cdn.DeleteResourceRequest) error {
	f.deleteReqs = append(f.deleteReqs, req)
	if f.deleteFn != nil {
		return f.deleteFn(ctx, req)
	}
	return nil
}

func (f *fakeResourceBackend) List(ctx context.Context, req *cdn.ListResourcesRequest) ([]*cdn.Resource, error) {
	f.listReqs = append(f.listReqs, req)
	if f.listFn != nil {
		return f.listFn(ctx, req)
	}
	return nil, errors.New("listFn not configured")
}

func (f *fakeResourceBackend) OriginGroupList(ctx context.Context, req *cdn.ListOriginGroupsRequest) ([]*cdn.OriginGroup, error) {
	f.originGroupListReqs = append(f.originGroupListReqs, req)
	if f.originGroupListFn != nil {
		return f.originGroupListFn(ctx, req)
	}
	return nil, errors.New("originGroupListFn not configured")
}

func (f *fakeResourceBackend) ShieldingGet(ctx context.Context, req *cdn.GetShieldingDetailsRequest) (*cdn.ShieldingDetails, error) {
	f.shieldingGetReqs = append(f.shieldingGetReqs, req)
	if f.shieldingGetFn != nil {
		return f.shieldingGetFn(ctx, req)
	}
	// Default: shielding not configured.
	return nil, grpcstatus.Error(codes.NotFound, "no shielding")
}

func (f *fakeResourceBackend) ShieldingActivate(ctx context.Context, req *cdn.ActivateShieldingRequest) error {
	f.shieldingActivateReqs = append(f.shieldingActivateReqs, req)
	if f.shieldingActivateFn != nil {
		return f.shieldingActivateFn(ctx, req)
	}
	return nil
}

func (f *fakeResourceBackend) ShieldingDeactivate(ctx context.Context, req *cdn.DeactivateShieldingRequest) error {
	f.shieldingDeactivateReqs = append(f.shieldingDeactivateReqs, req)
	if f.shieldingDeactivateFn != nil {
		return f.shieldingDeactivateFn(ctx, req)
	}
	return nil
}

// newResourceForTest returns a resource wired to the supplied backend and a
// providerConfig with a folder_id default so getFolderID works without a real
// SDK behind it.
func newResourceForTest(b resourceBackend) *cdnResourceResource {
	return &cdnResourceResource{
		backend: b,
		providerConfig: &config.Config{
			ProviderState: config.State{
				FolderID: types.StringValue("test-folder"),
			},
		},
	}
}

// nullResourceTimeouts returns the empty timeouts.Value that the schema accepts
// for the resource's timeouts block.
func nullResourceTimeouts() timeouts.Value {
	return timeouts.Value{
		Object: types.ObjectNull(map[string]attr.Type{
			"create": types.StringType,
			"update": types.StringType,
			"delete": types.StringType,
		}),
	}
}

// nullResourceOptionsList returns a properly-typed null options list (matches
// the resource schema).
func nullResourceOptionsList() types.List {
	return types.ListNull(types.ObjectType{AttrTypes: GetCDNOptionsAttrTypes()})
}

// nullSSLList returns a properly-typed null ssl_certificate list.
func nullSSLList() types.List {
	return types.ListNull(types.ObjectType{
		AttrTypes: map[string]attr.Type{
			"type":                   types.StringType,
			"status":                 types.StringType,
			"certificate_manager_id": types.StringType,
		},
	})
}

func fillResourceModelDefaults(m *CDNResourceModel) {
	if m.Timeouts.IsNull() && !m.Timeouts.IsUnknown() && len(m.Timeouts.Attributes()) == 0 {
		m.Timeouts = nullResourceTimeouts()
	}
	if m.Options.IsNull() && !m.Options.IsUnknown() && m.Options.ElementType(context.Background()) == nil {
		m.Options = nullResourceOptionsList()
	}
	if m.SSLCertificate.IsNull() && !m.SSLCertificate.IsUnknown() && m.SSLCertificate.ElementType(context.Background()) == nil {
		m.SSLCertificate = nullSSLList()
	}
	if m.Labels.IsNull() && !m.Labels.IsUnknown() && m.Labels.ElementType(context.Background()) == nil {
		m.Labels = types.MapNull(types.StringType)
	}
	if m.SecondaryHostnames.IsNull() && !m.SecondaryHostnames.IsUnknown() && m.SecondaryHostnames.ElementType(context.Background()) == nil {
		m.SecondaryHostnames = types.SetNull(types.StringType)
	}
}

func newResourcePlan(t *testing.T, m CDNResourceModel) tfsdk.Plan {
	t.Helper()
	fillResourceModelDefaults(&m)
	ctx := context.Background()
	s := CDNResourceSchema(ctx)
	p := tfsdk.Plan{Schema: s}
	diags := p.Set(ctx, &m)
	require.False(t, diags.HasError(), "plan.Set diagnostics: %v", diags)
	return p
}

func newResourceState(t *testing.T, m CDNResourceModel) tfsdk.State {
	t.Helper()
	fillResourceModelDefaults(&m)
	ctx := context.Background()
	s := CDNResourceSchema(ctx)
	st := tfsdk.State{Schema: s}
	diags := st.Set(ctx, &m)
	require.False(t, diags.HasError(), "state.Set diagnostics: %v", diags)
	return st
}

func emptyResourceState(t *testing.T) tfsdk.State {
	t.Helper()
	return newResourceState(t, CDNResourceModel{})
}

func readResourceModel(t *testing.T, s tfsdk.State) CDNResourceModel {
	t.Helper()
	var m CDNResourceModel
	diags := s.Get(context.Background(), &m)
	require.False(t, diags.HasError(), "state.Get diagnostics: %v", diags)
	return m
}

// cannedResource builds a minimal *cdn.Resource for Get-mock responses with
// all fields readResourceToState expects to be non-nil.
func cannedResource(id, cname, folderID string, originGroupID int64, active bool) *cdn.Resource {
	now := time.Now().UTC()
	return &cdn.Resource{
		Id:              id,
		Cname:           cname,
		FolderId:        folderID,
		Active:          active,
		OriginGroupId:   originGroupID,
		OriginGroupName: "og",
		OriginProtocol:  cdn.OriginProtocol_HTTP,
		ProviderType:    "gcore",
		ProviderCname:   cname + ".cdn",
		CreatedAt:       timestamppb.New(now),
		UpdatedAt:       timestamppb.New(now),
	}
}

// -----------------------------------------------------------------------------
// Create
// -----------------------------------------------------------------------------

func TestResourceCreate_Success(t *testing.T) {
	ctx := context.Background()
	be := &fakeResourceBackend{
		createFn: func(_ context.Context, _ *cdn.CreateResourceRequest) (string, error) {
			return "res-abc", nil
		},
		getFn: func(_ context.Context, req *cdn.GetResourceRequest) (*cdn.Resource, error) {
			assert.Equal(t, "res-abc", req.ResourceId)
			return cannedResource("res-abc", "cdn.example.com", "test-folder", 100, true), nil
		},
	}
	r := newResourceForTest(be)

	plan := newResourcePlan(t, CDNResourceModel{
		Cname:          types.StringValue("cdn.example.com"),
		OriginGroupID:  types.StringValue("100"),
		Active:         types.BoolValue(true),
		OriginProtocol: types.StringValue("http"),
	})
	resp := resource.CreateResponse{State: emptyResourceState(t)}
	r.Create(ctx, resource.CreateRequest{Plan: plan}, &resp)

	require.False(t, resp.Diagnostics.HasError(), "%v", resp.Diagnostics)
	require.Len(t, be.createReqs, 1)
	got := be.createReqs[0]
	assert.Equal(t, "cdn.example.com", got.Cname)
	assert.Equal(t, int64(100), got.GetOrigin().GetOriginGroupId())
	assert.Equal(t, cdn.OriginProtocol_HTTP, got.OriginProtocol)
	assert.Equal(t, "test-folder", got.FolderId, "folder_id falls back to provider config")

	final := readResourceModel(t, resp.State)
	assert.Equal(t, "res-abc", final.ID.ValueString())
	assert.Equal(t, "cdn.example.com", final.Cname.ValueString())
	assert.Empty(t, be.shieldingActivateReqs, "shielding not specified → not activated")
}

func TestResourceCreate_APIError(t *testing.T) {
	ctx := context.Background()
	be := &fakeResourceBackend{
		createFn: func(_ context.Context, _ *cdn.CreateResourceRequest) (string, error) {
			return "", errors.New("permission denied")
		},
	}
	r := newResourceForTest(be)

	plan := newResourcePlan(t, CDNResourceModel{
		Cname:          types.StringValue("a"),
		OriginGroupID:  types.StringValue("1"),
		Active:         types.BoolValue(true),
		OriginProtocol: types.StringValue("http"),
	})
	resp := resource.CreateResponse{State: emptyResourceState(t)}
	r.Create(ctx, resource.CreateRequest{Plan: plan}, &resp)

	require.True(t, resp.Diagnostics.HasError())
	assert.Empty(t, be.getReqs, "Get must not be called when Create fails")
}

func TestResourceCreate_InvalidOriginGroupIDFormat(t *testing.T) {
	ctx := context.Background()
	be := &fakeResourceBackend{}
	r := newResourceForTest(be)

	plan := newResourcePlan(t, CDNResourceModel{
		Cname:          types.StringValue("a"),
		OriginGroupID:  types.StringValue("not-a-number"),
		Active:         types.BoolValue(true),
		OriginProtocol: types.StringValue("http"),
	})
	resp := resource.CreateResponse{State: emptyResourceState(t)}
	r.Create(ctx, resource.CreateRequest{Plan: plan}, &resp)

	require.True(t, resp.Diagnostics.HasError())
	assert.Empty(t, be.createReqs, "Create must not be called when origin_group_id is malformed")
}

func TestResourceCreate_ResolveOriginGroupByName(t *testing.T) {
	ctx := context.Background()
	be := &fakeResourceBackend{
		originGroupListFn: func(_ context.Context, req *cdn.ListOriginGroupsRequest) ([]*cdn.OriginGroup, error) {
			assert.Equal(t, "test-folder", req.FolderId)
			return []*cdn.OriginGroup{
				{Id: 11, Name: "other"},
				{Id: 22, Name: "wanted"},
			}, nil
		},
		createFn: func(_ context.Context, req *cdn.CreateResourceRequest) (string, error) {
			assert.Equal(t, int64(22), req.GetOrigin().GetOriginGroupId(),
				"name 'wanted' resolves to id 22 (List order match)")
			return "res-named", nil
		},
		getFn: func(_ context.Context, _ *cdn.GetResourceRequest) (*cdn.Resource, error) {
			return cannedResource("res-named", "cdn.example.com", "test-folder", 22, true), nil
		},
	}
	r := newResourceForTest(be)

	plan := newResourcePlan(t, CDNResourceModel{
		Cname:           types.StringValue("cdn.example.com"),
		OriginGroupName: types.StringValue("wanted"),
		Active:          types.BoolValue(true),
		OriginProtocol:  types.StringValue("http"),
	})
	resp := resource.CreateResponse{State: emptyResourceState(t)}
	r.Create(ctx, resource.CreateRequest{Plan: plan}, &resp)

	require.False(t, resp.Diagnostics.HasError(), "%v", resp.Diagnostics)
	require.Len(t, be.originGroupListReqs, 1)
}

func TestResourceCreate_OriginGroupNameNotFound(t *testing.T) {
	ctx := context.Background()
	be := &fakeResourceBackend{
		originGroupListFn: func(_ context.Context, _ *cdn.ListOriginGroupsRequest) ([]*cdn.OriginGroup, error) {
			return []*cdn.OriginGroup{{Id: 11, Name: "other"}}, nil
		},
	}
	r := newResourceForTest(be)

	plan := newResourcePlan(t, CDNResourceModel{
		Cname:           types.StringValue("a"),
		OriginGroupName: types.StringValue("missing"),
		Active:          types.BoolValue(true),
		OriginProtocol:  types.StringValue("http"),
	})
	resp := resource.CreateResponse{State: emptyResourceState(t)}
	r.Create(ctx, resource.CreateRequest{Plan: plan}, &resp)

	require.True(t, resp.Diagnostics.HasError())
	assert.Empty(t, be.createReqs, "Create must not fire when origin_group_name resolution fails")
}

// TestResourceCreate_AppliesShielding pins down that when plan.shielding is
// set, Create issues a follow-up ShieldingActivate against the newly-minted
// resource id.
func TestResourceCreate_AppliesShielding(t *testing.T) {
	ctx := context.Background()
	be := &fakeResourceBackend{
		createFn: func(_ context.Context, _ *cdn.CreateResourceRequest) (string, error) {
			return "res-shielded", nil
		},
		shieldingGetFn: func(_ context.Context, _ *cdn.GetShieldingDetailsRequest) (*cdn.ShieldingDetails, error) {
			return &cdn.ShieldingDetails{LocationId: 42}, nil
		},
		getFn: func(_ context.Context, _ *cdn.GetResourceRequest) (*cdn.Resource, error) {
			return cannedResource("res-shielded", "a", "test-folder", 1, true), nil
		},
	}
	r := newResourceForTest(be)

	plan := newResourcePlan(t, CDNResourceModel{
		Cname:          types.StringValue("a"),
		OriginGroupID:  types.StringValue("1"),
		Active:         types.BoolValue(true),
		OriginProtocol: types.StringValue("http"),
		Shielding:      types.StringValue("42"),
	})
	resp := resource.CreateResponse{State: emptyResourceState(t)}
	r.Create(ctx, resource.CreateRequest{Plan: plan}, &resp)

	require.False(t, resp.Diagnostics.HasError(), "%v", resp.Diagnostics)
	require.Len(t, be.shieldingActivateReqs, 1)
	assert.Equal(t, "res-shielded", be.shieldingActivateReqs[0].ResourceId)
	assert.Equal(t, int64(42), be.shieldingActivateReqs[0].LocationId)
}

// -----------------------------------------------------------------------------
// Read
// -----------------------------------------------------------------------------

func TestResourceRead_Success(t *testing.T) {
	ctx := context.Background()
	be := &fakeResourceBackend{
		getFn: func(_ context.Context, req *cdn.GetResourceRequest) (*cdn.Resource, error) {
			assert.Equal(t, "res-1", req.ResourceId)
			return cannedResource("res-1", "cdn.refreshed", "test-folder", 7, false), nil
		},
	}
	r := newResourceForTest(be)

	state := newResourceState(t, CDNResourceModel{
		ID:    types.StringValue("res-1"),
		Cname: types.StringValue("placeholder"),
	})
	resp := resource.ReadResponse{State: state}
	r.Read(ctx, resource.ReadRequest{State: state}, &resp)

	require.False(t, resp.Diagnostics.HasError(), "%v", resp.Diagnostics)
	got := readResourceModel(t, resp.State)
	assert.Equal(t, "cdn.refreshed", got.Cname.ValueString())
	assert.False(t, got.Active.ValueBool())
}

// TestResourceRead_NotFound_RemovesResource exercises the documented drift path
// for Read: the Get backend returning an error makes readResourceToState
// return false → State.RemoveResource fires.
func TestResourceRead_NotFound_RemovesResource(t *testing.T) {
	ctx := context.Background()
	be := &fakeResourceBackend{
		getFn: func(_ context.Context, _ *cdn.GetResourceRequest) (*cdn.Resource, error) {
			return nil, grpcstatus.Error(codes.NotFound, "gone")
		},
	}
	r := newResourceForTest(be)

	state := newResourceState(t, CDNResourceModel{
		ID:    types.StringValue("res-1"),
		Cname: types.StringValue("x"),
	})
	resp := resource.ReadResponse{State: state}
	r.Read(ctx, resource.ReadRequest{State: state}, &resp)

	require.False(t, resp.Diagnostics.HasError(), "%v", resp.Diagnostics)
	assert.True(t, resp.State.Raw.IsNull(), "state should be cleared after NotFound")
}

// -----------------------------------------------------------------------------
// Update
// -----------------------------------------------------------------------------

func TestResourceUpdate_ActiveFlip(t *testing.T) {
	ctx := context.Background()
	be := &fakeResourceBackend{
		getFn: func(_ context.Context, _ *cdn.GetResourceRequest) (*cdn.Resource, error) {
			return cannedResource("res-1", "a", "test-folder", 1, false), nil
		},
	}
	r := newResourceForTest(be)

	plan := newResourcePlan(t, CDNResourceModel{
		ID:             types.StringValue("res-1"),
		Cname:          types.StringValue("a"),
		OriginGroupID:  types.StringValue("1"),
		Active:         types.BoolValue(false),
		OriginProtocol: types.StringValue("http"),
	})
	state := newResourceState(t, CDNResourceModel{
		ID:             types.StringValue("res-1"),
		Cname:          types.StringValue("a"),
		OriginGroupID:  types.StringValue("1"),
		Active:         types.BoolValue(true),
		OriginProtocol: types.StringValue("http"),
	})

	resp := resource.UpdateResponse{State: state}
	r.Update(ctx, resource.UpdateRequest{Plan: plan, State: state}, &resp)

	require.False(t, resp.Diagnostics.HasError(), "%v", resp.Diagnostics)
	require.Len(t, be.updateReqs, 1)
	require.NotNil(t, be.updateReqs[0].Active)
	assert.False(t, be.updateReqs[0].Active.Value)
}

// TestResourceUpdate_NoChanges_SkipsAPI confirms that an Update with no field
// deltas does not call backend.Update — that would replace ResourceOptions
// unnecessarily under "replace-all" semantics.
func TestResourceUpdate_NoChanges_SkipsAPI(t *testing.T) {
	ctx := context.Background()
	be := &fakeResourceBackend{
		getFn: func(_ context.Context, _ *cdn.GetResourceRequest) (*cdn.Resource, error) {
			return cannedResource("res-1", "a", "test-folder", 1, true), nil
		},
	}
	r := newResourceForTest(be)

	model := CDNResourceModel{
		ID:             types.StringValue("res-1"),
		Cname:          types.StringValue("a"),
		OriginGroupID:  types.StringValue("1"),
		Active:         types.BoolValue(true),
		OriginProtocol: types.StringValue("http"),
	}
	plan := newResourcePlan(t, model)
	state := newResourceState(t, model)

	resp := resource.UpdateResponse{State: state}
	r.Update(ctx, resource.UpdateRequest{Plan: plan, State: state}, &resp)

	require.False(t, resp.Diagnostics.HasError(), "%v", resp.Diagnostics)
	assert.Empty(t, be.updateReqs, "no-op plan must not call Update")
}

func TestResourceUpdate_APIError(t *testing.T) {
	ctx := context.Background()
	be := &fakeResourceBackend{
		updateFn: func(_ context.Context, _ *cdn.UpdateResourceRequest) error {
			return errors.New("conflict")
		},
	}
	r := newResourceForTest(be)

	plan := newResourcePlan(t, CDNResourceModel{
		ID:             types.StringValue("res-1"),
		Cname:          types.StringValue("a"),
		OriginGroupID:  types.StringValue("1"),
		Active:         types.BoolValue(false),
		OriginProtocol: types.StringValue("http"),
	})
	state := newResourceState(t, CDNResourceModel{
		ID:             types.StringValue("res-1"),
		Cname:          types.StringValue("a"),
		OriginGroupID:  types.StringValue("1"),
		Active:         types.BoolValue(true),
		OriginProtocol: types.StringValue("http"),
	})

	resp := resource.UpdateResponse{State: state}
	r.Update(ctx, resource.UpdateRequest{Plan: plan, State: state}, &resp)

	require.True(t, resp.Diagnostics.HasError())
	assert.Empty(t, be.getReqs, "Get must not be called when Update fails")
}

// TestResourceUpdate_EnableShielding verifies the path: plan adds shielding,
// state has none → ShieldingActivate fires with parsed location id.
func TestResourceUpdate_EnableShielding(t *testing.T) {
	ctx := context.Background()
	be := &fakeResourceBackend{
		getFn: func(_ context.Context, _ *cdn.GetResourceRequest) (*cdn.Resource, error) {
			return cannedResource("res-1", "a", "test-folder", 1, true), nil
		},
	}
	r := newResourceForTest(be)

	plan := newResourcePlan(t, CDNResourceModel{
		ID:             types.StringValue("res-1"),
		Cname:          types.StringValue("a"),
		OriginGroupID:  types.StringValue("1"),
		Active:         types.BoolValue(true),
		OriginProtocol: types.StringValue("http"),
		Shielding:      types.StringValue("42"),
	})
	state := newResourceState(t, CDNResourceModel{
		ID:             types.StringValue("res-1"),
		Cname:          types.StringValue("a"),
		OriginGroupID:  types.StringValue("1"),
		Active:         types.BoolValue(true),
		OriginProtocol: types.StringValue("http"),
		Shielding:      types.StringNull(),
	})

	resp := resource.UpdateResponse{State: state}
	r.Update(ctx, resource.UpdateRequest{Plan: plan, State: state}, &resp)

	require.False(t, resp.Diagnostics.HasError(), "%v", resp.Diagnostics)
	require.Len(t, be.shieldingActivateReqs, 1)
	assert.Equal(t, int64(42), be.shieldingActivateReqs[0].LocationId)
	assert.Empty(t, be.shieldingDeactivateReqs)
}

// TestResourceUpdate_DisableShielding_ChecksCurrentFirst verifies the
// guard inside disableShielding: it asks ShieldingGet first, and only
// calls Deactivate when shielding is currently active.
func TestResourceUpdate_DisableShielding_ChecksCurrentFirst(t *testing.T) {
	ctx := context.Background()
	be := &fakeResourceBackend{
		getFn: func(_ context.Context, _ *cdn.GetResourceRequest) (*cdn.Resource, error) {
			return cannedResource("res-1", "a", "test-folder", 1, true), nil
		},
		shieldingGetFn: func(_ context.Context, _ *cdn.GetShieldingDetailsRequest) (*cdn.ShieldingDetails, error) {
			return &cdn.ShieldingDetails{LocationId: 42}, nil
		},
	}
	r := newResourceForTest(be)

	plan := newResourcePlan(t, CDNResourceModel{
		ID:             types.StringValue("res-1"),
		Cname:          types.StringValue("a"),
		OriginGroupID:  types.StringValue("1"),
		Active:         types.BoolValue(true),
		OriginProtocol: types.StringValue("http"),
		Shielding:      types.StringNull(),
	})
	state := newResourceState(t, CDNResourceModel{
		ID:             types.StringValue("res-1"),
		Cname:          types.StringValue("a"),
		OriginGroupID:  types.StringValue("1"),
		Active:         types.BoolValue(true),
		OriginProtocol: types.StringValue("http"),
		Shielding:      types.StringValue("42"),
	})

	resp := resource.UpdateResponse{State: state}
	r.Update(ctx, resource.UpdateRequest{Plan: plan, State: state}, &resp)

	require.False(t, resp.Diagnostics.HasError(), "%v", resp.Diagnostics)
	assert.Empty(t, be.shieldingActivateReqs)
	require.Len(t, be.shieldingDeactivateReqs, 1, "deactivate must fire when shielding is currently on")
}

// TestResourceUpdate_DisableShielding_NoopWhenAlreadyOff verifies the
// short-circuit: if state has shielding set but ShieldingGet says it's
// already off, Deactivate is *not* called.
func TestResourceUpdate_DisableShielding_NoopWhenAlreadyOff(t *testing.T) {
	ctx := context.Background()
	be := &fakeResourceBackend{
		getFn: func(_ context.Context, _ *cdn.GetResourceRequest) (*cdn.Resource, error) {
			return cannedResource("res-1", "a", "test-folder", 1, true), nil
		},
		// default shieldingGetFn returns NotFound → currentShielding is nil → noop.
	}
	r := newResourceForTest(be)

	plan := newResourcePlan(t, CDNResourceModel{
		ID:             types.StringValue("res-1"),
		Cname:          types.StringValue("a"),
		OriginGroupID:  types.StringValue("1"),
		Active:         types.BoolValue(true),
		OriginProtocol: types.StringValue("http"),
		Shielding:      types.StringNull(),
	})
	state := newResourceState(t, CDNResourceModel{
		ID:             types.StringValue("res-1"),
		Cname:          types.StringValue("a"),
		OriginGroupID:  types.StringValue("1"),
		Active:         types.BoolValue(true),
		OriginProtocol: types.StringValue("http"),
		Shielding:      types.StringValue("42"),
	})

	resp := resource.UpdateResponse{State: state}
	r.Update(ctx, resource.UpdateRequest{Plan: plan, State: state}, &resp)

	require.False(t, resp.Diagnostics.HasError(), "%v", resp.Diagnostics)
	assert.Empty(t, be.shieldingDeactivateReqs,
		"deactivate must not fire when shielding is already off")
}

// -----------------------------------------------------------------------------
// Delete
// -----------------------------------------------------------------------------

func TestResourceDelete_Success(t *testing.T) {
	ctx := context.Background()
	be := &fakeResourceBackend{}
	r := newResourceForTest(be)

	state := newResourceState(t, CDNResourceModel{
		ID:    types.StringValue("res-1"),
		Cname: types.StringValue("a"),
	})

	resp := resource.DeleteResponse{State: state}
	r.Delete(ctx, resource.DeleteRequest{State: state}, &resp)

	require.False(t, resp.Diagnostics.HasError(), "%v", resp.Diagnostics)
	require.Len(t, be.deleteReqs, 1)
	assert.Equal(t, "res-1", be.deleteReqs[0].ResourceId)
}

func TestResourceDelete_APIError(t *testing.T) {
	ctx := context.Background()
	be := &fakeResourceBackend{
		deleteFn: func(_ context.Context, _ *cdn.DeleteResourceRequest) error {
			return errors.New("boom")
		},
	}
	r := newResourceForTest(be)

	state := newResourceState(t, CDNResourceModel{
		ID:    types.StringValue("res-1"),
		Cname: types.StringValue("a"),
	})

	resp := resource.DeleteResponse{State: state}
	r.Delete(ctx, resource.DeleteRequest{State: state}, &resp)

	require.True(t, resp.Diagnostics.HasError())
}

// -----------------------------------------------------------------------------
// ImportState
// -----------------------------------------------------------------------------

func TestResourceImportState_PassthroughID(t *testing.T) {
	ctx := context.Background()
	r := newResourceForTest(&fakeResourceBackend{})

	resp := resource.ImportStateResponse{State: emptyResourceState(t)}
	r.ImportState(ctx, resource.ImportStateRequest{ID: "res-xyz"}, &resp)

	require.False(t, resp.Diagnostics.HasError(), "%v", resp.Diagnostics)
	got := readResourceModel(t, resp.State)
	assert.Equal(t, "res-xyz", got.ID.ValueString())
}
