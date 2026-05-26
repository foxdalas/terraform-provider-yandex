package cdn_origin_group

import (
	"context"
	"errors"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework-timeouts/resource/timeouts"
	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/yandex-cloud/go-genproto/yandex/cloud/cdn/v1"
	provider_config "github.com/yandex-cloud/terraform-provider-yandex/yandex-framework/provider/config"
	"google.golang.org/grpc/codes"
	grpcstatus "google.golang.org/grpc/status"
)

// nullTimeouts returns a properly-typed empty timeouts.Value. The framework
// requires the ObjectValue inside to carry the right attribute types
// (matching the schema's timeouts block); a zero-value timeouts.Value is
// rejected during Plan/State.Set with a type-conversion error.
func nullTimeouts() timeouts.Value {
	return timeouts.Value{
		Object: types.ObjectNull(map[string]attr.Type{
			"create": types.StringType,
			"update": types.StringType,
			"delete": types.StringType,
		}),
	}
}

// fakeBackend is an in-memory implementation of originGroupBackend for tests.
// Each method can be overridden via the *Fn fields; calls are captured so
// tests can assert request shape.
type fakeBackend struct {
	createFn  func(ctx context.Context, req *cdn.CreateOriginGroupRequest) (int64, error)
	updateFn  func(ctx context.Context, req *cdn.UpdateOriginGroupRequest) error
	deleteFn  func(ctx context.Context, req *cdn.DeleteOriginGroupRequest) error
	getFn     func(ctx context.Context, req *cdn.GetOriginGroupRequest) (*cdn.OriginGroup, error)
	listAllFn func(ctx context.Context, req *cdn.ListOriginGroupsRequest) ([]*cdn.OriginGroup, error)

	createReqs  []*cdn.CreateOriginGroupRequest
	updateReqs  []*cdn.UpdateOriginGroupRequest
	deleteReqs  []*cdn.DeleteOriginGroupRequest
	getReqs     []*cdn.GetOriginGroupRequest
	listAllReqs []*cdn.ListOriginGroupsRequest
}

func (f *fakeBackend) Create(ctx context.Context, req *cdn.CreateOriginGroupRequest) (int64, error) {
	f.createReqs = append(f.createReqs, req)
	if f.createFn != nil {
		return f.createFn(ctx, req)
	}
	return 0, errors.New("createFn not configured")
}

func (f *fakeBackend) Update(ctx context.Context, req *cdn.UpdateOriginGroupRequest) error {
	f.updateReqs = append(f.updateReqs, req)
	if f.updateFn != nil {
		return f.updateFn(ctx, req)
	}
	return nil
}

func (f *fakeBackend) Delete(ctx context.Context, req *cdn.DeleteOriginGroupRequest) error {
	f.deleteReqs = append(f.deleteReqs, req)
	if f.deleteFn != nil {
		return f.deleteFn(ctx, req)
	}
	return nil
}

func (f *fakeBackend) Get(ctx context.Context, req *cdn.GetOriginGroupRequest) (*cdn.OriginGroup, error) {
	f.getReqs = append(f.getReqs, req)
	if f.getFn != nil {
		return f.getFn(ctx, req)
	}
	return nil, errors.New("getFn not configured")
}

func (f *fakeBackend) ListAll(ctx context.Context, req *cdn.ListOriginGroupsRequest) ([]*cdn.OriginGroup, error) {
	f.listAllReqs = append(f.listAllReqs, req)
	if f.listAllFn != nil {
		return f.listAllFn(ctx, req)
	}
	return nil, nil
}

// newResourceForTest wires the resource with a fake backend and a minimal
// providerConfig — folder fallbacks reach into providerConfig.ProviderState,
// so we always supply one to avoid nil-deref crashes.
func newResourceForTest(b originGroupBackend, defaultFolderID string) *cdnOriginGroupResource {
	return &cdnOriginGroupResource{
		backend: b,
		providerConfig: &provider_config.Config{
			ProviderState: provider_config.State{
				FolderID: types.StringValue(defaultFolderID),
			},
		},
	}
}

func originsAttrTypes() map[string]attr.Type {
	return map[string]attr.Type{
		"source":          types.StringType,
		"origin_group_id": types.StringType,
		"enabled":         types.BoolType,
		"backup":          types.BoolType,
	}
}

func buildOriginsList(t *testing.T, origins []OriginModel) types.List {
	t.Helper()
	l, diags := types.ListValueFrom(context.Background(), types.ObjectType{AttrTypes: originsAttrTypes()}, origins)
	require.False(t, diags.HasError(), "ListValueFrom: %v", diags)
	return l
}

// origin builds an OriginModel with the given source and explicit flags.
func origin(source string, enabled, backup bool) OriginModel {
	return OriginModel{
		Source:        types.StringValue(source),
		OriginGroupID: types.StringNull(), // populated by API on response
		Enabled:       types.BoolValue(enabled),
		Backup:        types.BoolValue(backup),
	}
}

func newPlan(t *testing.T, m CDNOriginGroupModel) tfsdk.Plan {
	t.Helper()
	if m.Timeouts.IsNull() && m.Timeouts.IsUnknown() == false && len(m.Timeouts.Attributes()) == 0 {
		m.Timeouts = nullTimeouts()
	}
	ctx := context.Background()
	s := CDNOriginGroupSchema(ctx)
	p := tfsdk.Plan{Schema: s}
	diags := p.Set(ctx, &m)
	require.False(t, diags.HasError(), "plan.Set diagnostics: %v", diags)
	return p
}

func newState(t *testing.T, m CDNOriginGroupModel) tfsdk.State {
	t.Helper()
	if m.Timeouts.IsNull() && m.Timeouts.IsUnknown() == false && len(m.Timeouts.Attributes()) == 0 {
		m.Timeouts = nullTimeouts()
	}
	ctx := context.Background()
	s := CDNOriginGroupSchema(ctx)
	st := tfsdk.State{Schema: s}
	diags := st.Set(ctx, &m)
	require.False(t, diags.HasError(), "state.Set diagnostics: %v", diags)
	return st
}

func emptyState(t *testing.T) tfsdk.State {
	t.Helper()
	return newState(t, CDNOriginGroupModel{
		ID:           types.StringNull(),
		FolderID:     types.StringNull(),
		Name:         types.StringNull(),
		ProviderType: types.StringNull(),
		UseNext:      types.BoolNull(),
		Origins:      types.ListNull(types.ObjectType{AttrTypes: originsAttrTypes()}),
	})
}

func readState(t *testing.T, s tfsdk.State) CDNOriginGroupModel {
	t.Helper()
	var m CDNOriginGroupModel
	diags := s.Get(context.Background(), &m)
	require.False(t, diags.HasError(), "state.Get diagnostics: %v", diags)
	return m
}

// canned origin group payload helpers
func cannedGroup(id int64, name, folder, providerType string, useNext bool, origins []*cdn.Origin) *cdn.OriginGroup {
	return &cdn.OriginGroup{
		Id:           id,
		FolderId:     folder,
		Name:         name,
		ProviderType: providerType,
		UseNext:      useNext,
		Origins:      origins,
	}
}

func cannedOrigin(source string, enabled, backup bool) *cdn.Origin {
	return &cdn.Origin{
		Source:  source,
		Enabled: enabled,
		Backup:  backup,
	}
}

// -----------------------------------------------------------------------------
// Create
// -----------------------------------------------------------------------------

func TestCreate_Success(t *testing.T) {
	ctx := context.Background()
	be := &fakeBackend{
		createFn: func(_ context.Context, _ *cdn.CreateOriginGroupRequest) (int64, error) {
			return 42, nil
		},
		getFn: func(_ context.Context, _ *cdn.GetOriginGroupRequest) (*cdn.OriginGroup, error) {
			return cannedGroup(42, "g1", "fld", "ourcdn", true, []*cdn.Origin{
				cannedOrigin("a.example.com", true, false),
				cannedOrigin("b.example.com", true, true),
			}), nil
		},
	}
	r := newResourceForTest(be, "")

	plan := newPlan(t, CDNOriginGroupModel{
		FolderID:     types.StringValue("fld"),
		Name:         types.StringValue("g1"),
		ProviderType: types.StringValue("ourcdn"),
		UseNext:      types.BoolValue(true),
		Origins: buildOriginsList(t, []OriginModel{
			origin("a.example.com", true, false),
			origin("b.example.com", true, true),
		}),
	})

	resp := resource.CreateResponse{State: emptyState(t)}
	r.Create(ctx, resource.CreateRequest{Plan: plan}, &resp)

	require.False(t, resp.Diagnostics.HasError(), "%v", resp.Diagnostics)
	require.Len(t, be.createReqs, 1)
	got := be.createReqs[0]
	assert.Equal(t, "fld", got.FolderId)
	assert.Equal(t, "g1", got.Name)
	assert.Equal(t, "ourcdn", got.ProviderType)
	require.NotNil(t, got.UseNext)
	assert.True(t, got.UseNext.Value)
	require.Len(t, got.Origins, 2)
	assert.Equal(t, "a.example.com", got.Origins[0].Source)
	assert.Equal(t, "b.example.com", got.Origins[1].Source)
	assert.True(t, got.Origins[1].Backup)

	final := readState(t, resp.State)
	assert.Equal(t, "42", final.ID.ValueString())
	assert.Equal(t, "fld", final.FolderID.ValueString())
	assert.Equal(t, "g1", final.Name.ValueString())
}

func TestCreate_FallsBackToProviderFolder(t *testing.T) {
	ctx := context.Background()
	be := &fakeBackend{
		createFn: func(_ context.Context, _ *cdn.CreateOriginGroupRequest) (int64, error) { return 7, nil },
		getFn: func(_ context.Context, _ *cdn.GetOriginGroupRequest) (*cdn.OriginGroup, error) {
			return cannedGroup(7, "g", "default-folder", "ourcdn", true,
				[]*cdn.Origin{cannedOrigin("x", true, false)}), nil
		},
	}
	r := newResourceForTest(be, "default-folder")

	plan := newPlan(t, CDNOriginGroupModel{
		FolderID: types.StringNull(),
		Name:     types.StringValue("g"),
		UseNext:  types.BoolValue(true),
		Origins: buildOriginsList(t, []OriginModel{
			origin("x", true, false),
		}),
	})

	resp := resource.CreateResponse{State: emptyState(t)}
	r.Create(ctx, resource.CreateRequest{Plan: plan}, &resp)

	require.False(t, resp.Diagnostics.HasError(), "%v", resp.Diagnostics)
	require.Len(t, be.createReqs, 1)
	assert.Equal(t, "default-folder", be.createReqs[0].FolderId,
		"unset model.folder_id should fall back to provider-level folder")
}

func TestCreate_DefaultsProviderTypeToOurcdn(t *testing.T) {
	ctx := context.Background()
	be := &fakeBackend{
		createFn: func(_ context.Context, _ *cdn.CreateOriginGroupRequest) (int64, error) { return 1, nil },
		getFn: func(_ context.Context, _ *cdn.GetOriginGroupRequest) (*cdn.OriginGroup, error) {
			return cannedGroup(1, "g", "fld", "ourcdn", true,
				[]*cdn.Origin{cannedOrigin("x", true, false)}), nil
		},
	}
	r := newResourceForTest(be, "")

	plan := newPlan(t, CDNOriginGroupModel{
		FolderID:     types.StringValue("fld"),
		Name:         types.StringValue("g"),
		ProviderType: types.StringNull(),
		UseNext:      types.BoolValue(true),
		Origins: buildOriginsList(t, []OriginModel{
			origin("x", true, false),
		}),
	})

	resp := resource.CreateResponse{State: emptyState(t)}
	r.Create(ctx, resource.CreateRequest{Plan: plan}, &resp)

	require.False(t, resp.Diagnostics.HasError(), "%v", resp.Diagnostics)
	assert.Equal(t, "ourcdn", be.createReqs[0].ProviderType)
}

func TestCreate_APIError(t *testing.T) {
	ctx := context.Background()
	be := &fakeBackend{
		createFn: func(_ context.Context, _ *cdn.CreateOriginGroupRequest) (int64, error) {
			return 0, errors.New("permission denied")
		},
	}
	r := newResourceForTest(be, "")

	plan := newPlan(t, CDNOriginGroupModel{
		FolderID: types.StringValue("fld"),
		Name:     types.StringValue("g"),
		UseNext:  types.BoolValue(true),
		Origins: buildOriginsList(t, []OriginModel{
			origin("x", true, false),
		}),
	})

	resp := resource.CreateResponse{State: emptyState(t)}
	r.Create(ctx, resource.CreateRequest{Plan: plan}, &resp)

	require.True(t, resp.Diagnostics.HasError())
	assert.Empty(t, be.getReqs, "Get must not be called when Create fails")
}

func TestCreate_MissingFolderID(t *testing.T) {
	ctx := context.Background()
	be := &fakeBackend{}
	// no provider-level fallback either
	r := newResourceForTest(be, "")

	plan := newPlan(t, CDNOriginGroupModel{
		FolderID: types.StringNull(),
		Name:     types.StringValue("g"),
		UseNext:  types.BoolValue(true),
		Origins: buildOriginsList(t, []OriginModel{
			origin("x", true, false),
		}),
	})

	resp := resource.CreateResponse{State: emptyState(t)}
	r.Create(ctx, resource.CreateRequest{Plan: plan}, &resp)

	require.True(t, resp.Diagnostics.HasError())
	assert.Empty(t, be.createReqs, "API should not be called when folder_id is unresolvable")
}

// -----------------------------------------------------------------------------
// Read
// -----------------------------------------------------------------------------

func TestRead_Success(t *testing.T) {
	ctx := context.Background()
	be := &fakeBackend{
		getFn: func(_ context.Context, _ *cdn.GetOriginGroupRequest) (*cdn.OriginGroup, error) {
			return cannedGroup(5, "g", "fld", "gcore", false,
				[]*cdn.Origin{cannedOrigin("x", true, false)}), nil
		},
	}
	r := newResourceForTest(be, "")

	state := newState(t, CDNOriginGroupModel{
		ID:       types.StringValue("5"),
		FolderID: types.StringValue("fld"),
		Name:     types.StringValue("placeholder"),
		UseNext:  types.BoolValue(true),
		Origins: buildOriginsList(t, []OriginModel{
			origin("placeholder", true, false),
		}),
	})
	resp := resource.ReadResponse{State: state}
	r.Read(ctx, resource.ReadRequest{State: state}, &resp)

	require.False(t, resp.Diagnostics.HasError(), "%v", resp.Diagnostics)
	got := readState(t, resp.State)
	assert.Equal(t, "g", got.Name.ValueString())
	assert.Equal(t, "gcore", got.ProviderType.ValueString())
	assert.False(t, got.UseNext.ValueBool())
}

func TestRead_NotFound_RemovesResource(t *testing.T) {
	ctx := context.Background()
	be := &fakeBackend{
		getFn: func(_ context.Context, _ *cdn.GetOriginGroupRequest) (*cdn.OriginGroup, error) {
			return nil, grpcstatus.Error(codes.NotFound, "gone")
		},
	}
	r := newResourceForTest(be, "")

	state := newState(t, CDNOriginGroupModel{
		ID:       types.StringValue("5"),
		FolderID: types.StringValue("fld"),
		Name:     types.StringValue("g"),
		UseNext:  types.BoolValue(true),
		Origins: buildOriginsList(t, []OriginModel{
			origin("x", true, false),
		}),
	})
	resp := resource.ReadResponse{State: state}
	r.Read(ctx, resource.ReadRequest{State: state}, &resp)

	require.False(t, resp.Diagnostics.HasError())
	assert.True(t, resp.State.Raw.IsNull(), "NotFound should clear state")
}

// TestRead_TransientError covers the bug that motivated this refactor:
// the previous implementation wiped state on ANY error, including transport
// errors. After the fix, only NotFound triggers RemoveResource; other errors
// surface a diag and leave state intact.
func TestRead_TransientError_PreservesState(t *testing.T) {
	ctx := context.Background()
	be := &fakeBackend{
		getFn: func(_ context.Context, _ *cdn.GetOriginGroupRequest) (*cdn.OriginGroup, error) {
			return nil, grpcstatus.Error(codes.Internal, "kaboom")
		},
	}
	r := newResourceForTest(be, "")

	original := CDNOriginGroupModel{
		ID:       types.StringValue("5"),
		FolderID: types.StringValue("fld"),
		Name:     types.StringValue("g"),
		UseNext:  types.BoolValue(true),
		Origins: buildOriginsList(t, []OriginModel{
			origin("x", true, false),
		}),
	}
	state := newState(t, original)
	resp := resource.ReadResponse{State: state}
	r.Read(ctx, resource.ReadRequest{State: state}, &resp)

	require.True(t, resp.Diagnostics.HasError())
	assert.False(t, resp.State.Raw.IsNull(), "transient error must NOT wipe state")
	got := readState(t, resp.State)
	assert.Equal(t, "g", got.Name.ValueString(), "state should remain untouched")
}

// -----------------------------------------------------------------------------
// Update
// -----------------------------------------------------------------------------

func TestUpdate_Success(t *testing.T) {
	ctx := context.Background()
	be := &fakeBackend{
		getFn: func(_ context.Context, _ *cdn.GetOriginGroupRequest) (*cdn.OriginGroup, error) {
			return cannedGroup(5, "renamed", "fld", "ourcdn", false,
				[]*cdn.Origin{cannedOrigin("new.example.com", true, false)}), nil
		},
	}
	r := newResourceForTest(be, "")

	plan := newPlan(t, CDNOriginGroupModel{
		ID:       types.StringValue("5"),
		FolderID: types.StringValue("fld"),
		Name:     types.StringValue("renamed"),
		UseNext:  types.BoolValue(false),
		Origins: buildOriginsList(t, []OriginModel{
			origin("new.example.com", true, false),
		}),
	})
	state := newState(t, CDNOriginGroupModel{
		ID:       types.StringValue("5"),
		FolderID: types.StringValue("fld"),
		Name:     types.StringValue("old-name"),
		UseNext:  types.BoolValue(true),
		Origins: buildOriginsList(t, []OriginModel{
			origin("old.example.com", true, false),
		}),
	})

	resp := resource.UpdateResponse{State: state}
	r.Update(ctx, resource.UpdateRequest{Plan: plan, State: state}, &resp)

	require.False(t, resp.Diagnostics.HasError(), "%v", resp.Diagnostics)
	require.Len(t, be.updateReqs, 1)
	got := be.updateReqs[0]
	assert.Equal(t, "fld", got.FolderId)
	assert.Equal(t, int64(5), got.OriginGroupId)
	require.NotNil(t, got.GroupName)
	assert.Equal(t, "renamed", got.GroupName.Value)
	require.NotNil(t, got.UseNext)
	assert.False(t, got.UseNext.Value)
}

func TestUpdate_APIError(t *testing.T) {
	ctx := context.Background()
	be := &fakeBackend{
		updateFn: func(_ context.Context, _ *cdn.UpdateOriginGroupRequest) error {
			return errors.New("conflict")
		},
	}
	r := newResourceForTest(be, "")

	plan := newPlan(t, CDNOriginGroupModel{
		ID:       types.StringValue("5"),
		FolderID: types.StringValue("fld"),
		Name:     types.StringValue("x"),
		UseNext:  types.BoolValue(true),
		Origins: buildOriginsList(t, []OriginModel{origin("a", true, false)}),
	})
	state := newState(t, CDNOriginGroupModel{
		ID:       types.StringValue("5"),
		FolderID: types.StringValue("fld"),
		Name:     types.StringValue("x"),
		UseNext:  types.BoolValue(true),
		Origins: buildOriginsList(t, []OriginModel{origin("a", true, false)}),
	})

	resp := resource.UpdateResponse{State: state}
	r.Update(ctx, resource.UpdateRequest{Plan: plan, State: state}, &resp)

	require.True(t, resp.Diagnostics.HasError())
	assert.Empty(t, be.getReqs, "Get must not be called when Update fails")
}

func TestUpdate_BadID(t *testing.T) {
	ctx := context.Background()
	be := &fakeBackend{}
	r := newResourceForTest(be, "")

	plan := newPlan(t, CDNOriginGroupModel{
		ID:       types.StringValue("not-a-number"),
		FolderID: types.StringValue("fld"),
		Name:     types.StringValue("x"),
		UseNext:  types.BoolValue(true),
		Origins: buildOriginsList(t, []OriginModel{origin("a", true, false)}),
	})
	state := newState(t, CDNOriginGroupModel{
		ID:       types.StringValue("not-a-number"),
		FolderID: types.StringValue("fld"),
		Name:     types.StringValue("x"),
		UseNext:  types.BoolValue(true),
		Origins: buildOriginsList(t, []OriginModel{origin("a", true, false)}),
	})

	resp := resource.UpdateResponse{State: state}
	r.Update(ctx, resource.UpdateRequest{Plan: plan, State: state}, &resp)

	require.True(t, resp.Diagnostics.HasError())
	assert.Empty(t, be.updateReqs)
}

// -----------------------------------------------------------------------------
// Delete
// -----------------------------------------------------------------------------

func TestDelete_Success(t *testing.T) {
	ctx := context.Background()
	be := &fakeBackend{}
	r := newResourceForTest(be, "")

	state := newState(t, CDNOriginGroupModel{
		ID:       types.StringValue("5"),
		FolderID: types.StringValue("fld"),
		Name:     types.StringValue("g"),
		UseNext:  types.BoolValue(true),
		Origins: buildOriginsList(t, []OriginModel{origin("a", true, false)}),
	})

	resp := resource.DeleteResponse{State: state}
	r.Delete(ctx, resource.DeleteRequest{State: state}, &resp)

	require.False(t, resp.Diagnostics.HasError(), "%v", resp.Diagnostics)
	require.Len(t, be.deleteReqs, 1)
	assert.Equal(t, int64(5), be.deleteReqs[0].OriginGroupId)
	assert.Equal(t, "fld", be.deleteReqs[0].FolderId)
}

func TestDelete_NotFound_Swallowed(t *testing.T) {
	ctx := context.Background()
	be := &fakeBackend{
		deleteFn: func(_ context.Context, _ *cdn.DeleteOriginGroupRequest) error {
			return grpcstatus.Error(codes.NotFound, "already gone")
		},
	}
	r := newResourceForTest(be, "")

	state := newState(t, CDNOriginGroupModel{
		ID:       types.StringValue("5"),
		FolderID: types.StringValue("fld"),
		Name:     types.StringValue("g"),
		UseNext:  types.BoolValue(true),
		Origins: buildOriginsList(t, []OriginModel{origin("a", true, false)}),
	})

	resp := resource.DeleteResponse{State: state}
	r.Delete(ctx, resource.DeleteRequest{State: state}, &resp)

	require.False(t, resp.Diagnostics.HasError(),
		"NotFound on Delete should be treated as success; got %v", resp.Diagnostics)
}

func TestDelete_OtherError(t *testing.T) {
	ctx := context.Background()
	be := &fakeBackend{
		deleteFn: func(_ context.Context, _ *cdn.DeleteOriginGroupRequest) error {
			return grpcstatus.Error(codes.Internal, "boom")
		},
	}
	r := newResourceForTest(be, "")

	state := newState(t, CDNOriginGroupModel{
		ID:       types.StringValue("5"),
		FolderID: types.StringValue("fld"),
		Name:     types.StringValue("g"),
		UseNext:  types.BoolValue(true),
		Origins: buildOriginsList(t, []OriginModel{origin("a", true, false)}),
	})

	resp := resource.DeleteResponse{State: state}
	r.Delete(ctx, resource.DeleteRequest{State: state}, &resp)

	require.True(t, resp.Diagnostics.HasError())
}

// -----------------------------------------------------------------------------
// ImportState
// -----------------------------------------------------------------------------

func TestImportState_NumericID(t *testing.T) {
	ctx := context.Background()
	r := newResourceForTest(&fakeBackend{}, "")

	resp := resource.ImportStateResponse{State: emptyState(t)}
	r.ImportState(ctx, resource.ImportStateRequest{ID: "1234567890"}, &resp)

	require.False(t, resp.Diagnostics.HasError(), "%v", resp.Diagnostics)
	var got types.String
	diags := resp.State.GetAttribute(ctx, path.Root("id"), &got)
	require.False(t, diags.HasError(), "%v", diags)
	assert.Equal(t, "1234567890", got.ValueString())
}

func TestImportState_NonNumericIDFails(t *testing.T) {
	ctx := context.Background()
	r := newResourceForTest(&fakeBackend{}, "")

	resp := resource.ImportStateResponse{State: emptyState(t)}
	r.ImportState(ctx, resource.ImportStateRequest{ID: "abc-def"}, &resp)

	require.True(t, resp.Diagnostics.HasError())
	assert.Contains(t, resp.Diagnostics[0].Summary(), "Invalid Import ID")
}

func TestImportState_EmptyIDFails(t *testing.T) {
	ctx := context.Background()
	r := newResourceForTest(&fakeBackend{}, "")

	resp := resource.ImportStateResponse{State: emptyState(t)}
	r.ImportState(ctx, resource.ImportStateRequest{ID: ""}, &resp)

	require.True(t, resp.Diagnostics.HasError())
}

// -----------------------------------------------------------------------------
// Additional Create coverage
// -----------------------------------------------------------------------------

func TestCreate_ProviderTypeGcore(t *testing.T) {
	ctx := context.Background()
	be := &fakeBackend{
		createFn: func(_ context.Context, _ *cdn.CreateOriginGroupRequest) (int64, error) { return 99, nil },
		getFn: func(_ context.Context, _ *cdn.GetOriginGroupRequest) (*cdn.OriginGroup, error) {
			return cannedGroup(99, "g", "fld", "gcore", true,
				[]*cdn.Origin{cannedOrigin("x", true, false)}), nil
		},
	}
	r := newResourceForTest(be, "")

	plan := newPlan(t, CDNOriginGroupModel{
		FolderID:     types.StringValue("fld"),
		Name:         types.StringValue("g"),
		ProviderType: types.StringValue("gcore"),
		UseNext:      types.BoolValue(true),
		Origins:      buildOriginsList(t, []OriginModel{origin("x", true, false)}),
	})
	resp := resource.CreateResponse{State: emptyState(t)}
	r.Create(ctx, resource.CreateRequest{Plan: plan}, &resp)

	require.False(t, resp.Diagnostics.HasError(), "%v", resp.Diagnostics)
	assert.Equal(t, "gcore", be.createReqs[0].ProviderType,
		"explicit provider_type must be passed through verbatim")
}

func TestCreate_SingleOrigin(t *testing.T) {
	ctx := context.Background()
	be := &fakeBackend{
		createFn: func(_ context.Context, _ *cdn.CreateOriginGroupRequest) (int64, error) { return 1, nil },
		getFn: func(_ context.Context, _ *cdn.GetOriginGroupRequest) (*cdn.OriginGroup, error) {
			return cannedGroup(1, "g", "fld", "ourcdn", true,
				[]*cdn.Origin{cannedOrigin("only.example.com", true, false)}), nil
		},
	}
	r := newResourceForTest(be, "")

	plan := newPlan(t, CDNOriginGroupModel{
		FolderID: types.StringValue("fld"),
		Name:     types.StringValue("g"),
		UseNext:  types.BoolValue(true),
		Origins: buildOriginsList(t, []OriginModel{
			origin("only.example.com", true, false),
		}),
	})

	resp := resource.CreateResponse{State: emptyState(t)}
	r.Create(ctx, resource.CreateRequest{Plan: plan}, &resp)

	require.False(t, resp.Diagnostics.HasError(), "%v", resp.Diagnostics)
	require.Len(t, be.createReqs[0].Origins, 1)
}

func TestCreate_MixedOriginFlags(t *testing.T) {
	ctx := context.Background()
	be := &fakeBackend{
		createFn: func(_ context.Context, _ *cdn.CreateOriginGroupRequest) (int64, error) { return 1, nil },
		getFn: func(_ context.Context, _ *cdn.GetOriginGroupRequest) (*cdn.OriginGroup, error) {
			return cannedGroup(1, "g", "fld", "ourcdn", true, []*cdn.Origin{
				cannedOrigin("primary", true, false),
				cannedOrigin("disabled", false, false),
				cannedOrigin("backup-1", true, true),
				cannedOrigin("backup-2", true, true),
			}), nil
		},
	}
	r := newResourceForTest(be, "")

	plan := newPlan(t, CDNOriginGroupModel{
		FolderID: types.StringValue("fld"),
		Name:     types.StringValue("g"),
		UseNext:  types.BoolValue(true),
		Origins: buildOriginsList(t, []OriginModel{
			origin("primary", true, false),
			origin("disabled", false, false),
			origin("backup-1", true, true),
			origin("backup-2", true, true),
		}),
	})

	resp := resource.CreateResponse{State: emptyState(t)}
	r.Create(ctx, resource.CreateRequest{Plan: plan}, &resp)

	require.False(t, resp.Diagnostics.HasError(), "%v", resp.Diagnostics)
	got := be.createReqs[0].Origins
	require.Len(t, got, 4)
	assert.True(t, got[0].Enabled)
	assert.False(t, got[0].Backup)
	assert.False(t, got[1].Enabled)
	assert.True(t, got[2].Enabled)
	assert.True(t, got[2].Backup)
	assert.True(t, got[3].Backup)
}

func TestCreate_GetAfterCreateNotFound_FailsLoudly(t *testing.T) {
	// If the freshly-created group is "not found" on the immediate follow-up
	// Get, something is very wrong — we should surface a clear error rather
	// than silently leaving state empty.
	ctx := context.Background()
	be := &fakeBackend{
		createFn: func(_ context.Context, _ *cdn.CreateOriginGroupRequest) (int64, error) { return 7, nil },
		getFn: func(_ context.Context, _ *cdn.GetOriginGroupRequest) (*cdn.OriginGroup, error) {
			return nil, grpcstatus.Error(codes.NotFound, "vanished")
		},
	}
	r := newResourceForTest(be, "")

	plan := newPlan(t, CDNOriginGroupModel{
		FolderID: types.StringValue("fld"),
		Name:     types.StringValue("g"),
		UseNext:  types.BoolValue(true),
		Origins:  buildOriginsList(t, []OriginModel{origin("x", true, false)}),
	})
	resp := resource.CreateResponse{State: emptyState(t)}
	r.Create(ctx, resource.CreateRequest{Plan: plan}, &resp)

	require.True(t, resp.Diagnostics.HasError())
	assert.Contains(t, resp.Diagnostics[0].Summary(), "disappeared right after create")
}

func TestCreate_GetAfterCreateTransientError(t *testing.T) {
	ctx := context.Background()
	be := &fakeBackend{
		createFn: func(_ context.Context, _ *cdn.CreateOriginGroupRequest) (int64, error) { return 7, nil },
		getFn: func(_ context.Context, _ *cdn.GetOriginGroupRequest) (*cdn.OriginGroup, error) {
			return nil, grpcstatus.Error(codes.Internal, "transient")
		},
	}
	r := newResourceForTest(be, "")

	plan := newPlan(t, CDNOriginGroupModel{
		FolderID: types.StringValue("fld"),
		Name:     types.StringValue("g"),
		UseNext:  types.BoolValue(true),
		Origins:  buildOriginsList(t, []OriginModel{origin("x", true, false)}),
	})
	resp := resource.CreateResponse{State: emptyState(t)}
	r.Create(ctx, resource.CreateRequest{Plan: plan}, &resp)

	require.True(t, resp.Diagnostics.HasError())
	assert.Contains(t, resp.Diagnostics[0].Summary(), "Failed to read CDN origin group after create")
}

// -----------------------------------------------------------------------------
// Additional Read coverage
// -----------------------------------------------------------------------------

func TestRead_FolderFallback(t *testing.T) {
	ctx := context.Background()
	be := &fakeBackend{
		getFn: func(_ context.Context, req *cdn.GetOriginGroupRequest) (*cdn.OriginGroup, error) {
			assert.Equal(t, "default-folder", req.FolderId,
				"state without folder_id should fall back to provider default")
			return cannedGroup(5, "g", "default-folder", "ourcdn", true,
				[]*cdn.Origin{cannedOrigin("x", true, false)}), nil
		},
	}
	r := newResourceForTest(be, "default-folder")

	state := newState(t, CDNOriginGroupModel{
		ID:       types.StringValue("5"),
		FolderID: types.StringNull(),
		Name:     types.StringValue("g"),
		UseNext:  types.BoolValue(true),
		Origins:  buildOriginsList(t, []OriginModel{origin("x", true, false)}),
	})
	resp := resource.ReadResponse{State: state}
	r.Read(ctx, resource.ReadRequest{State: state}, &resp)

	require.False(t, resp.Diagnostics.HasError(), "%v", resp.Diagnostics)
}

func TestRead_NoFolderAnywhere(t *testing.T) {
	ctx := context.Background()
	be := &fakeBackend{}
	r := newResourceForTest(be, "")

	state := newState(t, CDNOriginGroupModel{
		ID:       types.StringValue("5"),
		FolderID: types.StringNull(),
		Name:     types.StringValue("g"),
		UseNext:  types.BoolValue(true),
		Origins:  buildOriginsList(t, []OriginModel{origin("x", true, false)}),
	})
	resp := resource.ReadResponse{State: state}
	r.Read(ctx, resource.ReadRequest{State: state}, &resp)

	require.True(t, resp.Diagnostics.HasError())
	assert.Empty(t, be.getReqs, "no API call should fire when folder_id is unresolvable")
}

func TestRead_BadIDFormat(t *testing.T) {
	ctx := context.Background()
	be := &fakeBackend{}
	r := newResourceForTest(be, "")

	state := newState(t, CDNOriginGroupModel{
		ID:       types.StringValue("not-a-number"),
		FolderID: types.StringValue("fld"),
		Name:     types.StringValue("g"),
		UseNext:  types.BoolValue(true),
		Origins:  buildOriginsList(t, []OriginModel{origin("x", true, false)}),
	})
	resp := resource.ReadResponse{State: state}
	r.Read(ctx, resource.ReadRequest{State: state}, &resp)

	require.True(t, resp.Diagnostics.HasError())
	assert.Empty(t, be.getReqs)
}

func TestRead_PreservesOriginFlags(t *testing.T) {
	ctx := context.Background()
	be := &fakeBackend{
		getFn: func(_ context.Context, _ *cdn.GetOriginGroupRequest) (*cdn.OriginGroup, error) {
			return cannedGroup(5, "g", "fld", "ourcdn", false, []*cdn.Origin{
				cannedOrigin("disabled", false, false),
				cannedOrigin("backup", true, true),
			}), nil
		},
	}
	r := newResourceForTest(be, "")

	state := newState(t, CDNOriginGroupModel{
		ID:       types.StringValue("5"),
		FolderID: types.StringValue("fld"),
		Name:     types.StringValue("placeholder"),
		UseNext:  types.BoolValue(true),
		Origins:  buildOriginsList(t, []OriginModel{origin("placeholder", true, false)}),
	})
	resp := resource.ReadResponse{State: state}
	r.Read(ctx, resource.ReadRequest{State: state}, &resp)

	require.False(t, resp.Diagnostics.HasError(), "%v", resp.Diagnostics)
	got := readState(t, resp.State)
	var origins []OriginModel
	diags := got.Origins.ElementsAs(ctx, &origins, false)
	require.False(t, diags.HasError(), "%v", diags)
	require.Len(t, origins, 2)
	assert.Equal(t, "disabled", origins[0].Source.ValueString())
	assert.False(t, origins[0].Enabled.ValueBool())
	assert.True(t, origins[1].Backup.ValueBool())
}

// -----------------------------------------------------------------------------
// Additional Update coverage
// -----------------------------------------------------------------------------

func TestUpdate_OriginCountChange(t *testing.T) {
	ctx := context.Background()
	be := &fakeBackend{
		getFn: func(_ context.Context, _ *cdn.GetOriginGroupRequest) (*cdn.OriginGroup, error) {
			return cannedGroup(5, "g", "fld", "ourcdn", true, []*cdn.Origin{
				cannedOrigin("a", true, false),
				cannedOrigin("b", true, false),
				cannedOrigin("c", true, false),
			}), nil
		},
	}
	r := newResourceForTest(be, "")

	plan := newPlan(t, CDNOriginGroupModel{
		ID:       types.StringValue("5"),
		FolderID: types.StringValue("fld"),
		Name:     types.StringValue("g"),
		UseNext:  types.BoolValue(true),
		Origins: buildOriginsList(t, []OriginModel{
			origin("a", true, false),
			origin("b", true, false),
			origin("c", true, false),
		}),
	})
	state := newState(t, CDNOriginGroupModel{
		ID:       types.StringValue("5"),
		FolderID: types.StringValue("fld"),
		Name:     types.StringValue("g"),
		UseNext:  types.BoolValue(true),
		Origins:  buildOriginsList(t, []OriginModel{origin("a", true, false)}),
	})

	resp := resource.UpdateResponse{State: state}
	r.Update(ctx, resource.UpdateRequest{Plan: plan, State: state}, &resp)

	require.False(t, resp.Diagnostics.HasError(), "%v", resp.Diagnostics)
	require.Len(t, be.updateReqs, 1)
	require.Len(t, be.updateReqs[0].Origins, 3,
		"Update must send the full new origins list, not a diff")
}

func TestUpdate_GetAfterUpdateNotFound(t *testing.T) {
	ctx := context.Background()
	be := &fakeBackend{
		getFn: func(_ context.Context, _ *cdn.GetOriginGroupRequest) (*cdn.OriginGroup, error) {
			return nil, grpcstatus.Error(codes.NotFound, "vanished")
		},
	}
	r := newResourceForTest(be, "")

	plan := newPlan(t, CDNOriginGroupModel{
		ID:       types.StringValue("5"),
		FolderID: types.StringValue("fld"),
		Name:     types.StringValue("g"),
		UseNext:  types.BoolValue(true),
		Origins:  buildOriginsList(t, []OriginModel{origin("x", true, false)}),
	})
	state := newState(t, CDNOriginGroupModel{
		ID:       types.StringValue("5"),
		FolderID: types.StringValue("fld"),
		Name:     types.StringValue("g"),
		UseNext:  types.BoolValue(true),
		Origins:  buildOriginsList(t, []OriginModel{origin("x", true, false)}),
	})

	resp := resource.UpdateResponse{State: state}
	r.Update(ctx, resource.UpdateRequest{Plan: plan, State: state}, &resp)

	require.True(t, resp.Diagnostics.HasError())
	assert.Contains(t, resp.Diagnostics[0].Summary(), "disappeared right after update")
}

func TestUpdate_GetAfterUpdateTransientError(t *testing.T) {
	ctx := context.Background()
	be := &fakeBackend{
		getFn: func(_ context.Context, _ *cdn.GetOriginGroupRequest) (*cdn.OriginGroup, error) {
			return nil, grpcstatus.Error(codes.Unavailable, "service down")
		},
	}
	r := newResourceForTest(be, "")

	plan := newPlan(t, CDNOriginGroupModel{
		ID:       types.StringValue("5"),
		FolderID: types.StringValue("fld"),
		Name:     types.StringValue("g"),
		UseNext:  types.BoolValue(true),
		Origins:  buildOriginsList(t, []OriginModel{origin("x", true, false)}),
	})
	state := newState(t, CDNOriginGroupModel{
		ID:       types.StringValue("5"),
		FolderID: types.StringValue("fld"),
		Name:     types.StringValue("g"),
		UseNext:  types.BoolValue(true),
		Origins:  buildOriginsList(t, []OriginModel{origin("x", true, false)}),
	})

	resp := resource.UpdateResponse{State: state}
	r.Update(ctx, resource.UpdateRequest{Plan: plan, State: state}, &resp)

	require.True(t, resp.Diagnostics.HasError())
	assert.Contains(t, resp.Diagnostics[0].Summary(), "Failed to read CDN origin group after update")
}

func TestUpdate_FolderFallback(t *testing.T) {
	ctx := context.Background()
	be := &fakeBackend{
		getFn: func(_ context.Context, _ *cdn.GetOriginGroupRequest) (*cdn.OriginGroup, error) {
			return cannedGroup(5, "g", "default-folder", "ourcdn", true,
				[]*cdn.Origin{cannedOrigin("x", true, false)}), nil
		},
	}
	r := newResourceForTest(be, "default-folder")

	plan := newPlan(t, CDNOriginGroupModel{
		ID:       types.StringValue("5"),
		FolderID: types.StringNull(),
		Name:     types.StringValue("g"),
		UseNext:  types.BoolValue(true),
		Origins:  buildOriginsList(t, []OriginModel{origin("x", true, false)}),
	})
	state := newState(t, CDNOriginGroupModel{
		ID:       types.StringValue("5"),
		FolderID: types.StringNull(),
		Name:     types.StringValue("g"),
		UseNext:  types.BoolValue(true),
		Origins:  buildOriginsList(t, []OriginModel{origin("x", true, false)}),
	})

	resp := resource.UpdateResponse{State: state}
	r.Update(ctx, resource.UpdateRequest{Plan: plan, State: state}, &resp)

	require.False(t, resp.Diagnostics.HasError(), "%v", resp.Diagnostics)
	require.Len(t, be.updateReqs, 1)
	assert.Equal(t, "default-folder", be.updateReqs[0].FolderId)
}

// -----------------------------------------------------------------------------
// Additional Delete coverage
// -----------------------------------------------------------------------------

func TestDelete_BadIDFormat(t *testing.T) {
	ctx := context.Background()
	be := &fakeBackend{}
	r := newResourceForTest(be, "")

	state := newState(t, CDNOriginGroupModel{
		ID:       types.StringValue("xyz"),
		FolderID: types.StringValue("fld"),
		Name:     types.StringValue("g"),
		UseNext:  types.BoolValue(true),
		Origins:  buildOriginsList(t, []OriginModel{origin("x", true, false)}),
	})

	resp := resource.DeleteResponse{State: state}
	r.Delete(ctx, resource.DeleteRequest{State: state}, &resp)

	require.True(t, resp.Diagnostics.HasError())
	assert.Empty(t, be.deleteReqs, "API must not be called when state id is malformed")
}

func TestDelete_FolderFallback(t *testing.T) {
	ctx := context.Background()
	be := &fakeBackend{}
	r := newResourceForTest(be, "default-folder")

	state := newState(t, CDNOriginGroupModel{
		ID:       types.StringValue("5"),
		FolderID: types.StringNull(),
		Name:     types.StringValue("g"),
		UseNext:  types.BoolValue(true),
		Origins:  buildOriginsList(t, []OriginModel{origin("x", true, false)}),
	})

	resp := resource.DeleteResponse{State: state}
	r.Delete(ctx, resource.DeleteRequest{State: state}, &resp)

	require.False(t, resp.Diagnostics.HasError(), "%v", resp.Diagnostics)
	require.Len(t, be.deleteReqs, 1)
	assert.Equal(t, "default-folder", be.deleteReqs[0].FolderId)
}
