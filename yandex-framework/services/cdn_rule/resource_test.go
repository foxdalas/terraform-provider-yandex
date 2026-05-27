package cdn_rule

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework-timeouts/resource/timeouts"
	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/yandex-cloud/go-genproto/yandex/cloud/cdn/v1"
	cdn_resource "github.com/yandex-cloud/terraform-provider-yandex/yandex-framework/services/cdn_resource"
	"google.golang.org/grpc/codes"
	grpcstatus "google.golang.org/grpc/status"
)

// fakeBackend is an in-memory implementation of ruleBackend for tests.
type fakeBackend struct {
	createFn func(ctx context.Context, req *cdn.CreateResourceRuleRequest) (int64, error)
	updateFn func(ctx context.Context, req *cdn.UpdateResourceRuleRequest) (int64, error)
	deleteFn func(ctx context.Context, req *cdn.DeleteResourceRuleRequest) error
	getFn    func(ctx context.Context, req *cdn.GetResourceRuleRequest) (*cdn.Rule, error)
	listFn   func(ctx context.Context, req *cdn.ListResourceRulesRequest) (*cdn.ListResourceRulesResponse, error)

	createReqs []*cdn.CreateResourceRuleRequest
	updateReqs []*cdn.UpdateResourceRuleRequest
	deleteReqs []*cdn.DeleteResourceRuleRequest
	getReqs    []*cdn.GetResourceRuleRequest
	listReqs   []*cdn.ListResourceRulesRequest
}

func (f *fakeBackend) Create(ctx context.Context, req *cdn.CreateResourceRuleRequest) (int64, error) {
	f.createReqs = append(f.createReqs, req)
	if f.createFn != nil {
		return f.createFn(ctx, req)
	}
	return 0, errors.New("createFn not configured")
}

func (f *fakeBackend) Update(ctx context.Context, req *cdn.UpdateResourceRuleRequest) (int64, error) {
	f.updateReqs = append(f.updateReqs, req)
	if f.updateFn != nil {
		return f.updateFn(ctx, req)
	}
	// Default: pretend the API returned the same id (no renumber).
	return req.GetRuleId(), nil
}

func (f *fakeBackend) Delete(ctx context.Context, req *cdn.DeleteResourceRuleRequest) error {
	f.deleteReqs = append(f.deleteReqs, req)
	if f.deleteFn != nil {
		return f.deleteFn(ctx, req)
	}
	return nil
}

func (f *fakeBackend) Get(ctx context.Context, req *cdn.GetResourceRuleRequest) (*cdn.Rule, error) {
	f.getReqs = append(f.getReqs, req)
	if f.getFn != nil {
		return f.getFn(ctx, req)
	}
	return nil, errors.New("getFn not configured")
}

func (f *fakeBackend) List(ctx context.Context, req *cdn.ListResourceRulesRequest) (*cdn.ListResourceRulesResponse, error) {
	f.listReqs = append(f.listReqs, req)
	if f.listFn != nil {
		return f.listFn(ctx, req)
	}
	return nil, errors.New("listFn not configured")
}

func newResourceForTest(b ruleBackend) *cdnRuleResource {
	return &cdnRuleResource{backend: b}
}

// nullTimeouts returns a properly-typed empty timeouts.Value matching the
// resource schema's timeouts block (create/update/delete + read).
func nullTimeouts() timeouts.Value {
	return timeouts.Value{
		Object: types.ObjectNull(map[string]attr.Type{
			"create": types.StringType,
			"read":   types.StringType,
			"update": types.StringType,
			"delete": types.StringType,
		}),
	}
}

// nullOptionsList returns a properly-typed null options list (matches the
// schema). Lets newPlan/newState marshal the model without complaining about
// the embedded list element type.
func nullOptionsList() types.List {
	return types.ListNull(types.ObjectType{AttrTypes: cdn_resource.GetCDNOptionsAttrTypes()})
}

func fillResourceDefaults(m *CDNRuleModel) {
	if m.Timeouts.IsNull() && !m.Timeouts.IsUnknown() && len(m.Timeouts.Attributes()) == 0 {
		m.Timeouts = nullTimeouts()
	}
	if m.Options.IsNull() && !m.Options.IsUnknown() && m.Options.ElementType(context.Background()) == nil {
		m.Options = nullOptionsList()
	}
}

func newPlan(t *testing.T, m CDNRuleModel) tfsdk.Plan {
	t.Helper()
	fillResourceDefaults(&m)
	ctx := context.Background()
	s := CDNRuleSchema(ctx)
	p := tfsdk.Plan{Schema: s}
	diags := p.Set(ctx, &m)
	require.False(t, diags.HasError(), "plan.Set diagnostics: %v", diags)
	return p
}

func newState(t *testing.T, m CDNRuleModel) tfsdk.State {
	t.Helper()
	fillResourceDefaults(&m)
	ctx := context.Background()
	s := CDNRuleSchema(ctx)
	st := tfsdk.State{Schema: s}
	diags := st.Set(ctx, &m)
	require.False(t, diags.HasError(), "state.Set diagnostics: %v", diags)
	return st
}

func emptyState(t *testing.T) tfsdk.State {
	t.Helper()
	return newState(t, CDNRuleModel{
		ID:          types.StringNull(),
		ResourceID:  types.StringNull(),
		RuleID:      types.StringNull(),
		Name:        types.StringNull(),
		RulePattern: types.StringNull(),
		Weight:      types.Int64Null(),
		Options:     nullOptionsList(),
	})
}

func readState(t *testing.T, s tfsdk.State) CDNRuleModel {
	t.Helper()
	var m CDNRuleModel
	diags := s.Get(context.Background(), &m)
	require.False(t, diags.HasError(), "state.Get diagnostics: %v", diags)
	return m
}

// cannedRule builds a minimal *cdn.Rule for Get-mock responses.
func cannedRule(id int64, name, pattern string, weight int64) *cdn.Rule {
	return &cdn.Rule{
		Id:          id,
		Name:        name,
		RulePattern: pattern,
		Weight:      weight,
	}
}

// -----------------------------------------------------------------------------
// Create
// -----------------------------------------------------------------------------

func TestCreate_Success(t *testing.T) {
	ctx := context.Background()
	be := &fakeBackend{
		createFn: func(_ context.Context, _ *cdn.CreateResourceRuleRequest) (int64, error) {
			return 123, nil
		},
		getFn: func(_ context.Context, _ *cdn.GetResourceRuleRequest) (*cdn.Rule, error) {
			return cannedRule(123, "r1", `^/api/.*`, 5), nil
		},
	}
	r := newResourceForTest(be)

	plan := newPlan(t, CDNRuleModel{
		ResourceID:  types.StringValue("res-1"),
		Name:        types.StringValue("r1"),
		RulePattern: types.StringValue(`^/api/.*`),
		Weight:      types.Int64Value(5),
	})
	resp := resource.CreateResponse{State: emptyState(t)}
	r.Create(ctx, resource.CreateRequest{Plan: plan}, &resp)

	require.False(t, resp.Diagnostics.HasError(), "%v", resp.Diagnostics)
	require.Len(t, be.createReqs, 1)
	got := be.createReqs[0]
	assert.Equal(t, "res-1", got.ResourceId)
	assert.Equal(t, "r1", got.Name)
	assert.Equal(t, `^/api/.*`, got.RulePattern)
	assert.Equal(t, int64(5), got.Weight)

	final := readState(t, resp.State)
	assert.Equal(t, "res-1/123", final.ID.ValueString(),
		"composite ID should be resource_id/rule_id")
	assert.Equal(t, "123", final.RuleID.ValueString())
	assert.Equal(t, "r1", final.Name.ValueString())
}

func TestCreate_APIError(t *testing.T) {
	ctx := context.Background()
	be := &fakeBackend{
		createFn: func(_ context.Context, _ *cdn.CreateResourceRuleRequest) (int64, error) {
			return 0, errors.New("permission denied")
		},
	}
	r := newResourceForTest(be)

	plan := newPlan(t, CDNRuleModel{
		ResourceID:  types.StringValue("res-2"),
		Name:        types.StringValue("r"),
		RulePattern: types.StringValue(`.*`),
		Weight:      types.Int64Value(0),
	})
	resp := resource.CreateResponse{State: emptyState(t)}
	r.Create(ctx, resource.CreateRequest{Plan: plan}, &resp)

	require.True(t, resp.Diagnostics.HasError())
	assert.Empty(t, be.getReqs, "Get must not be called when Create fails")
}

func TestCreate_GetAfterCreateNotFound_FailsLoudly(t *testing.T) {
	ctx := context.Background()
	be := &fakeBackend{
		createFn: func(_ context.Context, _ *cdn.CreateResourceRuleRequest) (int64, error) { return 7, nil },
		getFn: func(_ context.Context, _ *cdn.GetResourceRuleRequest) (*cdn.Rule, error) {
			return nil, grpcstatus.Error(codes.NotFound, "vanished")
		},
	}
	r := newResourceForTest(be)

	plan := newPlan(t, CDNRuleModel{
		ResourceID:  types.StringValue("res-3"),
		Name:        types.StringValue("r"),
		RulePattern: types.StringValue(`.*`),
		Weight:      types.Int64Value(0),
	})
	resp := resource.CreateResponse{State: emptyState(t)}
	r.Create(ctx, resource.CreateRequest{Plan: plan}, &resp)

	require.True(t, resp.Diagnostics.HasError())
	assert.Contains(t, resp.Diagnostics[0].Summary(), "disappeared right after create")
}

func TestCreate_GetAfterCreateTransientError(t *testing.T) {
	ctx := context.Background()
	be := &fakeBackend{
		createFn: func(_ context.Context, _ *cdn.CreateResourceRuleRequest) (int64, error) { return 7, nil },
		getFn: func(_ context.Context, _ *cdn.GetResourceRuleRequest) (*cdn.Rule, error) {
			return nil, grpcstatus.Error(codes.Internal, "transient")
		},
	}
	r := newResourceForTest(be)

	plan := newPlan(t, CDNRuleModel{
		ResourceID:  types.StringValue("res-3"),
		Name:        types.StringValue("r"),
		RulePattern: types.StringValue(`.*`),
		Weight:      types.Int64Value(0),
	})
	resp := resource.CreateResponse{State: emptyState(t)}
	r.Create(ctx, resource.CreateRequest{Plan: plan}, &resp)

	require.True(t, resp.Diagnostics.HasError())
	assert.Contains(t, resp.Diagnostics[0].Summary(), "Failed to read CDN rule after create")
}

func TestCreate_DefaultWeight(t *testing.T) {
	ctx := context.Background()
	be := &fakeBackend{
		createFn: func(_ context.Context, _ *cdn.CreateResourceRuleRequest) (int64, error) { return 1, nil },
		getFn: func(_ context.Context, _ *cdn.GetResourceRuleRequest) (*cdn.Rule, error) {
			return cannedRule(1, "r", `.*`, 0), nil
		},
	}
	r := newResourceForTest(be)

	plan := newPlan(t, CDNRuleModel{
		ResourceID:  types.StringValue("res-4"),
		Name:        types.StringValue("r"),
		RulePattern: types.StringValue(`.*`),
		Weight:      types.Int64Value(0),
	})
	resp := resource.CreateResponse{State: emptyState(t)}
	r.Create(ctx, resource.CreateRequest{Plan: plan}, &resp)

	require.False(t, resp.Diagnostics.HasError(), "%v", resp.Diagnostics)
	assert.Equal(t, int64(0), be.createReqs[0].Weight)
}

// -----------------------------------------------------------------------------
// Read
// -----------------------------------------------------------------------------

func TestRead_Success(t *testing.T) {
	ctx := context.Background()
	be := &fakeBackend{
		getFn: func(_ context.Context, req *cdn.GetResourceRuleRequest) (*cdn.Rule, error) {
			assert.Equal(t, "res-r", req.ResourceId)
			assert.Equal(t, int64(7), req.RuleId)
			return cannedRule(7, "renamed", `^/v2/.*`, 9), nil
		},
	}
	r := newResourceForTest(be)

	state := newState(t, CDNRuleModel{
		ID:          types.StringValue("res-r/7"),
		ResourceID:  types.StringValue("res-r"),
		RuleID:      types.StringValue("7"),
		Name:        types.StringValue("old"),
		RulePattern: types.StringValue(`old`),
		Weight:      types.Int64Value(0),
	})
	resp := resource.ReadResponse{State: state}
	r.Read(ctx, resource.ReadRequest{State: state}, &resp)

	require.False(t, resp.Diagnostics.HasError(), "%v", resp.Diagnostics)
	got := readState(t, resp.State)
	assert.Equal(t, "renamed", got.Name.ValueString())
	assert.Equal(t, `^/v2/.*`, got.RulePattern.ValueString())
	assert.Equal(t, int64(9), got.Weight.ValueInt64())
}

// TestRead_NotFound_RemovesResource pins down the bug fix: previously, a
// NotFound on Read produced a diag-error rather than clearing state, breaking
// drift detection. Now it clears state.
func TestRead_NotFound_RemovesResource(t *testing.T) {
	ctx := context.Background()
	be := &fakeBackend{
		getFn: func(_ context.Context, _ *cdn.GetResourceRuleRequest) (*cdn.Rule, error) {
			return nil, grpcstatus.Error(codes.NotFound, "gone")
		},
	}
	r := newResourceForTest(be)

	state := newState(t, CDNRuleModel{
		ID:          types.StringValue("res-r/7"),
		ResourceID:  types.StringValue("res-r"),
		RuleID:      types.StringValue("7"),
		Name:        types.StringValue("x"),
		RulePattern: types.StringValue(`.*`),
		Weight:      types.Int64Value(0),
	})
	resp := resource.ReadResponse{State: state}
	r.Read(ctx, resource.ReadRequest{State: state}, &resp)

	require.False(t, resp.Diagnostics.HasError(),
		"NotFound on Read should clear state silently, not error: %v", resp.Diagnostics)
	assert.True(t, resp.State.Raw.IsNull(), "state should be cleared after NotFound")
}

func TestRead_TransientError_PreservesState(t *testing.T) {
	ctx := context.Background()
	be := &fakeBackend{
		getFn: func(_ context.Context, _ *cdn.GetResourceRuleRequest) (*cdn.Rule, error) {
			return nil, grpcstatus.Error(codes.Internal, "kaboom")
		},
	}
	r := newResourceForTest(be)

	state := newState(t, CDNRuleModel{
		ID:          types.StringValue("res-r/7"),
		ResourceID:  types.StringValue("res-r"),
		RuleID:      types.StringValue("7"),
		Name:        types.StringValue("x"),
		RulePattern: types.StringValue(`.*`),
		Weight:      types.Int64Value(0),
	})
	resp := resource.ReadResponse{State: state}
	r.Read(ctx, resource.ReadRequest{State: state}, &resp)

	require.True(t, resp.Diagnostics.HasError())
	assert.False(t, resp.State.Raw.IsNull(), "transient error must NOT wipe state")
}

func TestRead_BadIDFormat(t *testing.T) {
	ctx := context.Background()
	be := &fakeBackend{}
	r := newResourceForTest(be)

	state := newState(t, CDNRuleModel{
		ID:          types.StringValue("malformed-id"),
		ResourceID:  types.StringValue("res-r"),
		RuleID:      types.StringValue("7"),
		Name:        types.StringValue("x"),
		RulePattern: types.StringValue(`.*`),
		Weight:      types.Int64Value(0),
	})
	resp := resource.ReadResponse{State: state}
	r.Read(ctx, resource.ReadRequest{State: state}, &resp)

	require.True(t, resp.Diagnostics.HasError())
	assert.Empty(t, be.getReqs)
}

// -----------------------------------------------------------------------------
// Update
// -----------------------------------------------------------------------------

func TestUpdate_BasicFields(t *testing.T) {
	ctx := context.Background()
	be := &fakeBackend{
		getFn: func(_ context.Context, _ *cdn.GetResourceRuleRequest) (*cdn.Rule, error) {
			return cannedRule(7, "new-name", `new-pat`, 42), nil
		},
	}
	r := newResourceForTest(be)

	plan := newPlan(t, CDNRuleModel{
		ID:          types.StringValue("res-r/7"),
		ResourceID:  types.StringValue("res-r"),
		RuleID:      types.StringValue("7"),
		Name:        types.StringValue("new-name"),
		RulePattern: types.StringValue("new-pat"),
		Weight:      types.Int64Value(42),
	})
	state := newState(t, CDNRuleModel{
		ID:          types.StringValue("res-r/7"),
		ResourceID:  types.StringValue("res-r"),
		RuleID:      types.StringValue("7"),
		Name:        types.StringValue("old"),
		RulePattern: types.StringValue("old"),
		Weight:      types.Int64Value(0),
	})

	resp := resource.UpdateResponse{State: state}
	r.Update(ctx, resource.UpdateRequest{Plan: plan, State: state}, &resp)

	require.False(t, resp.Diagnostics.HasError(), "%v", resp.Diagnostics)
	require.Len(t, be.updateReqs, 1)
	got := be.updateReqs[0]
	assert.Equal(t, "res-r", got.ResourceId)
	assert.Equal(t, int64(7), got.RuleId)
	assert.Equal(t, "new-name", got.Name)
	assert.Equal(t, "new-pat", got.RulePattern)
	require.NotNil(t, got.Weight)
	assert.Equal(t, int64(42), *got.Weight)
}

// TestUpdate_EmptyNameFallsBackToState pins down the gotcha called out in
// resource.go: proto3 doesn't distinguish "unset" from empty string, and the
// API rejects "" with Internal. The resource compensates by falling back to
// state when plan carries empty strings.
func TestUpdate_EmptyNameFallsBackToState(t *testing.T) {
	ctx := context.Background()
	be := &fakeBackend{
		getFn: func(_ context.Context, _ *cdn.GetResourceRuleRequest) (*cdn.Rule, error) {
			return cannedRule(7, "kept", `kept`, 0), nil
		},
	}
	r := newResourceForTest(be)

	plan := newPlan(t, CDNRuleModel{
		ID:          types.StringValue("res-r/7"),
		ResourceID:  types.StringValue("res-r"),
		RuleID:      types.StringValue("7"),
		Name:        types.StringValue(""), // empty in plan
		RulePattern: types.StringValue(""), // empty in plan
		Weight:      types.Int64Value(0),
	})
	state := newState(t, CDNRuleModel{
		ID:          types.StringValue("res-r/7"),
		ResourceID:  types.StringValue("res-r"),
		RuleID:      types.StringValue("7"),
		Name:        types.StringValue("kept"),
		RulePattern: types.StringValue("kept"),
		Weight:      types.Int64Value(0),
	})

	resp := resource.UpdateResponse{State: state}
	r.Update(ctx, resource.UpdateRequest{Plan: plan, State: state}, &resp)

	require.False(t, resp.Diagnostics.HasError(), "%v", resp.Diagnostics)
	got := be.updateReqs[0]
	assert.Equal(t, "kept", got.Name, "empty plan.Name must fall back to state.Name")
	assert.Equal(t, "kept", got.RulePattern, "empty plan.RulePattern must fall back to state.RulePattern")
}

// TestUpdate_NoOptionsChange_SendsNilOptions confirms the optimization: when
// plan.Options equals state.Options, the resource sends nil Options to the API
// (which avoids replacing all option values via the "replace-all" semantics).
func TestUpdate_NoOptionsChange_SendsNilOptions(t *testing.T) {
	ctx := context.Background()
	be := &fakeBackend{
		getFn: func(_ context.Context, _ *cdn.GetResourceRuleRequest) (*cdn.Rule, error) {
			return cannedRule(7, "r", `.*`, 0), nil
		},
	}
	r := newResourceForTest(be)

	// plan and state share the same (null) Options
	plan := newPlan(t, CDNRuleModel{
		ID:          types.StringValue("res-r/7"),
		ResourceID:  types.StringValue("res-r"),
		RuleID:      types.StringValue("7"),
		Name:        types.StringValue("r"),
		RulePattern: types.StringValue(`.*`),
		Weight:      types.Int64Value(0),
	})
	state := newState(t, CDNRuleModel{
		ID:          types.StringValue("res-r/7"),
		ResourceID:  types.StringValue("res-r"),
		RuleID:      types.StringValue("7"),
		Name:        types.StringValue("r"),
		RulePattern: types.StringValue(`.*`),
		Weight:      types.Int64Value(0),
	})

	resp := resource.UpdateResponse{State: state}
	r.Update(ctx, resource.UpdateRequest{Plan: plan, State: state}, &resp)

	require.False(t, resp.Diagnostics.HasError(), "%v", resp.Diagnostics)
	require.Len(t, be.updateReqs, 1)
	assert.Nil(t, be.updateReqs[0].Options,
		"options unchanged in plan vs state should send nil Options (skip replace)")
}

func TestUpdate_APIError(t *testing.T) {
	ctx := context.Background()
	be := &fakeBackend{
		updateFn: func(_ context.Context, _ *cdn.UpdateResourceRuleRequest) (int64, error) {
			return 0, errors.New("conflict")
		},
	}
	r := newResourceForTest(be)

	plan := newPlan(t, CDNRuleModel{
		ID:          types.StringValue("res-r/7"),
		ResourceID:  types.StringValue("res-r"),
		RuleID:      types.StringValue("7"),
		Name:        types.StringValue("r"),
		RulePattern: types.StringValue(`.*`),
		Weight:      types.Int64Value(0),
	})
	state := newState(t, CDNRuleModel{
		ID:          types.StringValue("res-r/7"),
		ResourceID:  types.StringValue("res-r"),
		RuleID:      types.StringValue("7"),
		Name:        types.StringValue("r"),
		RulePattern: types.StringValue(`.*`),
		Weight:      types.Int64Value(0),
	})

	resp := resource.UpdateResponse{State: state}
	r.Update(ctx, resource.UpdateRequest{Plan: plan, State: state}, &resp)

	require.True(t, resp.Diagnostics.HasError())
	assert.Empty(t, be.getReqs, "Get must not be called when Update fails")
}

func TestUpdate_GetAfterUpdateNotFound(t *testing.T) {
	ctx := context.Background()
	be := &fakeBackend{
		getFn: func(_ context.Context, _ *cdn.GetResourceRuleRequest) (*cdn.Rule, error) {
			return nil, grpcstatus.Error(codes.NotFound, "vanished")
		},
	}
	r := newResourceForTest(be)

	plan := newPlan(t, CDNRuleModel{
		ID:          types.StringValue("res-r/7"),
		ResourceID:  types.StringValue("res-r"),
		RuleID:      types.StringValue("7"),
		Name:        types.StringValue("r"),
		RulePattern: types.StringValue(`.*`),
		Weight:      types.Int64Value(0),
	})
	state := newState(t, CDNRuleModel{
		ID:          types.StringValue("res-r/7"),
		ResourceID:  types.StringValue("res-r"),
		RuleID:      types.StringValue("7"),
		Name:        types.StringValue("r"),
		RulePattern: types.StringValue(`.*`),
		Weight:      types.Int64Value(0),
	})

	resp := resource.UpdateResponse{State: state}
	r.Update(ctx, resource.UpdateRequest{Plan: plan, State: state}, &resp)

	require.True(t, resp.Diagnostics.HasError())
	assert.Contains(t, resp.Diagnostics[0].Summary(), "disappeared right after update")
}

// TestUpdate_RenumberFromMetadata pins down the cdn_rule API's "clone with new
// ID" Update semantics: when the API returns a different rule ID in
// UpdateResourceRuleMetadata than the one we asked to update, the resource
// must (a) re-point state.ID/RuleID to the new id and (b) delete the stale
// rule that lingered with the old id.
func TestUpdate_RenumberFromMetadata(t *testing.T) {
	ctx := context.Background()
	be := &fakeBackend{
		updateFn: func(_ context.Context, _ *cdn.UpdateResourceRuleRequest) (int64, error) {
			return 999, nil // API returned a DIFFERENT id
		},
		getFn: func(_ context.Context, req *cdn.GetResourceRuleRequest) (*cdn.Rule, error) {
			assert.Equal(t, int64(999), req.RuleId,
				"post-update Read must target the new id, not the request id")
			return cannedRule(999, "renamed", `.*`, 10), nil
		},
	}
	r := newResourceForTest(be)

	plan := newPlan(t, CDNRuleModel{
		ID:          types.StringValue("res-r/7"),
		ResourceID:  types.StringValue("res-r"),
		RuleID:      types.StringValue("7"),
		Name:        types.StringValue("renamed"),
		RulePattern: types.StringValue(`.*`),
		Weight:      types.Int64Value(10),
	})
	state := newState(t, CDNRuleModel{
		ID:          types.StringValue("res-r/7"),
		ResourceID:  types.StringValue("res-r"),
		RuleID:      types.StringValue("7"),
		Name:        types.StringValue("old"),
		RulePattern: types.StringValue(`.*`),
		Weight:      types.Int64Value(0),
	})

	resp := resource.UpdateResponse{State: state}
	r.Update(ctx, resource.UpdateRequest{Plan: plan, State: state}, &resp)

	require.False(t, resp.Diagnostics.HasError(), "%v", resp.Diagnostics)

	// (a) state has the new composite ID
	got := readState(t, resp.State)
	assert.Equal(t, "res-r/999", got.ID.ValueString(),
		"composite ID must reflect the API's renumbered rule id")
	assert.Equal(t, "999", got.RuleID.ValueString())

	// (b) the stale rule was deleted
	require.Len(t, be.deleteReqs, 1, "cleanup Delete must fire when ID changes")
	assert.Equal(t, int64(7), be.deleteReqs[0].RuleId,
		"cleanup Delete must target the OLD id (7), not the new (999)")
	assert.Equal(t, "res-r", be.deleteReqs[0].ResourceId)
}

// TestUpdate_NoRenumber covers the optimistic case where the API returns the
// same id (in-place update). The resource must NOT issue a cleanup Delete in
// that case — that would wipe the rule we just updated.
func TestUpdate_NoRenumber(t *testing.T) {
	ctx := context.Background()
	be := &fakeBackend{
		updateFn: func(_ context.Context, req *cdn.UpdateResourceRuleRequest) (int64, error) {
			return req.RuleId, nil // same id back
		},
		getFn: func(_ context.Context, _ *cdn.GetResourceRuleRequest) (*cdn.Rule, error) {
			return cannedRule(7, "same", `.*`, 5), nil
		},
	}
	r := newResourceForTest(be)

	plan := newPlan(t, CDNRuleModel{
		ID:          types.StringValue("res-r/7"),
		ResourceID:  types.StringValue("res-r"),
		RuleID:      types.StringValue("7"),
		Name:        types.StringValue("same"),
		RulePattern: types.StringValue(`.*`),
		Weight:      types.Int64Value(5),
	})
	state := newState(t, CDNRuleModel{
		ID:          types.StringValue("res-r/7"),
		ResourceID:  types.StringValue("res-r"),
		RuleID:      types.StringValue("7"),
		Name:        types.StringValue("same"),
		RulePattern: types.StringValue(`.*`),
		Weight:      types.Int64Value(0),
	})

	resp := resource.UpdateResponse{State: state}
	r.Update(ctx, resource.UpdateRequest{Plan: plan, State: state}, &resp)

	require.False(t, resp.Diagnostics.HasError(), "%v", resp.Diagnostics)
	assert.Empty(t, be.deleteReqs,
		"cleanup Delete must NOT fire when API returns the same rule id")
	got := readState(t, resp.State)
	assert.Equal(t, "res-r/7", got.ID.ValueString(), "ID unchanged when no renumber")
}

// TestUpdate_RenumberZeroMetadata covers the defensive fallback: when the API
// or wrapper returns 0 as the new rule id (missing/malformed metadata), the
// resource falls back to the original request id, so behavior degrades to the
// old-style "trust the original id" path rather than crashing or hitting a
// nonsensical /0 composite.
func TestUpdate_RenumberZeroMetadata(t *testing.T) {
	ctx := context.Background()
	be := &fakeBackend{
		updateFn: func(_ context.Context, _ *cdn.UpdateResourceRuleRequest) (int64, error) {
			return 0, nil // zero-value newID, simulates absent metadata
		},
		getFn: func(_ context.Context, req *cdn.GetResourceRuleRequest) (*cdn.Rule, error) {
			assert.Equal(t, int64(7), req.RuleId,
				"with no metadata to renumber, Get should still target the original id")
			return cannedRule(7, "x", `.*`, 0), nil
		},
	}
	r := newResourceForTest(be)

	plan := newPlan(t, CDNRuleModel{
		ID:          types.StringValue("res-r/7"),
		ResourceID:  types.StringValue("res-r"),
		RuleID:      types.StringValue("7"),
		Name:        types.StringValue("x"),
		RulePattern: types.StringValue(`.*`),
		Weight:      types.Int64Value(0),
	})
	state := newState(t, CDNRuleModel{
		ID:          types.StringValue("res-r/7"),
		ResourceID:  types.StringValue("res-r"),
		RuleID:      types.StringValue("7"),
		Name:        types.StringValue("x"),
		RulePattern: types.StringValue(`.*`),
		Weight:      types.Int64Value(0),
	})

	resp := resource.UpdateResponse{State: state}
	r.Update(ctx, resource.UpdateRequest{Plan: plan, State: state}, &resp)

	require.False(t, resp.Diagnostics.HasError(), "%v", resp.Diagnostics)
	assert.Empty(t, be.deleteReqs, "no cleanup when there's no new id to switch to")
	got := readState(t, resp.State)
	assert.Equal(t, "res-r/7", got.ID.ValueString())
}

// TestUpdate_StaleDeleteNotFound_IsSilent — if the old rule has already been
// removed by some other actor between Update and our cleanup Delete, treat
// that as a no-op.
func TestUpdate_StaleDeleteNotFound_IsSilent(t *testing.T) {
	ctx := context.Background()
	be := &fakeBackend{
		updateFn: func(_ context.Context, _ *cdn.UpdateResourceRuleRequest) (int64, error) {
			return 999, nil
		},
		deleteFn: func(_ context.Context, _ *cdn.DeleteResourceRuleRequest) error {
			return grpcstatus.Error(codes.NotFound, "already gone")
		},
		getFn: func(_ context.Context, _ *cdn.GetResourceRuleRequest) (*cdn.Rule, error) {
			return cannedRule(999, "x", `.*`, 0), nil
		},
	}
	r := newResourceForTest(be)

	plan := newPlan(t, CDNRuleModel{
		ID:          types.StringValue("res-r/7"),
		ResourceID:  types.StringValue("res-r"),
		RuleID:      types.StringValue("7"),
		Name:        types.StringValue("x"),
		RulePattern: types.StringValue(`.*`),
		Weight:      types.Int64Value(0),
	})
	state := newState(t, CDNRuleModel{
		ID:          types.StringValue("res-r/7"),
		ResourceID:  types.StringValue("res-r"),
		RuleID:      types.StringValue("7"),
		Name:        types.StringValue("old"),
		RulePattern: types.StringValue(`.*`),
		Weight:      types.Int64Value(0),
	})

	resp := resource.UpdateResponse{State: state}
	r.Update(ctx, resource.UpdateRequest{Plan: plan, State: state}, &resp)

	require.False(t, resp.Diagnostics.HasError(),
		"NotFound during stale cleanup must not be reported; got %v", resp.Diagnostics)
	got := readState(t, resp.State)
	assert.Equal(t, "res-r/999", got.ID.ValueString())
}

// TestUpdate_StaleDeleteOtherError_Warns — cleanup of the stale rule failing
// with a non-NotFound error should not abort the Update (the new rule is
// already correctly in place), but it must surface as a warning so the user
// knows about the leak.
func TestUpdate_StaleDeleteOtherError_Warns(t *testing.T) {
	ctx := context.Background()
	be := &fakeBackend{
		updateFn: func(_ context.Context, _ *cdn.UpdateResourceRuleRequest) (int64, error) {
			return 999, nil
		},
		deleteFn: func(_ context.Context, _ *cdn.DeleteResourceRuleRequest) error {
			return grpcstatus.Error(codes.PermissionDenied, "nope")
		},
		getFn: func(_ context.Context, _ *cdn.GetResourceRuleRequest) (*cdn.Rule, error) {
			return cannedRule(999, "x", `.*`, 0), nil
		},
	}
	r := newResourceForTest(be)

	plan := newPlan(t, CDNRuleModel{
		ID:          types.StringValue("res-r/7"),
		ResourceID:  types.StringValue("res-r"),
		RuleID:      types.StringValue("7"),
		Name:        types.StringValue("x"),
		RulePattern: types.StringValue(`.*`),
		Weight:      types.Int64Value(0),
	})
	state := newState(t, CDNRuleModel{
		ID:          types.StringValue("res-r/7"),
		ResourceID:  types.StringValue("res-r"),
		RuleID:      types.StringValue("7"),
		Name:        types.StringValue("old"),
		RulePattern: types.StringValue(`.*`),
		Weight:      types.Int64Value(0),
	})

	resp := resource.UpdateResponse{State: state}
	r.Update(ctx, resource.UpdateRequest{Plan: plan, State: state}, &resp)

	require.False(t, resp.Diagnostics.HasError(),
		"cleanup failure should NOT be reported as an error (Update itself succeeded); got %v", resp.Diagnostics)
	// We should see a warning diagnostic instead.
	var warned bool
	for _, d := range resp.Diagnostics {
		if d.Severity().String() == "Warning" {
			warned = true
			assert.Contains(t, d.Summary(), "Stale CDN rule could not be deleted")
		}
	}
	assert.True(t, warned, "leaked stale rule must produce a warning diagnostic")
	got := readState(t, resp.State)
	assert.Equal(t, "res-r/999", got.ID.ValueString(),
		"new id is in state even when cleanup failed")
}

func TestUpdate_BadID(t *testing.T) {
	ctx := context.Background()
	be := &fakeBackend{}
	r := newResourceForTest(be)

	plan := newPlan(t, CDNRuleModel{
		ID:          types.StringValue("malformed"),
		ResourceID:  types.StringValue("res-r"),
		RuleID:      types.StringValue("7"),
		Name:        types.StringValue("r"),
		RulePattern: types.StringValue(`.*`),
		Weight:      types.Int64Value(0),
	})
	state := newState(t, CDNRuleModel{
		ID:          types.StringValue("malformed"),
		ResourceID:  types.StringValue("res-r"),
		RuleID:      types.StringValue("7"),
		Name:        types.StringValue("r"),
		RulePattern: types.StringValue(`.*`),
		Weight:      types.Int64Value(0),
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
	r := newResourceForTest(be)

	state := newState(t, CDNRuleModel{
		ID:          types.StringValue("res-r/7"),
		ResourceID:  types.StringValue("res-r"),
		RuleID:      types.StringValue("7"),
		Name:        types.StringValue("r"),
		RulePattern: types.StringValue(`.*`),
		Weight:      types.Int64Value(0),
	})

	resp := resource.DeleteResponse{State: state}
	r.Delete(ctx, resource.DeleteRequest{State: state}, &resp)

	require.False(t, resp.Diagnostics.HasError(), "%v", resp.Diagnostics)
	require.Len(t, be.deleteReqs, 1)
	assert.Equal(t, "res-r", be.deleteReqs[0].ResourceId)
	assert.Equal(t, int64(7), be.deleteReqs[0].RuleId)
}

func TestDelete_NotFound_Swallowed(t *testing.T) {
	ctx := context.Background()
	be := &fakeBackend{
		deleteFn: func(_ context.Context, _ *cdn.DeleteResourceRuleRequest) error {
			return grpcstatus.Error(codes.NotFound, "already gone")
		},
	}
	r := newResourceForTest(be)

	state := newState(t, CDNRuleModel{
		ID:          types.StringValue("res-r/7"),
		ResourceID:  types.StringValue("res-r"),
		RuleID:      types.StringValue("7"),
		Name:        types.StringValue("r"),
		RulePattern: types.StringValue(`.*`),
		Weight:      types.Int64Value(0),
	})

	resp := resource.DeleteResponse{State: state}
	r.Delete(ctx, resource.DeleteRequest{State: state}, &resp)

	require.False(t, resp.Diagnostics.HasError(),
		"NotFound on Delete should be treated as success; got %v", resp.Diagnostics)
}

func TestDelete_OtherError(t *testing.T) {
	ctx := context.Background()
	be := &fakeBackend{
		deleteFn: func(_ context.Context, _ *cdn.DeleteResourceRuleRequest) error {
			return grpcstatus.Error(codes.Internal, "boom")
		},
	}
	r := newResourceForTest(be)

	state := newState(t, CDNRuleModel{
		ID:          types.StringValue("res-r/7"),
		ResourceID:  types.StringValue("res-r"),
		RuleID:      types.StringValue("7"),
		Name:        types.StringValue("r"),
		RulePattern: types.StringValue(`.*`),
		Weight:      types.Int64Value(0),
	})

	resp := resource.DeleteResponse{State: state}
	r.Delete(ctx, resource.DeleteRequest{State: state}, &resp)

	require.True(t, resp.Diagnostics.HasError())
}

func TestDelete_BadIDFormat(t *testing.T) {
	ctx := context.Background()
	be := &fakeBackend{}
	r := newResourceForTest(be)

	state := newState(t, CDNRuleModel{
		ID:          types.StringValue("malformed"),
		ResourceID:  types.StringValue("res-r"),
		RuleID:      types.StringValue("7"),
		Name:        types.StringValue("r"),
		RulePattern: types.StringValue(`.*`),
		Weight:      types.Int64Value(0),
	})

	resp := resource.DeleteResponse{State: state}
	r.Delete(ctx, resource.DeleteRequest{State: state}, &resp)

	require.True(t, resp.Diagnostics.HasError())
	assert.Empty(t, be.deleteReqs)
}

// -----------------------------------------------------------------------------
// ImportState
// -----------------------------------------------------------------------------

func TestImportState_Composite(t *testing.T) {
	ctx := context.Background()
	r := newResourceForTest(&fakeBackend{})

	resp := resource.ImportStateResponse{State: emptyState(t)}
	r.ImportState(ctx, resource.ImportStateRequest{ID: "res-xyz/123"}, &resp)

	require.False(t, resp.Diagnostics.HasError(), "%v", resp.Diagnostics)

	got := readState(t, resp.State)
	assert.Equal(t, "res-xyz/123", got.ID.ValueString())
	assert.Equal(t, "res-xyz", got.ResourceID.ValueString())
	assert.Equal(t, "123", got.RuleID.ValueString())
}

func TestImportState_BadFormat(t *testing.T) {
	ctx := context.Background()
	r := newResourceForTest(&fakeBackend{})

	for _, id := range []string{"", "no-slash", "abc/notanumber", "/123", "res/"} {
		t.Run(id, func(t *testing.T) {
			resp := resource.ImportStateResponse{State: emptyState(t)}
			r.ImportState(ctx, resource.ImportStateRequest{ID: id}, &resp)
			require.True(t, resp.Diagnostics.HasError(), "id %q should be rejected", id)
		})
	}
}

// -----------------------------------------------------------------------------
// parseCDNRuleID (pure helper)
// -----------------------------------------------------------------------------

// TestCreate_AllowedHTTPMethodsPreserved pins down issue [7] from
// CDN_PROVIDER_TEST_ISSUES.md: when the user configures
// allowed_http_methods=["GET","HEAD","OPTIONS"] (which equals the API
// defaults), Read after Create must not silently null the field — that
// trips Terraform's "Provider produced inconsistent result" check and
// marks the rule as tainted.
//
// The fix is in flattenOptions / readRuleInto: the prior plan options are
// threaded into FlattenCDNResourceOptions so isDefaultAllowedHttpMethods's
// fallback to null only fires when the user truly did not configure it.
func TestCreate_AllowedHTTPMethodsPreserved(t *testing.T) {
	ctx := context.Background()

	apiOptions := &cdn.ResourceOptions{
		AllowedHttpMethods: &cdn.ResourceOptions_StringsListOption{
			Enabled: true,
			Value:   []string{"GET", "HEAD", "OPTIONS"},
		},
	}

	// Build a properly-typed plan options list with AllowedHTTPMethods set.
	// Constructing CDNOptionsModel via Go literals leaves nested list/map
	// elem-types missing on zero-value fields and trips ObjectValueFrom's
	// type-validation, so flattenBaseOptionsModel pre-fills every nested
	// container with a typed-null value first.
	base := flattenBaseOptionsModel()
	allowed, listDiags := types.ListValue(types.StringType, []attr.Value{
		types.StringValue("GET"),
		types.StringValue("HEAD"),
		types.StringValue("OPTIONS"),
	})
	require.False(t, listDiags.HasError(), "%v", listDiags)
	base.AllowedHTTPMethods = allowed

	planOptions, planDiags := types.ListValueFrom(ctx, types.ObjectType{
		AttrTypes: cdn_resource.GetCDNOptionsAttrTypes(),
	}, []cdn_resource.CDNOptionsModel{base})
	require.False(t, planDiags.HasError(), "%v", planDiags)

	be := &fakeBackend{
		createFn: func(_ context.Context, _ *cdn.CreateResourceRuleRequest) (int64, error) {
			return 1, nil
		},
		// Server returns exactly the defaults that the user asked for; without
		// the plan-threading fix, flatten would drop these to null.
		getFn: func(_ context.Context, _ *cdn.GetResourceRuleRequest) (*cdn.Rule, error) {
			return &cdn.Rule{
				Id:          1,
				Name:        "r",
				RulePattern: `.*`,
				Options:     apiOptions,
			}, nil
		},
	}
	r := newResourceForTest(be)

	plan := newPlan(t, CDNRuleModel{
		ResourceID:  types.StringValue("res-1"),
		Name:        types.StringValue("r"),
		RulePattern: types.StringValue(`.*`),
		Weight:      types.Int64Value(0),
		Options:     planOptions,
	})
	resp := resource.CreateResponse{State: emptyState(t)}
	r.Create(ctx, resource.CreateRequest{Plan: plan}, &resp)

	require.False(t, resp.Diagnostics.HasError(), "%v", resp.Diagnostics)
	got := readState(t, resp.State)

	require.False(t, got.Options.IsNull(), "options list must not be null after Create")
	var gotModels []cdn_resource.CDNOptionsModel
	require.False(t, got.Options.ElementsAs(ctx, &gotModels, false).HasError())
	require.Len(t, gotModels, 1)
	require.False(t, gotModels[0].AllowedHTTPMethods.IsNull(),
		"allowed_http_methods must survive Create→Read when user asked for the API defaults")

	var methods []string
	require.False(t, gotModels[0].AllowedHTTPMethods.ElementsAs(ctx, &methods, false).HasError())
	assert.ElementsMatch(t, []string{"GET", "HEAD", "OPTIONS"}, methods,
		"allowed_http_methods round-trips through Create→Read intact")
}

// flattenBaseOptionsModel builds a CDNOptionsModel whose every list/map/nested
// field is a typed-null value. Constructing one from scratch with Go literals
// leaves elem-types missing on List/Map zero values and trips
// ObjectValueFrom's type-validation.
func flattenBaseOptionsModel() cdn_resource.CDNOptionsModel {
	strList := types.ListNull(types.StringType)
	strMap := types.MapNull(types.StringType)
	nestedListNull := func(at map[string]attr.Type) types.List {
		return types.ListNull(types.ObjectType{AttrTypes: at})
	}
	return cdn_resource.CDNOptionsModel{
		EdgeCacheSettings:     nestedListNull(cdn_resource.GetEdgeCacheSettingsAttrTypes()),
		BrowserCacheSettings:  nestedListNull(map[string]attr.Type{"enabled": types.BoolType, "cache_time": types.Int64Type}),
		CacheHTTPHeaders:      strList,
		QueryParamsWhitelist:  strList,
		QueryParamsBlacklist:  strList,
		Cors:                  strList,
		AllowedHTTPMethods:    strList,
		Stale:                 strList,
		StaticResponseHeaders: strMap,
		StaticRequestHeaders:  strMap,
		IPAddressACL: nestedListNull(map[string]attr.Type{
			"policy_type":     types.StringType,
			"excepted_values": types.ListType{ElemType: types.StringType},
		}),
		Rewrite: nestedListNull(map[string]attr.Type{
			"enabled": types.BoolType,
			"body":    types.StringType,
			"flag":    types.StringType,
		}),
		BrotliCompression: strList,
		GeoACL:            nestedListNull(cdn_resource.GetGeoACLAttrTypes()),
		ReferrerACL:       nestedListNull(cdn_resource.GetReferrerACLAttrTypes()),
		HeaderFilter:      nestedListNull(cdn_resource.GetHeaderFilterAttrTypes()),
		FollowRedirects:   nestedListNull(cdn_resource.GetFollowRedirectsAttrTypes()),
		StaticResponseOpt: nestedListNull(cdn_resource.GetStaticResponseAttrTypes()),
	}
}

func TestParseCDNRuleID(t *testing.T) {
	cases := []struct {
		in       string
		wantRes  string
		wantRule int64
		ok       bool
	}{
		{"res/1", "res", 1, true},
		{"resource-abc-123/9876543210", "resource-abc-123", 9876543210, true},
		{"", "", 0, false},
		{"resource-only", "", 0, false},
		{"/1", "", 0, false},
		{"res/", "", 0, false},
		{"res/abc", "", 0, false},
		{"a/b/c", "", 0, false},
	}
	for _, tc := range cases {
		t.Run(tc.in, func(t *testing.T) {
			res, rule, err := parseCDNRuleID(tc.in)
			if tc.ok {
				require.NoError(t, err)
				assert.Equal(t, tc.wantRes, res)
				assert.Equal(t, tc.wantRule, rule)
			} else {
				require.Error(t, err)
			}
		})
	}
}

// TestSchema_ForceReplaceOnRuleChanges pins down the intentional schema
// decision around issue [11] in CDN_PROVIDER_TEST_ISSUES.md. The YC API's
// UpdateResourceRule has clone-with-new-id semantics — every "in-place"
// change actually recreates the rule under a new id (see
// TestUpdate_RenumberFromMetadata). Surfacing that as `forces replacement`
// in `terraform plan` is honest; hiding it behind a fake in-place Update
// would still recreate the rule but without warning the operator.
//
// If you find yourself flipping this test, make sure the API has actually
// gained in-place update support — otherwise users will be surprised by
// silent rule id churn.
func TestSchema_ForceReplaceOnRuleChanges(t *testing.T) {
	ctx := context.Background()
	s := CDNRuleSchema(ctx)

	for _, field := range []string{"resource_id", "name", "rule_pattern", "weight"} {
		t.Run(field, func(t *testing.T) {
			attr, ok := s.Attributes[field]
			require.True(t, ok, "attribute %q missing from schema", field)
			require.True(t, attributeHasRequiresReplace(attr),
				"attribute %q must require replacement on change; YC API does not support true in-place updates for rules", field)
		})
	}
}

func attributeHasRequiresReplace(attr schema.Attribute) bool {
	type withStringPM interface {
		StringPlanModifiers() []planmodifier.String
	}
	type withInt64PM interface {
		Int64PlanModifiers() []planmodifier.Int64
	}
	if a, ok := attr.(withStringPM); ok {
		for _, m := range a.StringPlanModifiers() {
			if isStringRequiresReplace(m) {
				return true
			}
		}
	}
	if a, ok := attr.(withInt64PM); ok {
		for _, m := range a.Int64PlanModifiers() {
			if isInt64RequiresReplace(m) {
				return true
			}
		}
	}
	return false
}

// All requires-replace modifiers in plugin-framework describe themselves as
// "...destroy and recreate the resource." There is no public API to distinguish
// requires-replace from any other plan modifier, so we match on the description.

func isStringRequiresReplace(m planmodifier.String) bool {
	return strings.Contains(strings.ToLower(m.Description(context.Background())), "destroy and recreate")
}

func isInt64RequiresReplace(m planmodifier.Int64) bool {
	return strings.Contains(strings.ToLower(m.Description(context.Background())), "destroy and recreate")
}
