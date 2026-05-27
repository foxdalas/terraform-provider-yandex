package cdn_rule

import (
	"context"
	"errors"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/yandex-cloud/go-genproto/yandex/cloud/cdn/v1"
	"google.golang.org/grpc/codes"
	grpcstatus "google.golang.org/grpc/status"
)

func newDataSourceForTest(b ruleBackend) *cdnRuleDataSource {
	return &cdnRuleDataSource{backend: b}
}

// dsOptionsElemType extracts the element ObjectType the data-source schema
// expects for the `options` block. We have to look it up via the schema (not
// reuse cdn_resource.GetCDNOptionsAttrTypes()) because the data-source variant
// of the options block has a different attribute shape (everything Computed,
// nested blocks vs attributes etc.).
func dsOptionsElemType(t *testing.T) attr.Type {
	t.Helper()
	s := DataSourceCDNRuleSchema()
	listType, ok := s.GetBlocks()["options"].Type().(types.ListType)
	require.True(t, ok, "options block should be a ListType, got %T", s.GetBlocks()["options"].Type())
	return listType.ElemType
}

// fillDSDefaults patches model fields whose zero value the framework rejects
// (typed-null Lists for the options block).
func fillDSDefaults(t *testing.T, m *CDNRuleDataSource) {
	t.Helper()
	if m.Options.IsNull() && !m.Options.IsUnknown() && m.Options.ElementType(context.Background()) == nil {
		m.Options = types.ListNull(dsOptionsElemType(t))
	}
}

func newDSConfig(t *testing.T, m CDNRuleDataSource) tfsdk.Config {
	t.Helper()
	fillDSDefaults(t, &m)
	ctx := context.Background()
	s := DataSourceCDNRuleSchema()
	tmp := tfsdk.State{Schema: s}
	diags := tmp.Set(ctx, &m)
	require.False(t, diags.HasError(), "%v", diags)
	return tfsdk.Config{Raw: tmp.Raw, Schema: s}
}

func newDSState(t *testing.T, m CDNRuleDataSource) tfsdk.State {
	t.Helper()
	fillDSDefaults(t, &m)
	ctx := context.Background()
	s := DataSourceCDNRuleSchema()
	st := tfsdk.State{Schema: s}
	diags := st.Set(ctx, &m)
	require.False(t, diags.HasError(), "%v", diags)
	return st
}

func readDSState(t *testing.T, s tfsdk.State) CDNRuleDataSource {
	t.Helper()
	var m CDNRuleDataSource
	diags := s.Get(context.Background(), &m)
	require.False(t, diags.HasError(), "%v", diags)
	return m
}

func TestDataSource_ReadByRuleID(t *testing.T) {
	ctx := context.Background()
	be := &fakeBackend{
		getFn: func(_ context.Context, req *cdn.GetResourceRuleRequest) (*cdn.Rule, error) {
			assert.Equal(t, "res-1", req.ResourceId)
			assert.Equal(t, int64(7), req.RuleId)
			return cannedRule(7, "named", `^/.*`, 3), nil
		},
	}
	d := newDataSourceForTest(be)

	cfg := newDSConfig(t, CDNRuleDataSource{
		ResourceID: types.StringValue("res-1"),
		RuleID:     types.StringValue("7"),
	})
	resp := datasource.ReadResponse{State: newDSState(t, CDNRuleDataSource{})}
	d.Read(ctx, datasource.ReadRequest{Config: cfg}, &resp)

	require.False(t, resp.Diagnostics.HasError(), "%v", resp.Diagnostics)
	require.Len(t, be.getReqs, 1)
	assert.Empty(t, be.listReqs, "List must not be called when rule_id is supplied")

	got := readDSState(t, resp.State)
	assert.Equal(t, "res-1/7", got.ID.ValueString())
	assert.Equal(t, "7", got.RuleID.ValueString())
	assert.Equal(t, "named", got.Name.ValueString())
	assert.Equal(t, `^/.*`, got.RulePattern.ValueString())
	assert.Equal(t, int64(3), got.Weight.ValueInt64())
}

func TestDataSource_ReadByName_ResolvesViaList(t *testing.T) {
	ctx := context.Background()
	be := &fakeBackend{
		listFn: func(_ context.Context, req *cdn.ListResourceRulesRequest) (*cdn.ListResourceRulesResponse, error) {
			assert.Equal(t, "res-2", req.ResourceId)
			return &cdn.ListResourceRulesResponse{
				Rules: []*cdn.Rule{
					cannedRule(1, "other", `o`, 0),
					cannedRule(42, "wanted", `^/api/.*`, 5),
				},
			}, nil
		},
		getFn: func(_ context.Context, req *cdn.GetResourceRuleRequest) (*cdn.Rule, error) {
			assert.Equal(t, int64(42), req.RuleId)
			return cannedRule(42, "wanted", `^/api/.*`, 5), nil
		},
	}
	d := newDataSourceForTest(be)

	cfg := newDSConfig(t, CDNRuleDataSource{
		ResourceID: types.StringValue("res-2"),
		Name:       types.StringValue("wanted"),
	})
	resp := datasource.ReadResponse{State: newDSState(t, CDNRuleDataSource{})}
	d.Read(ctx, datasource.ReadRequest{Config: cfg}, &resp)

	require.False(t, resp.Diagnostics.HasError(), "%v", resp.Diagnostics)
	require.Len(t, be.listReqs, 1)
	require.Len(t, be.getReqs, 1)
	got := readDSState(t, resp.State)
	assert.Equal(t, "42", got.RuleID.ValueString())
	assert.Equal(t, "wanted", got.Name.ValueString())
}

func TestDataSource_ReadByName_NotFound(t *testing.T) {
	ctx := context.Background()
	be := &fakeBackend{
		listFn: func(_ context.Context, _ *cdn.ListResourceRulesRequest) (*cdn.ListResourceRulesResponse, error) {
			return &cdn.ListResourceRulesResponse{Rules: []*cdn.Rule{cannedRule(1, "other", `o`, 0)}}, nil
		},
	}
	d := newDataSourceForTest(be)

	cfg := newDSConfig(t, CDNRuleDataSource{
		ResourceID: types.StringValue("res-3"),
		Name:       types.StringValue("missing"),
	})
	resp := datasource.ReadResponse{State: newDSState(t, CDNRuleDataSource{})}
	d.Read(ctx, datasource.ReadRequest{Config: cfg}, &resp)

	require.True(t, resp.Diagnostics.HasError())
	assert.Empty(t, be.getReqs)
}

func TestDataSource_ReadByName_ListError(t *testing.T) {
	ctx := context.Background()
	be := &fakeBackend{
		listFn: func(_ context.Context, _ *cdn.ListResourceRulesRequest) (*cdn.ListResourceRulesResponse, error) {
			return nil, errors.New("transient")
		},
	}
	d := newDataSourceForTest(be)

	cfg := newDSConfig(t, CDNRuleDataSource{
		ResourceID: types.StringValue("res-4"),
		Name:       types.StringValue("anything"),
	})
	resp := datasource.ReadResponse{State: newDSState(t, CDNRuleDataSource{})}
	d.Read(ctx, datasource.ReadRequest{Config: cfg}, &resp)

	require.True(t, resp.Diagnostics.HasError())
	assert.Empty(t, be.getReqs)
}

func TestDataSource_RuleIDTakesPrecedence(t *testing.T) {
	ctx := context.Background()
	be := &fakeBackend{
		getFn: func(_ context.Context, req *cdn.GetResourceRuleRequest) (*cdn.Rule, error) {
			assert.Equal(t, int64(42), req.RuleId, "id-based lookup wins; name is ignored")
			return cannedRule(42, "explicit", `.*`, 0), nil
		},
	}
	d := newDataSourceForTest(be)

	cfg := newDSConfig(t, CDNRuleDataSource{
		ResourceID: types.StringValue("res-5"),
		RuleID:     types.StringValue("42"),
		Name:       types.StringValue("ignored"),
	})
	resp := datasource.ReadResponse{State: newDSState(t, CDNRuleDataSource{})}
	d.Read(ctx, datasource.ReadRequest{Config: cfg}, &resp)

	require.False(t, resp.Diagnostics.HasError(), "%v", resp.Diagnostics)
	assert.Empty(t, be.listReqs, "List must not be called when rule_id is provided")
}

func TestDataSource_NeitherRuleIDNorName(t *testing.T) {
	ctx := context.Background()
	be := &fakeBackend{}
	d := newDataSourceForTest(be)

	cfg := newDSConfig(t, CDNRuleDataSource{
		ResourceID: types.StringValue("res-6"),
	})
	resp := datasource.ReadResponse{State: newDSState(t, CDNRuleDataSource{})}
	d.Read(ctx, datasource.ReadRequest{Config: cfg}, &resp)

	require.True(t, resp.Diagnostics.HasError())
	assert.Empty(t, be.getReqs)
	assert.Empty(t, be.listReqs)
}

func TestDataSource_MissingResourceID(t *testing.T) {
	ctx := context.Background()
	be := &fakeBackend{}
	d := newDataSourceForTest(be)

	cfg := newDSConfig(t, CDNRuleDataSource{
		ResourceID: types.StringValue(""),
		RuleID:     types.StringValue("7"),
	})
	resp := datasource.ReadResponse{State: newDSState(t, CDNRuleDataSource{})}
	d.Read(ctx, datasource.ReadRequest{Config: cfg}, &resp)

	require.True(t, resp.Diagnostics.HasError())
	assert.Contains(t, resp.Diagnostics[0].Summary(), "Missing required parameter")
}

func TestDataSource_BadRuleIDFormat(t *testing.T) {
	ctx := context.Background()
	be := &fakeBackend{}
	d := newDataSourceForTest(be)

	cfg := newDSConfig(t, CDNRuleDataSource{
		ResourceID: types.StringValue("res-7"),
		RuleID:     types.StringValue("not-numeric"),
	})
	resp := datasource.ReadResponse{State: newDSState(t, CDNRuleDataSource{})}
	d.Read(ctx, datasource.ReadRequest{Config: cfg}, &resp)

	require.True(t, resp.Diagnostics.HasError())
	assert.Empty(t, be.getReqs)
}

func TestDataSource_GetNotFound(t *testing.T) {
	ctx := context.Background()
	be := &fakeBackend{
		getFn: func(_ context.Context, _ *cdn.GetResourceRuleRequest) (*cdn.Rule, error) {
			return nil, grpcstatus.Error(codes.NotFound, "gone")
		},
	}
	d := newDataSourceForTest(be)

	cfg := newDSConfig(t, CDNRuleDataSource{
		ResourceID: types.StringValue("res-8"),
		RuleID:     types.StringValue("999"),
	})
	resp := datasource.ReadResponse{State: newDSState(t, CDNRuleDataSource{})}
	d.Read(ctx, datasource.ReadRequest{Config: cfg}, &resp)

	require.True(t, resp.Diagnostics.HasError())
	assert.Contains(t, resp.Diagnostics[0].Summary(), "CDN rule not found")
}

func TestDataSource_DuplicateNames_FirstWins(t *testing.T) {
	// API doesn't enforce unique rule names within a resource — document the
	// client-side resolution behavior: first match in List order wins.
	ctx := context.Background()
	be := &fakeBackend{
		listFn: func(_ context.Context, _ *cdn.ListResourceRulesRequest) (*cdn.ListResourceRulesResponse, error) {
			return &cdn.ListResourceRulesResponse{
				Rules: []*cdn.Rule{
					cannedRule(11, "same-name", `a`, 0),
					cannedRule(22, "same-name", `b`, 0),
				},
			}, nil
		},
		getFn: func(_ context.Context, req *cdn.GetResourceRuleRequest) (*cdn.Rule, error) {
			return cannedRule(req.RuleId, "same-name", `a`, 0), nil
		},
	}
	d := newDataSourceForTest(be)

	cfg := newDSConfig(t, CDNRuleDataSource{
		ResourceID: types.StringValue("res-9"),
		Name:       types.StringValue("same-name"),
	})
	resp := datasource.ReadResponse{State: newDSState(t, CDNRuleDataSource{})}
	d.Read(ctx, datasource.ReadRequest{Config: cfg}, &resp)

	require.False(t, resp.Diagnostics.HasError(), "%v", resp.Diagnostics)
	got := readDSState(t, resp.State)
	assert.Equal(t, "11", got.RuleID.ValueString(), "first match in List order wins")
}

func TestDataSource_EmptyList(t *testing.T) {
	ctx := context.Background()
	be := &fakeBackend{
		listFn: func(_ context.Context, _ *cdn.ListResourceRulesRequest) (*cdn.ListResourceRulesResponse, error) {
			return &cdn.ListResourceRulesResponse{}, nil
		},
	}
	d := newDataSourceForTest(be)

	cfg := newDSConfig(t, CDNRuleDataSource{
		ResourceID: types.StringValue("res-10"),
		Name:       types.StringValue("any"),
	})
	resp := datasource.ReadResponse{State: newDSState(t, CDNRuleDataSource{})}
	d.Read(ctx, datasource.ReadRequest{Config: cfg}, &resp)

	require.True(t, resp.Diagnostics.HasError())
	assert.Empty(t, be.getReqs)
}
