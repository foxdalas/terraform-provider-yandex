package cdn_origin_group

import (
	"context"
	"errors"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/yandex-cloud/go-genproto/yandex/cloud/cdn/v1"
	provider_config "github.com/yandex-cloud/terraform-provider-yandex/yandex-framework/provider/config"
	"google.golang.org/grpc/codes"
	grpcstatus "google.golang.org/grpc/status"
)

func newDataSourceForTest(b originGroupBackend, defaultFolderID string) *cdnOriginGroupDataSource {
	return &cdnOriginGroupDataSource{
		backend: b,
		providerConfig: &provider_config.Config{
			ProviderState: provider_config.State{
				FolderID: types.StringValue(defaultFolderID),
			},
		},
	}
}

// fillDSDefaults patches model fields whose zero value the framework rejects
// during Plan/State.Set (typed-null Lists, etc.).
func fillDSDefaults(m *CDNOriginGroupDataSource) {
	if m.Origins.IsNull() && m.Origins.IsUnknown() == false && m.Origins.ElementType(context.Background()) == nil {
		m.Origins = types.ListNull(types.ObjectType{AttrTypes: originsAttrTypes()})
	}
}

// newDSConfig builds a tfsdk.Config for the data source. Like in the resource
// tests it routes Go→tftypes conversion through tfsdk.State (which shares the
// same schema/Raw shape).
func newDSConfig(t *testing.T, m CDNOriginGroupDataSource) tfsdk.Config {
	t.Helper()
	fillDSDefaults(&m)
	ctx := context.Background()
	s := DataSourceCDNOriginGroupSchema()
	tmp := tfsdk.State{Schema: s}
	diags := tmp.Set(ctx, &m)
	require.False(t, diags.HasError(), "%v", diags)
	return tfsdk.Config{Raw: tmp.Raw, Schema: s}
}

func newDSState(t *testing.T, m CDNOriginGroupDataSource) tfsdk.State {
	t.Helper()
	fillDSDefaults(&m)
	ctx := context.Background()
	s := DataSourceCDNOriginGroupSchema()
	st := tfsdk.State{Schema: s}
	diags := st.Set(ctx, &m)
	require.False(t, diags.HasError(), "%v", diags)
	return st
}

func readDSState(t *testing.T, s tfsdk.State) CDNOriginGroupDataSource {
	t.Helper()
	var m CDNOriginGroupDataSource
	diags := s.Get(context.Background(), &m)
	require.False(t, diags.HasError(), "%v", diags)
	return m
}

func TestDataSource_ReadByID(t *testing.T) {
	ctx := context.Background()
	be := &fakeBackend{
		getFn: func(_ context.Context, _ *cdn.GetOriginGroupRequest) (*cdn.OriginGroup, error) {
			return cannedGroup(42, "alpha", "fld", "ourcdn", true, []*cdn.Origin{
				cannedOrigin("a.example.com", true, false),
			}), nil
		},
	}
	d := newDataSourceForTest(be, "")

	cfg := newDSConfig(t, CDNOriginGroupDataSource{
		OriginGroupID: types.StringValue("42"),
		FolderID:      types.StringValue("fld"),
	})
	resp := datasource.ReadResponse{State: newDSState(t, CDNOriginGroupDataSource{})}
	d.Read(ctx, datasource.ReadRequest{Config: cfg}, &resp)

	require.False(t, resp.Diagnostics.HasError(), "%v", resp.Diagnostics)
	require.Len(t, be.getReqs, 1)
	assert.Equal(t, int64(42), be.getReqs[0].OriginGroupId)
	assert.Equal(t, "fld", be.getReqs[0].FolderId)
	assert.Empty(t, be.listAllReqs, "ListAll must not be called when origin_group_id is supplied")

	got := readDSState(t, resp.State)
	assert.Equal(t, "42", got.ID.ValueString())
	assert.Equal(t, "42", got.OriginGroupID.ValueString())
	assert.Equal(t, "alpha", got.Name.ValueString())
}

func TestDataSource_ReadByName_ResolvesViaListAll(t *testing.T) {
	ctx := context.Background()
	be := &fakeBackend{
		listAllFn: func(_ context.Context, _ *cdn.ListOriginGroupsRequest) ([]*cdn.OriginGroup, error) {
			return []*cdn.OriginGroup{
				cannedGroup(1, "other", "fld", "ourcdn", true, nil),
				cannedGroup(7, "wanted", "fld", "ourcdn", true,
					[]*cdn.Origin{cannedOrigin("x", true, false)}),
			}, nil
		},
		getFn: func(_ context.Context, req *cdn.GetOriginGroupRequest) (*cdn.OriginGroup, error) {
			require.Equal(t, int64(7), req.OriginGroupId)
			return cannedGroup(7, "wanted", "fld", "ourcdn", true,
				[]*cdn.Origin{cannedOrigin("x", true, false)}), nil
		},
	}
	d := newDataSourceForTest(be, "")

	cfg := newDSConfig(t, CDNOriginGroupDataSource{
		Name:     types.StringValue("wanted"),
		FolderID: types.StringValue("fld"),
	})
	resp := datasource.ReadResponse{State: newDSState(t, CDNOriginGroupDataSource{})}
	d.Read(ctx, datasource.ReadRequest{Config: cfg}, &resp)

	require.False(t, resp.Diagnostics.HasError(), "%v", resp.Diagnostics)
	require.Len(t, be.listAllReqs, 1, "name lookup should hit ListAll once")
	require.Len(t, be.getReqs, 1, "after resolving the id, Get is called once")
	got := readDSState(t, resp.State)
	assert.Equal(t, "7", got.ID.ValueString())
	assert.Equal(t, "wanted", got.Name.ValueString())
}

func TestDataSource_ReadByName_NotFound(t *testing.T) {
	ctx := context.Background()
	be := &fakeBackend{
		listAllFn: func(_ context.Context, _ *cdn.ListOriginGroupsRequest) ([]*cdn.OriginGroup, error) {
			return []*cdn.OriginGroup{cannedGroup(1, "other", "fld", "ourcdn", true, nil)}, nil
		},
	}
	d := newDataSourceForTest(be, "")

	cfg := newDSConfig(t, CDNOriginGroupDataSource{
		Name:     types.StringValue("missing"),
		FolderID: types.StringValue("fld"),
	})
	resp := datasource.ReadResponse{State: newDSState(t, CDNOriginGroupDataSource{})}
	d.Read(ctx, datasource.ReadRequest{Config: cfg}, &resp)

	require.True(t, resp.Diagnostics.HasError(),
		"name not present in folder should surface an error")
	assert.Empty(t, be.getReqs, "Get must not be called when name resolution fails")
}

func TestDataSource_ReadByName_ListError(t *testing.T) {
	ctx := context.Background()
	be := &fakeBackend{
		listAllFn: func(_ context.Context, _ *cdn.ListOriginGroupsRequest) ([]*cdn.OriginGroup, error) {
			return nil, errors.New("network broken")
		},
	}
	d := newDataSourceForTest(be, "")

	cfg := newDSConfig(t, CDNOriginGroupDataSource{
		Name:     types.StringValue("anything"),
		FolderID: types.StringValue("fld"),
	})
	resp := datasource.ReadResponse{State: newDSState(t, CDNOriginGroupDataSource{})}
	d.Read(ctx, datasource.ReadRequest{Config: cfg}, &resp)

	require.True(t, resp.Diagnostics.HasError())
	assert.Empty(t, be.getReqs)
}

func TestDataSource_NeitherIDNorName(t *testing.T) {
	ctx := context.Background()
	be := &fakeBackend{}
	d := newDataSourceForTest(be, "")

	cfg := newDSConfig(t, CDNOriginGroupDataSource{
		FolderID: types.StringValue("fld"),
	})
	resp := datasource.ReadResponse{State: newDSState(t, CDNOriginGroupDataSource{})}
	d.Read(ctx, datasource.ReadRequest{Config: cfg}, &resp)

	require.True(t, resp.Diagnostics.HasError())
	assert.Empty(t, be.getReqs)
	assert.Empty(t, be.listAllReqs)
}

func TestDataSource_FolderFallback(t *testing.T) {
	ctx := context.Background()
	be := &fakeBackend{
		getFn: func(_ context.Context, _ *cdn.GetOriginGroupRequest) (*cdn.OriginGroup, error) {
			return cannedGroup(1, "g", "default-folder", "ourcdn", true,
				[]*cdn.Origin{cannedOrigin("x", true, false)}), nil
		},
	}
	d := newDataSourceForTest(be, "default-folder")

	cfg := newDSConfig(t, CDNOriginGroupDataSource{
		OriginGroupID: types.StringValue("1"),
		FolderID:      types.StringNull(),
	})
	resp := datasource.ReadResponse{State: newDSState(t, CDNOriginGroupDataSource{})}
	d.Read(ctx, datasource.ReadRequest{Config: cfg}, &resp)

	require.False(t, resp.Diagnostics.HasError(), "%v", resp.Diagnostics)
	require.Len(t, be.getReqs, 1)
	assert.Equal(t, "default-folder", be.getReqs[0].FolderId,
		"unset folder_id should fall back to provider default")
}

func TestDataSource_GetNotFound(t *testing.T) {
	ctx := context.Background()
	be := &fakeBackend{
		getFn: func(_ context.Context, _ *cdn.GetOriginGroupRequest) (*cdn.OriginGroup, error) {
			return nil, grpcstatus.Error(codes.NotFound, "gone")
		},
	}
	d := newDataSourceForTest(be, "")

	cfg := newDSConfig(t, CDNOriginGroupDataSource{
		OriginGroupID: types.StringValue("999"),
		FolderID:      types.StringValue("fld"),
	})
	resp := datasource.ReadResponse{State: newDSState(t, CDNOriginGroupDataSource{})}
	d.Read(ctx, datasource.ReadRequest{Config: cfg}, &resp)

	require.True(t, resp.Diagnostics.HasError())
	assert.Contains(t, resp.Diagnostics[0].Summary(), "Origin group not found")
}

func TestDataSource_BadIDFormat(t *testing.T) {
	ctx := context.Background()
	be := &fakeBackend{}
	d := newDataSourceForTest(be, "")

	cfg := newDSConfig(t, CDNOriginGroupDataSource{
		OriginGroupID: types.StringValue("not-numeric"),
		FolderID:      types.StringValue("fld"),
	})
	resp := datasource.ReadResponse{State: newDSState(t, CDNOriginGroupDataSource{})}
	d.Read(ctx, datasource.ReadRequest{Config: cfg}, &resp)

	require.True(t, resp.Diagnostics.HasError())
	assert.Empty(t, be.getReqs)
}

// TestDataSource_IDTakesPrecedence verifies that when both origin_group_id
// AND name are supplied, the id wins and List is never called.
func TestDataSource_IDTakesPrecedence(t *testing.T) {
	ctx := context.Background()
	be := &fakeBackend{
		getFn: func(_ context.Context, req *cdn.GetOriginGroupRequest) (*cdn.OriginGroup, error) {
			assert.Equal(t, int64(42), req.OriginGroupId)
			return cannedGroup(42, "explicit", "fld", "ourcdn", true,
				[]*cdn.Origin{cannedOrigin("x", true, false)}), nil
		},
	}
	d := newDataSourceForTest(be, "")

	cfg := newDSConfig(t, CDNOriginGroupDataSource{
		OriginGroupID: types.StringValue("42"),
		Name:          types.StringValue("ignored"),
		FolderID:      types.StringValue("fld"),
	})
	resp := datasource.ReadResponse{State: newDSState(t, CDNOriginGroupDataSource{})}
	d.Read(ctx, datasource.ReadRequest{Config: cfg}, &resp)

	require.False(t, resp.Diagnostics.HasError(), "%v", resp.Diagnostics)
	assert.Empty(t, be.listAllReqs, "ListAll must not be called when id is provided")
	got := readDSState(t, resp.State)
	assert.Equal(t, "explicit", got.Name.ValueString(),
		"id-based lookup wins; config's name field is overwritten from API")
}

// TestDataSource_ListAll_EmptyFolder is the case where the user searches by
// name but the folder has no origin groups at all.
func TestDataSource_ListAll_EmptyFolder(t *testing.T) {
	ctx := context.Background()
	be := &fakeBackend{
		listAllFn: func(_ context.Context, _ *cdn.ListOriginGroupsRequest) ([]*cdn.OriginGroup, error) {
			return nil, nil
		},
	}
	d := newDataSourceForTest(be, "")

	cfg := newDSConfig(t, CDNOriginGroupDataSource{
		Name:     types.StringValue("anything"),
		FolderID: types.StringValue("fld"),
	})
	resp := datasource.ReadResponse{State: newDSState(t, CDNOriginGroupDataSource{})}
	d.Read(ctx, datasource.ReadRequest{Config: cfg}, &resp)

	require.True(t, resp.Diagnostics.HasError())
	assert.Empty(t, be.getReqs)
}

// TestDataSource_DuplicateNames documents the current behavior: when two
// origin groups share a name the FIRST one returned by ListAll wins.
// The API itself does not enforce name uniqueness in a folder, so this is a
// pure client-side resolution.
func TestDataSource_DuplicateNames_FirstWins(t *testing.T) {
	ctx := context.Background()
	be := &fakeBackend{
		listAllFn: func(_ context.Context, _ *cdn.ListOriginGroupsRequest) ([]*cdn.OriginGroup, error) {
			return []*cdn.OriginGroup{
				cannedGroup(11, "same-name", "fld", "ourcdn", true, nil),
				cannedGroup(22, "same-name", "fld", "ourcdn", true, nil),
			}, nil
		},
		getFn: func(_ context.Context, req *cdn.GetOriginGroupRequest) (*cdn.OriginGroup, error) {
			return cannedGroup(req.OriginGroupId, "same-name", "fld", "ourcdn", true,
				[]*cdn.Origin{cannedOrigin("x", true, false)}), nil
		},
	}
	d := newDataSourceForTest(be, "")

	cfg := newDSConfig(t, CDNOriginGroupDataSource{
		Name:     types.StringValue("same-name"),
		FolderID: types.StringValue("fld"),
	})
	resp := datasource.ReadResponse{State: newDSState(t, CDNOriginGroupDataSource{})}
	d.Read(ctx, datasource.ReadRequest{Config: cfg}, &resp)

	require.False(t, resp.Diagnostics.HasError(), "%v", resp.Diagnostics)
	got := readDSState(t, resp.State)
	assert.Equal(t, "11", got.ID.ValueString(), "first matching name should win")
}

// TestDataSource_FullFieldsExposed walks through every field the data source
// exposes to make sure none are silently dropped on the read path.
func TestDataSource_FullFieldsExposed(t *testing.T) {
	ctx := context.Background()
	be := &fakeBackend{
		getFn: func(_ context.Context, _ *cdn.GetOriginGroupRequest) (*cdn.OriginGroup, error) {
			return cannedGroup(100, "thorough", "fld-xyz", "gcore", false, []*cdn.Origin{
				cannedOrigin("primary.example.com", true, false),
				cannedOrigin("backup.example.com", true, true),
			}), nil
		},
	}
	d := newDataSourceForTest(be, "")

	cfg := newDSConfig(t, CDNOriginGroupDataSource{
		OriginGroupID: types.StringValue("100"),
		FolderID:      types.StringValue("fld-xyz"),
	})
	resp := datasource.ReadResponse{State: newDSState(t, CDNOriginGroupDataSource{})}
	d.Read(ctx, datasource.ReadRequest{Config: cfg}, &resp)

	require.False(t, resp.Diagnostics.HasError(), "%v", resp.Diagnostics)
	got := readDSState(t, resp.State)
	assert.Equal(t, "100", got.ID.ValueString())
	assert.Equal(t, "100", got.OriginGroupID.ValueString())
	assert.Equal(t, "thorough", got.Name.ValueString())
	assert.Equal(t, "fld-xyz", got.FolderID.ValueString())
	assert.Equal(t, "gcore", got.ProviderType.ValueString())
	assert.False(t, got.UseNext.ValueBool())

	var origins []OriginModel
	diags := got.Origins.ElementsAs(ctx, &origins, false)
	require.False(t, diags.HasError(), "%v", diags)
	require.Len(t, origins, 2)
	assert.Equal(t, "100", origins[0].OriginGroupID.ValueString(),
		"parentGroupID should propagate into each flattened origin")
	assert.True(t, origins[1].Backup.ValueBool())
}

// TestDataSource_EmptyProviderType verifies the explicit null branch in
// datasource.go where an empty provider_type from the API maps to a null
// state attribute rather than "". (Same shape difference we saw with raw_log
// BucketRegion.)
func TestDataSource_EmptyProviderType(t *testing.T) {
	ctx := context.Background()
	be := &fakeBackend{
		getFn: func(_ context.Context, _ *cdn.GetOriginGroupRequest) (*cdn.OriginGroup, error) {
			og := cannedGroup(1, "g", "fld", "", true,
				[]*cdn.Origin{cannedOrigin("x", true, false)})
			return og, nil
		},
	}
	d := newDataSourceForTest(be, "")

	cfg := newDSConfig(t, CDNOriginGroupDataSource{
		OriginGroupID: types.StringValue("1"),
		FolderID:      types.StringValue("fld"),
	})
	resp := datasource.ReadResponse{State: newDSState(t, CDNOriginGroupDataSource{})}
	d.Read(ctx, datasource.ReadRequest{Config: cfg}, &resp)

	require.False(t, resp.Diagnostics.HasError(), "%v", resp.Diagnostics)
	got := readDSState(t, resp.State)
	assert.True(t, got.ProviderType.IsNull(),
		"empty provider_type from API should remain null in state")
}
