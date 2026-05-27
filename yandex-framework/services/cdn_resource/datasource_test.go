package cdn_resource

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
	"github.com/yandex-cloud/terraform-provider-yandex/yandex-framework/provider/config"
	"google.golang.org/grpc/codes"
	grpcstatus "google.golang.org/grpc/status"
)

func newDataSourceForTest(b resourceBackend) *cdnResourceDataSource {
	return &cdnResourceDataSource{
		backend: b,
		providerConfig: &config.Config{
			ProviderState: config.State{
				FolderID: types.StringValue("test-folder"),
			},
		},
	}
}

// dsBlockElemType extracts the element ObjectType for a ListNestedBlock from
// the data-source schema. We have to look it up via the schema (not reuse
// resource attr-type helpers) because the data-source variants have everything
// Computed and a different attribute shape.
func dsBlockElemType(t *testing.T, name string) attr.Type {
	t.Helper()
	s := DataSourceCDNResourceSchema()
	listType, ok := s.GetBlocks()[name].Type().(types.ListType)
	require.True(t, ok, "%s block should be a ListType, got %T", name, s.GetBlocks()[name].Type())
	return listType.ElemType
}

func fillDSResourceDefaults(t *testing.T, m *CDNResourceDataSource) {
	t.Helper()
	ctx := context.Background()
	if m.Options.IsNull() && !m.Options.IsUnknown() && m.Options.ElementType(ctx) == nil {
		m.Options = types.ListNull(dsBlockElemType(t, "options"))
	}
	if m.SSLCertificate.IsNull() && !m.SSLCertificate.IsUnknown() && m.SSLCertificate.ElementType(ctx) == nil {
		m.SSLCertificate = types.ListNull(dsBlockElemType(t, "ssl_certificate"))
	}
	if m.Labels.IsNull() && !m.Labels.IsUnknown() && m.Labels.ElementType(ctx) == nil {
		m.Labels = types.MapNull(types.StringType)
	}
	if m.SecondaryHostnames.IsNull() && !m.SecondaryHostnames.IsUnknown() && m.SecondaryHostnames.ElementType(ctx) == nil {
		m.SecondaryHostnames = types.SetNull(types.StringType)
	}
}

func newDSResourceConfig(t *testing.T, m CDNResourceDataSource) tfsdk.Config {
	t.Helper()
	fillDSResourceDefaults(t, &m)
	ctx := context.Background()
	s := DataSourceCDNResourceSchema()
	tmp := tfsdk.State{Schema: s}
	diags := tmp.Set(ctx, &m)
	require.False(t, diags.HasError(), "%v", diags)
	return tfsdk.Config{Raw: tmp.Raw, Schema: s}
}

func newDSResourceState(t *testing.T, m CDNResourceDataSource) tfsdk.State {
	t.Helper()
	fillDSResourceDefaults(t, &m)
	ctx := context.Background()
	s := DataSourceCDNResourceSchema()
	st := tfsdk.State{Schema: s}
	diags := st.Set(ctx, &m)
	require.False(t, diags.HasError(), "%v", diags)
	return st
}

func readDSResourceState(t *testing.T, s tfsdk.State) CDNResourceDataSource {
	t.Helper()
	var m CDNResourceDataSource
	diags := s.Get(context.Background(), &m)
	require.False(t, diags.HasError(), "%v", diags)
	return m
}

func TestResourceDataSource_ReadByResourceID(t *testing.T) {
	ctx := context.Background()
	be := &fakeResourceBackend{
		getFn: func(_ context.Context, req *cdn.GetResourceRequest) (*cdn.Resource, error) {
			assert.Equal(t, "res-1", req.ResourceId)
			return cannedResource("res-1", "cdn.example.com", "test-folder", 100, true), nil
		},
	}
	d := newDataSourceForTest(be)

	cfg := newDSResourceConfig(t, CDNResourceDataSource{
		ResourceID: types.StringValue("res-1"),
	})
	resp := datasource.ReadResponse{State: newDSResourceState(t, CDNResourceDataSource{})}
	d.Read(ctx, datasource.ReadRequest{Config: cfg}, &resp)

	require.False(t, resp.Diagnostics.HasError(), "%v", resp.Diagnostics)
	require.Len(t, be.getReqs, 1)
	assert.Empty(t, be.listReqs, "List must not be called when resource_id is supplied")

	got := readDSResourceState(t, resp.State)
	assert.Equal(t, "res-1", got.ID.ValueString())
	assert.Equal(t, "res-1", got.ResourceID.ValueString())
	assert.Equal(t, "cdn.example.com", got.Cname.ValueString())
}

func TestResourceDataSource_ReadByCname_ResolvesViaList(t *testing.T) {
	ctx := context.Background()
	be := &fakeResourceBackend{
		listFn: func(_ context.Context, req *cdn.ListResourcesRequest) ([]*cdn.Resource, error) {
			assert.Equal(t, "test-folder", req.FolderId)
			return []*cdn.Resource{
				cannedResource("res-other", "other.example.com", "test-folder", 1, true),
				cannedResource("res-wanted", "wanted.example.com", "test-folder", 2, true),
			}, nil
		},
		getFn: func(_ context.Context, req *cdn.GetResourceRequest) (*cdn.Resource, error) {
			assert.Equal(t, "res-wanted", req.ResourceId)
			return cannedResource("res-wanted", "wanted.example.com", "test-folder", 2, true), nil
		},
	}
	d := newDataSourceForTest(be)

	cfg := newDSResourceConfig(t, CDNResourceDataSource{
		Cname: types.StringValue("wanted.example.com"),
	})
	resp := datasource.ReadResponse{State: newDSResourceState(t, CDNResourceDataSource{})}
	d.Read(ctx, datasource.ReadRequest{Config: cfg}, &resp)

	require.False(t, resp.Diagnostics.HasError(), "%v", resp.Diagnostics)
	require.Len(t, be.listReqs, 1)
	require.Len(t, be.getReqs, 1)
	got := readDSResourceState(t, resp.State)
	assert.Equal(t, "res-wanted", got.ResourceID.ValueString())
}

func TestResourceDataSource_ReadByCname_NotFound(t *testing.T) {
	ctx := context.Background()
	be := &fakeResourceBackend{
		listFn: func(_ context.Context, _ *cdn.ListResourcesRequest) ([]*cdn.Resource, error) {
			return []*cdn.Resource{cannedResource("res-other", "other.example.com", "test-folder", 1, true)}, nil
		},
	}
	d := newDataSourceForTest(be)

	cfg := newDSResourceConfig(t, CDNResourceDataSource{
		Cname: types.StringValue("missing.example.com"),
	})
	resp := datasource.ReadResponse{State: newDSResourceState(t, CDNResourceDataSource{})}
	d.Read(ctx, datasource.ReadRequest{Config: cfg}, &resp)

	require.True(t, resp.Diagnostics.HasError())
	assert.Empty(t, be.getReqs)
}

func TestResourceDataSource_ReadByCname_ListError(t *testing.T) {
	ctx := context.Background()
	be := &fakeResourceBackend{
		listFn: func(_ context.Context, _ *cdn.ListResourcesRequest) ([]*cdn.Resource, error) {
			return nil, errors.New("transient")
		},
	}
	d := newDataSourceForTest(be)

	cfg := newDSResourceConfig(t, CDNResourceDataSource{
		Cname: types.StringValue("any.example.com"),
	})
	resp := datasource.ReadResponse{State: newDSResourceState(t, CDNResourceDataSource{})}
	d.Read(ctx, datasource.ReadRequest{Config: cfg}, &resp)

	require.True(t, resp.Diagnostics.HasError())
	assert.Empty(t, be.getReqs)
}

func TestResourceDataSource_ResourceIDTakesPrecedence(t *testing.T) {
	ctx := context.Background()
	be := &fakeResourceBackend{
		getFn: func(_ context.Context, req *cdn.GetResourceRequest) (*cdn.Resource, error) {
			assert.Equal(t, "res-explicit", req.ResourceId,
				"resource_id-based lookup wins; cname is ignored")
			return cannedResource("res-explicit", "explicit.example.com", "test-folder", 1, true), nil
		},
	}
	d := newDataSourceForTest(be)

	cfg := newDSResourceConfig(t, CDNResourceDataSource{
		ResourceID: types.StringValue("res-explicit"),
		Cname:      types.StringValue("ignored"),
	})
	resp := datasource.ReadResponse{State: newDSResourceState(t, CDNResourceDataSource{})}
	d.Read(ctx, datasource.ReadRequest{Config: cfg}, &resp)

	require.False(t, resp.Diagnostics.HasError(), "%v", resp.Diagnostics)
	assert.Empty(t, be.listReqs, "List must not be called when resource_id is provided")
}

func TestResourceDataSource_NeitherResourceIDNorCname(t *testing.T) {
	ctx := context.Background()
	be := &fakeResourceBackend{}
	d := newDataSourceForTest(be)

	cfg := newDSResourceConfig(t, CDNResourceDataSource{})
	resp := datasource.ReadResponse{State: newDSResourceState(t, CDNResourceDataSource{})}
	d.Read(ctx, datasource.ReadRequest{Config: cfg}, &resp)

	require.True(t, resp.Diagnostics.HasError())
	assert.Empty(t, be.getReqs)
	assert.Empty(t, be.listReqs)
}

func TestResourceDataSource_GetNotFound(t *testing.T) {
	ctx := context.Background()
	be := &fakeResourceBackend{
		getFn: func(_ context.Context, _ *cdn.GetResourceRequest) (*cdn.Resource, error) {
			return nil, grpcstatus.Error(codes.NotFound, "gone")
		},
	}
	d := newDataSourceForTest(be)

	cfg := newDSResourceConfig(t, CDNResourceDataSource{
		ResourceID: types.StringValue("res-missing"),
	})
	resp := datasource.ReadResponse{State: newDSResourceState(t, CDNResourceDataSource{})}
	d.Read(ctx, datasource.ReadRequest{Config: cfg}, &resp)

	require.True(t, resp.Diagnostics.HasError())
	assert.Contains(t, resp.Diagnostics[0].Summary(), "CDN resource not found")
}

func TestResourceDataSource_DuplicateCnames_FirstWins(t *testing.T) {
	// CDN allows multiple resources with the same cname (in practice this
	// is rare but legal). Pin the client-side resolution: first match in
	// List order wins.
	ctx := context.Background()
	be := &fakeResourceBackend{
		listFn: func(_ context.Context, _ *cdn.ListResourcesRequest) ([]*cdn.Resource, error) {
			return []*cdn.Resource{
				cannedResource("res-a", "same.example.com", "test-folder", 1, true),
				cannedResource("res-b", "same.example.com", "test-folder", 2, true),
			}, nil
		},
		getFn: func(_ context.Context, req *cdn.GetResourceRequest) (*cdn.Resource, error) {
			return cannedResource(req.ResourceId, "same.example.com", "test-folder", 1, true), nil
		},
	}
	d := newDataSourceForTest(be)

	cfg := newDSResourceConfig(t, CDNResourceDataSource{
		Cname: types.StringValue("same.example.com"),
	})
	resp := datasource.ReadResponse{State: newDSResourceState(t, CDNResourceDataSource{})}
	d.Read(ctx, datasource.ReadRequest{Config: cfg}, &resp)

	require.False(t, resp.Diagnostics.HasError(), "%v", resp.Diagnostics)
	got := readDSResourceState(t, resp.State)
	assert.Equal(t, "res-a", got.ResourceID.ValueString(), "first match in List order wins")
}

func TestResourceDataSource_EmptyList(t *testing.T) {
	ctx := context.Background()
	be := &fakeResourceBackend{
		listFn: func(_ context.Context, _ *cdn.ListResourcesRequest) ([]*cdn.Resource, error) {
			return nil, nil
		},
	}
	d := newDataSourceForTest(be)

	cfg := newDSResourceConfig(t, CDNResourceDataSource{
		Cname: types.StringValue("any.example.com"),
	})
	resp := datasource.ReadResponse{State: newDSResourceState(t, CDNResourceDataSource{})}
	d.Read(ctx, datasource.ReadRequest{Config: cfg}, &resp)

	require.True(t, resp.Diagnostics.HasError())
	assert.Empty(t, be.getReqs)
}
