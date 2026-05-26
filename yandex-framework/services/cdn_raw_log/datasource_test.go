package cdn_raw_log

import (
	"context"
	"errors"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/datasource"
	dsschema "github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/yandex-cloud/go-genproto/yandex/cloud/cdn/v1"
)

func newDataSourceForTest(b rawLogsBackend) *cdnRawLogDataSource {
	return &cdnRawLogDataSource{backend: b}
}

// newDSConfig builds a tfsdk.Config from the data-source schema and a typed
// model. tfsdk.Config has no public setter, so we route Go→tftypes conversion
// through tfsdk.State (which shares the same schema/Raw shape) and copy out.
func newDSConfig(t *testing.T, m CDNRawLogDataSource) tfsdk.Config {
	t.Helper()
	ctx := context.Background()
	s := CDNRawLogDataSourceSchema(ctx)
	tmp := tfsdk.State{Schema: s}
	diags := tmp.Set(ctx, &m)
	require.False(t, diags.HasError(), "config.Set diagnostics: %v", diags)
	return tfsdk.Config{Raw: tmp.Raw, Schema: s}
}

func newDSState(t *testing.T, schemaObj dsschema.Schema, m CDNRawLogDataSource) tfsdk.State {
	t.Helper()
	ctx := context.Background()
	s := tfsdk.State{Schema: schemaObj}
	diags := s.Set(ctx, &m)
	require.False(t, diags.HasError(), "state.Set diagnostics: %v", diags)
	return s
}

func readDSState(t *testing.T, s tfsdk.State) CDNRawLogDataSource {
	t.Helper()
	var m CDNRawLogDataSource
	diags := s.Get(context.Background(), &m)
	require.False(t, diags.HasError(), "state.Get diagnostics: %v", diags)
	return m
}

func TestDataSource_Read_Success(t *testing.T) {
	ctx := context.Background()
	schemaObj := CDNRawLogDataSourceSchema(ctx)
	be := &fakeBackend{
		getFn: func(_ context.Context, _ *cdn.GetRawLogsRequest) (*cdn.GetRawLogsResponse, error) {
			return &cdn.GetRawLogsResponse{
				Status: cdn.RawLogsStatus_RAW_LOGS_STATUS_OK,
				Settings: &cdn.RawLogsSettings{
					BucketName:   "bk",
					BucketRegion: "ru-central1",
					FilePrefix:   "logs/",
				},
			}, nil
		},
	}
	d := newDataSourceForTest(be)

	cfg := newDSConfig(t, CDNRawLogDataSource{
		ResourceID: types.StringValue("res-ds-1"),
	})
	resp := datasource.ReadResponse{State: newDSState(t, schemaObj, CDNRawLogDataSource{})}
	d.Read(ctx, datasource.ReadRequest{Config: cfg}, &resp)

	require.False(t, resp.Diagnostics.HasError(), "%v", resp.Diagnostics)
	require.Len(t, be.getReqs, 1)
	assert.Equal(t, "res-ds-1", be.getReqs[0].ResourceId)

	got := readDSState(t, resp.State)
	assert.Equal(t, "res-ds-1", got.ID.ValueString())
	assert.Equal(t, "res-ds-1", got.ResourceID.ValueString())
	assert.Equal(t, "RAW_LOGS_STATUS_OK", got.Status.ValueString())
	require.NotNil(t, got.Settings)
	assert.Equal(t, "bk", got.Settings.BucketName.ValueString())
	assert.Equal(t, "ru-central1", got.Settings.BucketRegion.ValueString())
	assert.Equal(t, "logs/", got.Settings.FilePrefix.ValueString())
}

func TestDataSource_Read_APIError(t *testing.T) {
	ctx := context.Background()
	schemaObj := CDNRawLogDataSourceSchema(ctx)
	be := &fakeBackend{
		getFn: func(_ context.Context, _ *cdn.GetRawLogsRequest) (*cdn.GetRawLogsResponse, error) {
			return nil, errors.New("internal")
		},
	}
	d := newDataSourceForTest(be)

	cfg := newDSConfig(t, CDNRawLogDataSource{
		ResourceID: types.StringValue("res-ds-2"),
	})
	resp := datasource.ReadResponse{State: newDSState(t, schemaObj, CDNRawLogDataSource{})}
	d.Read(ctx, datasource.ReadRequest{Config: cfg}, &resp)

	require.True(t, resp.Diagnostics.HasError())
	assert.Equal(t, "Error reading CDN Raw Log", resp.Diagnostics[0].Summary())
}

func TestDataSource_Read_EmptyOptionalFieldsLeftNull(t *testing.T) {
	// API returns BucketRegion and FilePrefix as "" — the resource code only
	// surfaces them when non-empty, so the data source state should keep them
	// at the schema default (null), not "" coerced to a string.
	ctx := context.Background()
	schemaObj := CDNRawLogDataSourceSchema(ctx)
	be := &fakeBackend{
		getFn: func(_ context.Context, _ *cdn.GetRawLogsRequest) (*cdn.GetRawLogsResponse, error) {
			return &cdn.GetRawLogsResponse{
				Status: cdn.RawLogsStatus_RAW_LOGS_STATUS_NOT_ACTIVATED,
				Settings: &cdn.RawLogsSettings{
					BucketName:   "only-bucket",
					BucketRegion: "",
					FilePrefix:   "",
				},
			}, nil
		},
	}
	d := newDataSourceForTest(be)

	cfg := newDSConfig(t, CDNRawLogDataSource{
		ResourceID: types.StringValue("res-ds-3"),
	})
	resp := datasource.ReadResponse{State: newDSState(t, schemaObj, CDNRawLogDataSource{})}
	d.Read(ctx, datasource.ReadRequest{Config: cfg}, &resp)

	require.False(t, resp.Diagnostics.HasError(), "%v", resp.Diagnostics)
	got := readDSState(t, resp.State)
	require.NotNil(t, got.Settings)
	assert.Equal(t, "only-bucket", got.Settings.BucketName.ValueString())
	// Empty string from API → null in state, not "".
	// The data-source schema marks bucket_region and file_prefix as Computed,
	// so they end up as unknown until populated. Here the code only assigns
	// them when API returns non-empty — so they remain at whatever the framework
	// initialized them to (null in our test state.Set seed).
	assert.True(t, got.Settings.BucketRegion.IsNull(), "empty BucketRegion stays null in state")
	assert.True(t, got.Settings.FilePrefix.IsNull(), "empty FilePrefix stays null in state")
}
