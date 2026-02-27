package cdn_raw_log

import (
	"context"
	"fmt"

	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"
	"github.com/yandex-cloud/go-genproto/yandex/cloud/cdn/v1"
	provider_config "github.com/yandex-cloud/terraform-provider-yandex/yandex-framework/provider/config"
)

// Ensure provider defined types fully satisfy framework interfaces
var (
	_ datasource.DataSource              = &cdnRawLogDataSource{}
	_ datasource.DataSourceWithConfigure = &cdnRawLogDataSource{}
)

type cdnRawLogDataSource struct {
	providerConfig *provider_config.Config
}

func NewDataSource() datasource.DataSource {
	return &cdnRawLogDataSource{}
}

func (d *cdnRawLogDataSource) Metadata(_ context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_cdn_raw_log"
}

func (d *cdnRawLogDataSource) Schema(ctx context.Context, _ datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = CDNRawLogDataSourceSchema(ctx)
}

func (d *cdnRawLogDataSource) Configure(_ context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
	if req.ProviderData == nil {
		return
	}

	providerConfig, ok := req.ProviderData.(*provider_config.Config)
	if !ok {
		resp.Diagnostics.AddError(
			"Unexpected Data Source Configure Type",
			fmt.Sprintf("Expected *provider_config.Config, got: %T. Please report this issue to the provider developers.", req.ProviderData),
		)
		return
	}

	d.providerConfig = providerConfig
}

func (d *cdnRawLogDataSource) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	var config CDNRawLogDataSource

	resp.Diagnostics.Append(req.Config.Get(ctx, &config)...)
	if resp.Diagnostics.HasError() {
		return
	}

	resourceID := config.ResourceID.ValueString()

	tflog.Debug(ctx, "Reading CDN Raw Log data source", map[string]interface{}{
		"resource_id": resourceID,
	})

	rawLog, err := d.providerConfig.SDK.CDN().RawLogs().Get(ctx, &cdn.GetRawLogsRequest{
		ResourceId: resourceID,
	})
	if err != nil {
		resp.Diagnostics.AddError(
			"Error reading CDN Raw Log",
			fmt.Sprintf("Could not read CDN Raw Log: %s", err),
		)
		return
	}

	config.ID = types.StringValue(resourceID)
	config.Status = types.StringValue(rawLog.Status.String())

	if settings := rawLog.GetSettings(); settings != nil {
		if config.Settings == nil {
			config.Settings = &Settings{}
		}
		config.Settings.BucketName = types.StringValue(settings.BucketName)
		if settings.BucketRegion != "" {
			config.Settings.BucketRegion = types.StringValue(settings.BucketRegion)
		}
		if settings.FilePrefix != "" {
			config.Settings.FilePrefix = types.StringValue(settings.FilePrefix)
		}
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &config)...)
}

