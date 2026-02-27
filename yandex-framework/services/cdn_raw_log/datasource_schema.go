package cdn_raw_log

import (
	"context"

	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
)

func CDNRawLogDataSourceSchema(ctx context.Context) schema.Schema {
	return schema.Schema{
		MarkdownDescription: "Get information about a Yandex.Cloud CDN Raw Log configuration.",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Computed:            true,
				MarkdownDescription: "The ID of the CDN Raw Log configuration",
			},
			"resource_id": schema.StringAttribute{
				Required:            true,
				MarkdownDescription: "CDN resource ID for which to retrieve raw logs configuration",
				Validators: []validator.String{
					stringvalidator.LengthAtLeast(1),
				},
			},
			"status": schema.StringAttribute{
				Computed:            true,
				MarkdownDescription: "The status of the raw logs configuration (ACTIVE, NOT_ACTIVATED, SUSPENDED)",
			},
		},
		Blocks: map[string]schema.Block{
			"settings": schema.SingleNestedBlock{
				MarkdownDescription: "Raw logs settings configuration",
				Attributes: map[string]schema.Attribute{
					"bucket_name": schema.StringAttribute{
						Computed:            true,
						MarkdownDescription: "Object Storage bucket name where logs are stored",
					},
					"bucket_region": schema.StringAttribute{
						Computed:            true,
						MarkdownDescription: "Object Storage bucket region",
					},
					"file_prefix": schema.StringAttribute{
						Computed:            true,
						MarkdownDescription: "Prefix for log files in the bucket",
					},
				},
			},
		},
	}
}
