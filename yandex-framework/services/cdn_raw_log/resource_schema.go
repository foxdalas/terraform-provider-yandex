package cdn_raw_log

import (
	"context"
	"regexp"

	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringdefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
)

// filePrefixNoTrailingSlash matches the empty string or any string whose last
// character is not '/'. The CDN Raw Logs API rejects file_prefix values that
// end with '/' (returns InvalidArgument at Activate/Update time); validating
// up front surfaces the problem during `terraform plan` instead of `apply`.
var filePrefixNoTrailingSlash = regexp.MustCompile(`^(.*[^/]|)$`)

func CDNRawLogResourceSchema(ctx context.Context) schema.Schema {
	return schema.Schema{
		MarkdownDescription: "Allows management of a Yandex.Cloud CDN Raw Log configuration. Raw logs provide access to detailed CDN access logs that are stored in Object Storage.",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Computed:            true,
				MarkdownDescription: "The ID of the CDN Raw Log configuration",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"resource_id": schema.StringAttribute{
				Required:            true,
				MarkdownDescription: "CDN resource ID for which raw logs are configured",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
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
						Required:            true,
						MarkdownDescription: "Object Storage bucket name where logs will be stored",
						Validators: []validator.String{
							stringvalidator.LengthAtLeast(3),
							stringvalidator.LengthAtMost(63),
						},
					},
					"bucket_region": schema.StringAttribute{
						Optional: true,
						// Computed + Default lets us populate ru-central1 during plan
						// rather than silently substituting it during apply — without
						// Computed, Terraform reports "inconsistent result after apply"
						// when the user omits the attribute.
						Computed:            true,
						Default:             stringdefault.StaticString("ru-central1"),
						MarkdownDescription: "Object Storage bucket region (defaults to `ru-central1`)",
					},
					"file_prefix": schema.StringAttribute{
						Optional:            true,
						MarkdownDescription: "Prefix for log files in the bucket. Must not end with `/` — the CDN API rejects such values.",
						Validators: []validator.String{
							stringvalidator.RegexMatches(
								filePrefixNoTrailingSlash,
								"file_prefix must not end with '/'",
							),
						},
					},
				},
			},
		},
	}
}
