package cdn_rule

import (
	"context"

	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"
	"github.com/yandex-cloud/go-genproto/yandex/cloud/cdn/v1"
	"github.com/yandex-cloud/terraform-provider-yandex/yandex-framework/services/cdn_resource"
)

// flattenOptions converts API options to Terraform options. planOptions
// carries the user-provided options block from plan/state (or null when
// unavailable) so flatteners can distinguish "API returned defaults the user
// also explicitly asked for" from "user did not set this field". Without it,
// fields like allowed_http_methods get silently dropped to null on Read after
// Create, tripping Terraform's "inconsistent result" detector.
func flattenOptions(ctx context.Context, options *cdn.ResourceOptions, planOptions types.List, diags *diag.Diagnostics) types.List {
	tflog.Debug(ctx, "Flattening CDN rule options using cdn_resource.FlattenCDNResourceOptions")

	// Delegate to cdn_resource flatten function - options structure is identical.
	return cdn_resource.FlattenCDNResourceOptions(ctx, options, planOptions, diags)
}
