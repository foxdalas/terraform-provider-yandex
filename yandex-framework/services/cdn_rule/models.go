package cdn_rule

import (
	"github.com/hashicorp/terraform-plugin-framework-timeouts/resource/timeouts"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

// CDNRuleModel represents the Terraform resource model for yandex_cdn_rule
type CDNRuleModel struct {
	Timeouts    timeouts.Value `tfsdk:"timeouts"`
	ID          types.String   `tfsdk:"id"`           // Composite: "resource_id/rule_id"
	ResourceID  types.String   `tfsdk:"resource_id"`  // CDN resource ID this rule belongs to
	RuleID      types.String   `tfsdk:"rule_id"`      // Rule ID (computed)
	Name        types.String   `tfsdk:"name"`         // Rule name
	RulePattern types.String   `tfsdk:"rule_pattern"` // Regular expression pattern
	Weight      types.Int64    `tfsdk:"weight"`       // Rule weight for ordering
	Options     types.List     `tfsdk:"options"`      // CDN options - uses same structure as cdn_resource
	// OriginsGroupID and OriginProtocol override the resource-level origins
	// group and origin protocol for requests matching this rule. They are
	// write-only: the CDN API accepts them on Create/Update but the Rule
	// returned by Get does not echo them back, so Read never reconciles these
	// fields and Terraform trusts the configured value.
	OriginsGroupID types.String `tfsdk:"origins_group_id"` // Per-rule origins group override (write-only)
	OriginProtocol types.String `tfsdk:"origin_protocol"`  // Per-rule origin protocol override (write-only)
}

// CDNRuleDataSource represents the Terraform data source model for yandex_cdn_rule
type CDNRuleDataSource struct {
	ID          types.String `tfsdk:"id"`           // Composite: "resource_id/rule_id" (computed)
	ResourceID  types.String `tfsdk:"resource_id"`  // CDN resource ID (required)
	RuleID      types.String `tfsdk:"rule_id"`      // Rule ID for direct lookup (optional, computed) - String to match resource
	Name        types.String `tfsdk:"name"`         // Rule name for search (optional, computed)
	RulePattern types.String `tfsdk:"rule_pattern"` // Regular expression pattern (computed)
	Weight      types.Int64  `tfsdk:"weight"`       // Rule weight for ordering (computed)
	Options     types.List   `tfsdk:"options"`      // CDN options (computed)
}

// Note: Options uses CDNOptionsModel from cdn_resource package
// This ensures consistency between cdn_resource and cdn_rule
