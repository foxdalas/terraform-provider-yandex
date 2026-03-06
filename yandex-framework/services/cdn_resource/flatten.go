package cdn_resource

import (
	"context"
	"fmt"

	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"
	"github.com/yandex-cloud/go-genproto/yandex/cloud/cdn/v1"
)

// FlattenCDNResourceOptions converts CDN API ResourceOptions to Terraform state
// planOptions: optional plan options to preserve disabled cache blocks
// When API returns nil for cache settings but plan has enabled=false,
// we preserve the disabled block in state to prevent plan/apply inconsistency
// Exported for reuse in cdn_rule package
func FlattenCDNResourceOptions(ctx context.Context, options *cdn.ResourceOptions, planOptions types.List, diags *diag.Diagnostics) types.List {
	if options == nil {
		return types.ListNull(types.ObjectType{
			AttrTypes: GetCDNOptionsAttrTypes(),
		})
	}

	// Extract plan options model if available
	// Errors are logged but don't fail the operation (graceful degradation)
	var planOptionsModel *CDNOptionsModel
	if !planOptions.IsNull() && len(planOptions.Elements()) > 0 {
		var planOptionsModels []CDNOptionsModel
		d := planOptions.ElementsAs(ctx, &planOptionsModels, false)
		if d.HasError() {
			tflog.Warn(ctx, "Failed to extract plan options", map[string]interface{}{
				"error": d.Errors(),
			})
		} else if len(planOptionsModels) > 0 {
			planOptionsModel = &planOptionsModels[0]
		}
	}

	opt := CDNOptionsModel{}

	// Boolean options - CRITICAL: Set null when Enabled=false to prevent state drift
	opt.Slice = flattenBoolOption(options.Slice)
	opt.IgnoreCookie = flattenBoolOption(options.IgnoreCookie)
	opt.ProxyCacheMethodsSet = flattenBoolOption(options.ProxyCacheMethodsSet)
	opt.DisableProxyForceRanges = flattenBoolOption(options.DisableProxyForceRanges)

	// Cache settings - nested blocks (pass plan to preserve disabled blocks)
	opt.EdgeCacheSettings = flattenEdgeCacheSettings(ctx, options.EdgeCacheSettings, planOptionsModel, diags)
	opt.BrowserCacheSettings = flattenBrowserCacheSettings(ctx, options.BrowserCacheSettings, planOptionsModel, diags)

	// String options - CORRECT SEMANTICS: null when not configured
	if options.CustomServerName != nil && options.CustomServerName.Enabled {
		opt.CustomServerName = types.StringValue(options.CustomServerName.Value)
	} else {
		opt.CustomServerName = types.StringNull()
	}

	// SecureKey - combines secure_key and enable_ip_url_signing
	// CORRECT SEMANTICS: Both null when secure_key is not configured
	if options.SecureKey != nil && options.SecureKey.Enabled {
		opt.SecureKey = types.StringValue(options.SecureKey.Key)
		// EnableIPURLSigning is derived from SecureKey.Type
		if options.SecureKey.Type == cdn.SecureKeyURLType_ENABLE_IP_SIGNING {
			opt.EnableIPURLSigning = types.BoolValue(true)
		} else {
			opt.EnableIPURLSigning = types.BoolValue(false)
		}
	} else {
		opt.SecureKey = types.StringNull()
		opt.EnableIPURLSigning = types.BoolNull()
	}

	// List options - CORRECT SEMANTICS: null when not configured
	// DEPRECATED: cache_http_headers - removed as it does not affect anything
	// Always set to null (not read from API)
	opt.CacheHTTPHeaders = types.ListNull(types.StringType)

	if options.Cors != nil && options.Cors.Enabled {
		listVal, d := types.ListValueFrom(ctx, types.StringType, options.Cors.Value)
		diags.Append(d...)
		opt.Cors = listVal
	} else {
		opt.Cors = types.ListNull(types.StringType)
	}

	if options.AllowedHttpMethods != nil && options.AllowedHttpMethods.Enabled {
		// Check if API returned defaults - treat as "not configured"
		// This ensures plan consistency: user doesn't specify → plan=null → result=null
		if isDefaultAllowedHttpMethods(options.AllowedHttpMethods.Value) && (planOptionsModel == nil || planOptionsModel.AllowedHTTPMethods.IsNull()) {
			opt.AllowedHTTPMethods = types.ListNull(types.StringType)
		} else {
			// User explicitly configured non-default values
			listVal, d := types.ListValueFrom(ctx, types.StringType, options.AllowedHttpMethods.Value)
			diags.Append(d...)
			opt.AllowedHTTPMethods = listVal
		}
	} else {
		opt.AllowedHTTPMethods = types.ListNull(types.StringType)
	}

	if options.Stale != nil && options.Stale.Enabled {
		listVal, d := types.ListValueFrom(ctx, types.StringType, options.Stale.Value)
		diags.Append(d...)
		opt.Stale = listVal
	} else {
		opt.Stale = types.ListNull(types.StringType)
	}

	// Map options - respect plan's type (null vs empty map)
	// When API returns disabled, check plan to determine if state should be null or empty map
	if options.StaticHeaders != nil && options.StaticHeaders.Enabled {
		mapVal, d := types.MapValueFrom(ctx, types.StringType, options.StaticHeaders.Value)
		diags.Append(d...)
		opt.StaticResponseHeaders = mapVal
	} else {
		// API returned disabled/nil - check what plan expected
		if planOptionsModel != nil && !planOptionsModel.StaticResponseHeaders.IsNull() {
			// Plan had a non-null value (could be empty map {})
			// Return empty map to match plan's type
			opt.StaticResponseHeaders = types.MapValueMust(types.StringType, map[string]attr.Value{})
		} else {
			// Plan was null - return null
			opt.StaticResponseHeaders = types.MapNull(types.StringType)
		}
	}

	if options.StaticRequestHeaders != nil && options.StaticRequestHeaders.Enabled {
		mapVal, d := types.MapValueFrom(ctx, types.StringType, options.StaticRequestHeaders.Value)
		diags.Append(d...)
		opt.StaticRequestHeaders = mapVal
	} else {
		// API returned disabled/nil - check what plan expected
		if planOptionsModel != nil && !planOptionsModel.StaticRequestHeaders.IsNull() {
			// Plan had a non-null value (could be empty map {})
			// Return empty map to match plan's type
			opt.StaticRequestHeaders = types.MapValueMust(types.StringType, map[string]attr.Value{})
		} else {
			// Plan was null - return null
			opt.StaticRequestHeaders = types.MapNull(types.StringType)
		}
	}

	// Mutually exclusive options groups
	flattenHostOptions(options.HostOptions, &opt, planOptionsModel, diags)
	flattenQueryParamsOptions(ctx, options.QueryParamsOptions, &opt, diags)
	flattenCompressionOptions(options.CompressionOptions, &opt)
	flattenRedirectOptions(options.RedirectOptions, &opt)

	// Nested blocks
	flattenIPAddressACL(ctx, options.IpAddressAcl, &opt, diags)
	flattenRewrite(ctx, options.Rewrite, &opt, diags)

	// New options (go-genproto v0.57.0)
	opt.Websockets = flattenWebsocketsOption(options.Websockets)
	flattenGeoACL(ctx, options.GeoAcl, &opt, diags)
	flattenReferrerACL(ctx, options.ReferrerAcl, &opt, diags)
	flattenHeaderFilter(ctx, options.HeaderFilter, &opt, planOptionsModel, diags)
	flattenFollowRedirects(ctx, options.FollowRedirects, &opt, planOptionsModel, diags)
	flattenStaticResponse(ctx, options.StaticResponse, &opt, planOptionsModel, diags)

	optionsList, d := types.ListValueFrom(ctx, types.ObjectType{
		AttrTypes: GetCDNOptionsAttrTypes(),
	}, []CDNOptionsModel{opt})
	diags.Append(d...)

	return optionsList
}

// flattenBoolOption converts CDN API BoolOption to types.Bool with proper null handling
// CORRECT SEMANTICS: Enabled=false means "not configured by user" → return null
// This is the proper Framework way - null = "provider doesn't manage this field"
func flattenBoolOption(option *cdn.ResourceOptions_BoolOption) types.Bool {
	if option == nil || !option.Enabled {
		// Not configured in API = not managed by provider
		return types.BoolNull()
	}
	return types.BoolValue(option.Value)
}

// isDefaultAllowedHttpMethods checks if API returned default HTTP methods
// API applies defaults: ["GET", "HEAD", "OPTIONS"] when user doesn't configure this field
// Returns true if apiValues contains exactly the default set (order-independent)
func isDefaultAllowedHttpMethods(apiValues []string) bool {
	// Known API defaults from actual behavior (confirmed via testing)
	defaults := map[string]bool{
		"GET":     true,
		"HEAD":    true,
		"OPTIONS": true,
	}

	if len(apiValues) != len(defaults) {
		return false
	}

	for _, v := range apiValues {
		if !defaults[v] {
			return false
		}
	}

	return true
}

// flattenHostOptions handles mutually exclusive forward_host_header and custom_host_header
// IMPORTANT: Returns zero values for inactive fields to work with plan modifiers
// expand.go will check if ALL fields are zero values before sending to API
func flattenHostOptions(hostOptions *cdn.ResourceOptions_HostOptions, opt *CDNOptionsModel, planOptions *CDNOptionsModel, diags *diag.Diagnostics) {
	if hostOptions == nil {
		// No host options configured → both null (matches schema Optional+Computed=false)

		// CRITICAL: Check plan for false/empty values to preserve user intent and avoid consistency errors
		if planOptions != nil && !planOptions.ForwardHostHeader.IsNull() && !planOptions.ForwardHostHeader.ValueBool() {
			opt.ForwardHostHeader = types.BoolValue(false)
		} else {
			opt.ForwardHostHeader = types.BoolNull()
		}

		if planOptions != nil && !planOptions.CustomHostHeader.IsNull() && planOptions.CustomHostHeader.ValueString() == "" {
			opt.CustomHostHeader = types.StringValue("")
		} else {
			opt.CustomHostHeader = types.StringNull()
		}
		return
	}

	switch variant := hostOptions.HostVariant.(type) {
	case *cdn.ResourceOptions_HostOptions_ForwardHostHeader:
		// forward_host_header is active
		if variant.ForwardHostHeader != nil && variant.ForwardHostHeader.Enabled {
			opt.ForwardHostHeader = types.BoolValue(variant.ForwardHostHeader.Value)
		} else {
			opt.ForwardHostHeader = types.BoolValue(false)
		}
		// custom_host_header is inactive
		// Preserve plan value if it's empty string
		if planOptions != nil && !planOptions.CustomHostHeader.IsNull() && planOptions.CustomHostHeader.ValueString() == "" {
			opt.CustomHostHeader = types.StringValue("")
		} else {
			opt.CustomHostHeader = types.StringNull()
		}
	case *cdn.ResourceOptions_HostOptions_Host:
		// custom_host_header is active
		if variant.Host != nil && variant.Host.Enabled {
			opt.CustomHostHeader = types.StringValue(variant.Host.Value)
		} else {
			opt.CustomHostHeader = types.StringValue("")
		}
		// forward_host_header is inactive
		// Preserve plan value if it's false
		if planOptions != nil && !planOptions.ForwardHostHeader.IsNull() && !planOptions.ForwardHostHeader.ValueBool() {
			opt.ForwardHostHeader = types.BoolValue(false)
		} else {
			opt.ForwardHostHeader = types.BoolNull()
		}
	default:
		// Unknown variant → both null (or preserve plan)
		if planOptions != nil && !planOptions.ForwardHostHeader.IsNull() && !planOptions.ForwardHostHeader.ValueBool() {
			opt.ForwardHostHeader = types.BoolValue(false)
		} else {
			opt.ForwardHostHeader = types.BoolNull()
		}

		if planOptions != nil && !planOptions.CustomHostHeader.IsNull() && planOptions.CustomHostHeader.ValueString() == "" {
			opt.CustomHostHeader = types.StringValue("")
		} else {
			opt.CustomHostHeader = types.StringNull()
		}
	}
}

// flattenQueryParamsOptions handles mutually exclusive query params options
// IMPORTANT: Returns zero values for inactive fields to work with plan modifiers
// expand.go will check if ALL fields are zero values before sending to API
func flattenQueryParamsOptions(ctx context.Context, queryOptions *cdn.ResourceOptions_QueryParamsOptions, opt *CDNOptionsModel, diags *diag.Diagnostics) {
	// Initialize all to zero values
	opt.IgnoreQueryParams = types.BoolValue(false)
	opt.QueryParamsWhitelist = types.ListNull(types.StringType)
	opt.QueryParamsBlacklist = types.ListNull(types.StringType)

	if queryOptions == nil {
		return // All remain at zero values
	}

	switch variant := queryOptions.QueryParamsVariant.(type) {
	case *cdn.ResourceOptions_QueryParamsOptions_IgnoreQueryString:
		// ignore_query_params is active
		if variant.IgnoreQueryString != nil && variant.IgnoreQueryString.Enabled {
			opt.IgnoreQueryParams = types.BoolValue(variant.IgnoreQueryString.Value)
		}
		// whitelist and blacklist remain null (inactive fields)
	case *cdn.ResourceOptions_QueryParamsOptions_QueryParamsWhitelist:
		// query_params_whitelist is active
		if variant.QueryParamsWhitelist != nil && variant.QueryParamsWhitelist.Enabled {
			listVal, d := types.ListValueFrom(ctx, types.StringType, variant.QueryParamsWhitelist.Value)
			diags.Append(d...)
			opt.QueryParamsWhitelist = listVal
		}
		// ignore_query_params remains false, blacklist remains null (inactive fields)
	case *cdn.ResourceOptions_QueryParamsOptions_QueryParamsBlacklist:
		// query_params_blacklist is active
		if variant.QueryParamsBlacklist != nil && variant.QueryParamsBlacklist.Enabled {
			listVal, d := types.ListValueFrom(ctx, types.StringType, variant.QueryParamsBlacklist.Value)
			diags.Append(d...)
			opt.QueryParamsBlacklist = listVal
		}
		// ignore_query_params remains false, whitelist remains null (inactive fields)
	}
}

// flattenCompressionOptions handles mutually exclusive gzip_on, fetched_compressed, and brotli_compression
// IMPORTANT: Returns false/null for inactive fields to match user config with coalesce()
// expand.go only sends options with true value, so false is effectively ignored
func flattenCompressionOptions(compressionOptions *cdn.ResourceOptions_CompressionOptions, opt *CDNOptionsModel) {
	// Initialize all to zero/null values
	opt.GzipOn = types.BoolValue(false)
	opt.FetchedCompressed = types.BoolValue(false)
	opt.BrotliCompression = types.ListNull(types.StringType)

	if compressionOptions == nil {
		return
	}

	switch variant := compressionOptions.CompressionVariant.(type) {
	case *cdn.ResourceOptions_CompressionOptions_GzipOn:
		if variant.GzipOn != nil && variant.GzipOn.Enabled {
			opt.GzipOn = types.BoolValue(variant.GzipOn.Value)
		}
	case *cdn.ResourceOptions_CompressionOptions_FetchCompressed:
		if variant.FetchCompressed != nil && variant.FetchCompressed.Enabled {
			opt.FetchedCompressed = types.BoolValue(variant.FetchCompressed.Value)
		}
	case *cdn.ResourceOptions_CompressionOptions_BrotliCompression:
		if variant.BrotliCompression != nil && variant.BrotliCompression.Enabled && len(variant.BrotliCompression.Value) > 0 {
			listVal, d := types.ListValueFrom(context.Background(), types.StringType, variant.BrotliCompression.Value)
			if !d.HasError() {
				opt.BrotliCompression = listVal
			}
		}
	}
}

// flattenRedirectOptions handles mutually exclusive redirect options
// IMPORTANT: Returns zero values for inactive fields to work with plan modifiers
// expand.go will check if ALL fields are zero values before sending to API
func flattenRedirectOptions(redirectOptions *cdn.ResourceOptions_RedirectOptions, opt *CDNOptionsModel) {
	// Initialize both to false (zero value for bool)
	opt.RedirectHttpToHttps = types.BoolValue(false)
	opt.RedirectHttpsToHttp = types.BoolValue(false)

	if redirectOptions == nil {
		return // Both remain false
	}

	switch variant := redirectOptions.RedirectVariant.(type) {
	case *cdn.ResourceOptions_RedirectOptions_RedirectHttpToHttps:
		// redirect_http_to_https is active
		if variant.RedirectHttpToHttps != nil && variant.RedirectHttpToHttps.Enabled {
			opt.RedirectHttpToHttps = types.BoolValue(variant.RedirectHttpToHttps.Value)
		}
		// redirect_https_to_http remains false (inactive field)
	case *cdn.ResourceOptions_RedirectOptions_RedirectHttpsToHttp:
		// redirect_https_to_http is active
		if variant.RedirectHttpsToHttp != nil && variant.RedirectHttpsToHttp.Enabled {
			opt.RedirectHttpsToHttp = types.BoolValue(variant.RedirectHttpsToHttp.Value)
		}
		// redirect_http_to_https remains false (inactive field)
	}
}

// flattenIPAddressACL converts API IP address ACL to Terraform state
func flattenIPAddressACL(ctx context.Context, acl *cdn.ResourceOptions_IPAddressACLOption, opt *CDNOptionsModel, diags *diag.Diagnostics) {
	if acl == nil {
		opt.IPAddressACL = types.ListNull(types.ObjectType{
			AttrTypes: map[string]attr.Type{
				"policy_type":     types.StringType,
				"excepted_values": types.ListType{ElemType: types.StringType},
			},
		})
		return
	}

	var policyType string
	switch acl.PolicyType {
	case cdn.PolicyType_POLICY_TYPE_ALLOW:
		policyType = "allow"
	case cdn.PolicyType_POLICY_TYPE_DENY:
		policyType = "deny"
	default:
		policyType = "allow"
	}

	exceptedList, d := types.ListValueFrom(ctx, types.StringType, acl.ExceptedValues)
	diags.Append(d...)

	aclModel := IPAddressACLModel{
		PolicyType:     types.StringValue(policyType),
		ExceptedValues: exceptedList,
	}

	aclList, d := types.ListValueFrom(ctx, types.ObjectType{
		AttrTypes: map[string]attr.Type{
			"policy_type":     types.StringType,
			"excepted_values": types.ListType{ElemType: types.StringType},
		},
	}, []IPAddressACLModel{aclModel})
	diags.Append(d...)

	opt.IPAddressACL = aclList
}

// flattenRewrite converts API rewrite option to Terraform state
func flattenRewrite(ctx context.Context, rewrite *cdn.ResourceOptions_RewriteOption, opt *CDNOptionsModel, diags *diag.Diagnostics) {
	if rewrite == nil || !rewrite.Enabled {
		opt.Rewrite = types.ListNull(types.ObjectType{
			AttrTypes: map[string]attr.Type{
				"enabled": types.BoolType,
				"body":    types.StringType,
				"flag":    types.StringType,
			},
		})
		return
	}

	var flag string
	switch rewrite.Flag {
	case cdn.RewriteFlag_LAST:
		flag = "last"
	case cdn.RewriteFlag_BREAK:
		flag = "break"
	case cdn.RewriteFlag_REDIRECT:
		flag = "redirect"
	case cdn.RewriteFlag_PERMANENT:
		flag = "permanent"
	default:
		flag = "break"
	}

	rewriteModel := RewriteModel{
		Enabled: types.BoolValue(rewrite.Enabled),
		Body:    types.StringValue(rewrite.Body),
		Flag:    types.StringValue(flag),
	}

	rewriteList, d := types.ListValueFrom(ctx, types.ObjectType{
		AttrTypes: map[string]attr.Type{
			"enabled": types.BoolType,
			"body":    types.StringType,
			"flag":    types.StringType,
		},
	}, []RewriteModel{rewriteModel})
	diags.Append(d...)
	opt.Rewrite = rewriteList
}

// flattenEdgeCacheSettings converts API EdgeCacheSettings to Terraform state
// Handles two API variants:
// 1. DefaultValue → cache_time = {"*" = value}
// 2. Value.CustomValues → cache_time = map
// planOptionsModel: optional plan options model to preserve disabled blocks
func flattenEdgeCacheSettings(ctx context.Context, edgeCache *cdn.ResourceOptions_EdgeCacheSettings, planOptionsModel *CDNOptionsModel, diags *diag.Diagnostics) types.List {
	edgeCacheAttrTypes := map[string]attr.Type{
		"enabled":       types.BoolType,
		"value":         types.Int64Type,
		"custom_values": types.MapType{ElemType: types.Int64Type},
		"default_value": types.Int64Type,
	}

	// Log what API returned
	if edgeCache == nil {
		tflog.Debug(ctx, "EdgeCacheSettings: API returned nil")

		// CRITICAL: Check if plan had enabled=false
		// API may delete the block when we send cache_time=0
		// But plan expects the block with enabled=false, not null!
		if planOptionsModel != nil && !planOptionsModel.EdgeCacheSettings.IsNull() && len(planOptionsModel.EdgeCacheSettings.Elements()) > 0 {
			var planEdgeSettings []EdgeCacheSettingsModel
			planDiags := planOptionsModel.EdgeCacheSettings.ElementsAs(ctx, &planEdgeSettings, false)
			if !planDiags.HasError() && len(planEdgeSettings) > 0 {
				planEnabled := planEdgeSettings[0].Enabled
				if !planEnabled.IsNull() && !planEnabled.IsUnknown() && !planEnabled.ValueBool() {
					// Plan had enabled=false, preserve it in state
					tflog.Debug(ctx, "EdgeCacheSettings: Plan had enabled=false, preserving in state")
					edgeCacheModel := EdgeCacheSettingsModel{
						Enabled:      types.BoolValue(false),
						Value:        types.Int64Null(),
						CustomValues: types.MapNull(types.Int64Type),
						DefaultValue: types.Int64Null(),
					}
					edgeCacheList, d := types.ListValueFrom(ctx, types.ObjectType{
						AttrTypes: edgeCacheAttrTypes,
					}, []EdgeCacheSettingsModel{edgeCacheModel})
					diags.Append(d...)
					return edgeCacheList
				}
			}
		}

		return types.ListNull(types.ObjectType{AttrTypes: edgeCacheAttrTypes})
	}

	tflog.Debug(ctx, "EdgeCacheSettings: API returned", map[string]interface{}{
		"Enabled": edgeCache.Enabled,
	})

	// If API returns Enabled=false, it means "use default 345600"
	// We don't expose this in state (return null) UNLESS plan had enabled=false
	if !edgeCache.Enabled {
		tflog.Debug(ctx, "EdgeCacheSettings: API returned Enabled=false (use default)")

		// Check if plan had enabled=false (user wanted to disable caching)
		if planOptionsModel != nil && !planOptionsModel.EdgeCacheSettings.IsNull() && len(planOptionsModel.EdgeCacheSettings.Elements()) > 0 {
			var planEdgeSettings []EdgeCacheSettingsModel
			planDiags := planOptionsModel.EdgeCacheSettings.ElementsAs(ctx, &planEdgeSettings, false)
			if !planDiags.HasError() && len(planEdgeSettings) > 0 {
				planEnabled := planEdgeSettings[0].Enabled
				if !planEnabled.IsNull() && !planEnabled.IsUnknown() && !planEnabled.ValueBool() {
					// Plan had enabled=false, preserve it in state
					tflog.Debug(ctx, "EdgeCacheSettings: Plan had enabled=false, preserving in state")
					edgeCacheModel := EdgeCacheSettingsModel{
						Enabled:      types.BoolValue(false),
						Value:        types.Int64Null(),
						CustomValues: types.MapNull(types.Int64Type),
						DefaultValue: types.Int64Null(),
					}
					edgeCacheList, d := types.ListValueFrom(ctx, types.ObjectType{
						AttrTypes: edgeCacheAttrTypes,
					}, []EdgeCacheSettingsModel{edgeCacheModel})
					diags.Append(d...)
					return edgeCacheList
				}
			}
		}

		return types.ListNull(types.ObjectType{AttrTypes: edgeCacheAttrTypes})
	}

	// Check if caching is disabled (cache_time=0)
	// This needs to be translated to user-facing enabled=false
	cachingDisabled := false
	if edgeCache.ValuesVariant != nil {
		switch v := edgeCache.ValuesVariant.(type) {
		case *cdn.ResourceOptions_EdgeCacheSettings_DefaultValue:
			if v.DefaultValue == 0 {
				cachingDisabled = true
				tflog.Debug(ctx, "EdgeCacheSettings: API returned DefaultValue=0 (disabled), saving as enabled=false")
			}
		case *cdn.ResourceOptions_EdgeCacheSettings_Value:
			if v.Value != nil {
				// Check if all custom values are 0 (fully disabled)
				allZero := true
				for _, val := range v.Value.CustomValues {
					if val != 0 {
						allZero = false
						break
					}
				}
				if allZero && len(v.Value.CustomValues) > 0 {
					cachingDisabled = true
					tflog.Debug(ctx, "EdgeCacheSettings: API returned all cache_time=0 (disabled), saving as enabled=false")
				}
			}
		}
	}

	// If caching is disabled (cache_time=0), return enabled=false without value/custom_values
	if cachingDisabled {
		edgeCacheModel := EdgeCacheSettingsModel{
			Enabled:      types.BoolValue(false),
			Value:        types.Int64Null(),
			CustomValues: types.MapNull(types.Int64Type),
			DefaultValue: types.Int64Null(),
		}
		edgeCacheList, d := types.ListValueFrom(ctx, types.ObjectType{
			AttrTypes: edgeCacheAttrTypes,
		}, []EdgeCacheSettingsModel{edgeCacheModel})
		diags.Append(d...)
		return edgeCacheList
	}

	// Caching is enabled with non-zero values
	edgeCacheModel := EdgeCacheSettingsModel{
		Enabled: types.BoolValue(true),
	}

	// Handle value/custom_values based on API response
	// NEW API from master (commit 042b2e91):
	// - SimpleValue: base cache time for 200, 206, 301, 302 (4xx/5xx NOT cached)
	// - CustomValues: overrides with higher priority, key "any" = all response codes
	if edgeCache.ValuesVariant != nil {
		switch v := edgeCache.ValuesVariant.(type) {
		case *cdn.ResourceOptions_EdgeCacheSettings_DefaultValue:
			edgeCacheModel.Value = types.Int64Null()
			edgeCacheModel.CustomValues = types.MapNull(types.Int64Type)
			edgeCacheModel.DefaultValue = types.Int64Value(v.DefaultValue)

		case *cdn.ResourceOptions_EdgeCacheSettings_Value:
			// New API with CachingTimes (SimpleValue + CustomValues)
			if v.Value != nil {
				// Return SimpleValue as value
				if v.Value.SimpleValue > 0 {
					edgeCacheModel.Value = types.Int64Value(v.Value.SimpleValue)
				} else {
					edgeCacheModel.Value = types.Int64Null()
				}

				// Return CustomValues as custom_values
				if len(v.Value.CustomValues) > 0 {
					mapVal, d := types.MapValueFrom(ctx, types.Int64Type, v.Value.CustomValues)
					diags.Append(d...)
					edgeCacheModel.CustomValues = mapVal
				} else {
					edgeCacheModel.CustomValues = types.MapNull(types.Int64Type)
				}
			} else {
				edgeCacheModel.Value = types.Int64Null()
				edgeCacheModel.CustomValues = types.MapNull(types.Int64Type)
			}

		default:
			edgeCacheModel.Value = types.Int64Null()
			edgeCacheModel.CustomValues = types.MapNull(types.Int64Type)
		}
	} else {
		edgeCacheModel.Value = types.Int64Null()
		edgeCacheModel.CustomValues = types.MapNull(types.Int64Type)
	}

	edgeCacheList, d := types.ListValueFrom(ctx, types.ObjectType{
		AttrTypes: edgeCacheAttrTypes,
	}, []EdgeCacheSettingsModel{edgeCacheModel})
	diags.Append(d...)

	return edgeCacheList
}

// flattenBrowserCacheSettings converts API BrowserCacheSettings to Terraform state
// planOptionsModel: optional plan options model to preserve disabled blocks
func flattenBrowserCacheSettings(ctx context.Context, browserCache *cdn.ResourceOptions_Int64Option, planOptionsModel *CDNOptionsModel, diags *diag.Diagnostics) types.List {
	browserCacheAttrTypes := map[string]attr.Type{
		"enabled":    types.BoolType,
		"cache_time": types.Int64Type,
	}

	// If API returns nil, return null (not configured)
	if browserCache == nil {
		// CRITICAL: Check if plan had enabled=false
		// API may delete the block when we send cache_time=0
		if planOptionsModel != nil && !planOptionsModel.BrowserCacheSettings.IsNull() && len(planOptionsModel.BrowserCacheSettings.Elements()) > 0 {
			var planBrowserSettings []BrowserCacheSettingsModel
			planDiags := planOptionsModel.BrowserCacheSettings.ElementsAs(ctx, &planBrowserSettings, false)
			if !planDiags.HasError() && len(planBrowserSettings) > 0 {
				planEnabled := planBrowserSettings[0].Enabled
				if !planEnabled.IsNull() && !planEnabled.IsUnknown() && !planEnabled.ValueBool() {
					// Plan had enabled=false, preserve it in state
					tflog.Debug(ctx, "BrowserCacheSettings: Plan had enabled=false, preserving in state")
					browserCacheModel := BrowserCacheSettingsModel{
						Enabled:   types.BoolValue(false),
						CacheTime: types.Int64Null(),
					}
					browserCacheList, d := types.ListValueFrom(ctx, types.ObjectType{
						AttrTypes: browserCacheAttrTypes,
					}, []BrowserCacheSettingsModel{browserCacheModel})
					diags.Append(d...)
					return browserCacheList
				}
			}
		}

		return types.ListNull(types.ObjectType{AttrTypes: browserCacheAttrTypes})
	}

	// If API returns Enabled=false, it means "use default 4 days"
	// We don't expose this in state (return null) UNLESS plan had enabled=false
	if !browserCache.Enabled {
		tflog.Debug(ctx, "BrowserCacheSettings: API returned Enabled=false (use default)")

		// Check if plan had enabled=false (user wanted to disable caching)
		if planOptionsModel != nil && !planOptionsModel.BrowserCacheSettings.IsNull() && len(planOptionsModel.BrowserCacheSettings.Elements()) > 0 {
			var planBrowserSettings []BrowserCacheSettingsModel
			planDiags := planOptionsModel.BrowserCacheSettings.ElementsAs(ctx, &planBrowserSettings, false)
			if !planDiags.HasError() && len(planBrowserSettings) > 0 {
				planEnabled := planBrowserSettings[0].Enabled
				if !planEnabled.IsNull() && !planEnabled.IsUnknown() && !planEnabled.ValueBool() {
					// Plan had enabled=false, preserve it in state
					tflog.Debug(ctx, "BrowserCacheSettings: Plan had enabled=false, preserving in state")
					browserCacheModel := BrowserCacheSettingsModel{
						Enabled:   types.BoolValue(false),
						CacheTime: types.Int64Null(),
					}
					browserCacheList, d := types.ListValueFrom(ctx, types.ObjectType{
						AttrTypes: browserCacheAttrTypes,
					}, []BrowserCacheSettingsModel{browserCacheModel})
					diags.Append(d...)
					return browserCacheList
				}
			}
		}

		return types.ListNull(types.ObjectType{AttrTypes: browserCacheAttrTypes})
	}

	// Check if caching is disabled (cache_time=0)
	// This needs to be translated to user-facing enabled=false
	if browserCache.Value == 0 {
		tflog.Debug(ctx, "BrowserCacheSettings: API returned Value=0 (disabled), saving as enabled=false")
		browserCacheModel := BrowserCacheSettingsModel{
			Enabled:   types.BoolValue(false),
			CacheTime: types.Int64Null(),
		}
		browserCacheList, d := types.ListValueFrom(ctx, types.ObjectType{
			AttrTypes: browserCacheAttrTypes,
		}, []BrowserCacheSettingsModel{browserCacheModel})
		diags.Append(d...)
		return browserCacheList
	}

	// Caching is enabled with non-zero value
	browserCacheModel := BrowserCacheSettingsModel{
		Enabled:   types.BoolValue(true),
		CacheTime: types.Int64Value(browserCache.Value),
	}

	browserCacheList, d := types.ListValueFrom(ctx, types.ObjectType{
		AttrTypes: browserCacheAttrTypes,
	}, []BrowserCacheSettingsModel{browserCacheModel})
	diags.Append(d...)

	return browserCacheList
}

// flattenSSLCertificate converts API SSL certificate to Terraform state
func flattenSSLCertificate(ctx context.Context, cert *cdn.SSLCertificate, diags *diag.Diagnostics) types.List {
	if cert == nil {
		return types.ListNull(types.ObjectType{
			AttrTypes: map[string]attr.Type{
				"type":                   types.StringType,
				"status":                 types.StringType,
				"certificate_manager_id": types.StringType,
			},
		})
	}

	var certType string
	switch cert.Type {
	case cdn.SSLCertificateType_DONT_USE:
		certType = "not_used"
	case cdn.SSLCertificateType_CM:
		certType = "certificate_manager"
	case cdn.SSLCertificateType_LETS_ENCRYPT_GCORE:
		certType = "lets_encrypt"
	default:
		certType = "not_used"
	}

	var status string
	switch cert.Status {
	case cdn.SSLCertificateStatus_READY:
		status = "ready"
	case cdn.SSLCertificateStatus_CREATING:
		status = "creating"
	default:
		status = ""
	}

	// Get certificate manager ID if available
	var cmID string
	if cert.Data != nil && cert.Data.GetCm() != nil {
		cmID = cert.Data.GetCm().Id
	}

	certModel := SSLCertificateModel{
		Type:                 types.StringValue(certType),
		Status:               types.StringValue(status),
		CertificateManagerID: types.StringValue(cmID),
	}

	certList, d := types.ListValueFrom(ctx, types.ObjectType{
		AttrTypes: map[string]attr.Type{
			"type":                   types.StringType,
			"status":                 types.StringType,
			"certificate_manager_id": types.StringType,
		},
	}, []SSLCertificateModel{certModel})
	diags.Append(d...)

	return certList
}

// getCDNOptionsAttrTypes returns the attribute types for CDNOptionsModel
// This is used for creating types.List from CDNOptionsModel
// GetCDNOptionsAttrTypes returns the attribute types for CDNOptionsModel
// Exported for use by cdn_rule package
func GetCDNOptionsAttrTypes() map[string]attr.Type {
	return map[string]attr.Type{
		// Boolean options
		"ignore_query_params":        types.BoolType,
		"slice":                      types.BoolType,
		"fetched_compressed":         types.BoolType,
		"gzip_on":                    types.BoolType,
		"redirect_http_to_https":     types.BoolType,
		"redirect_https_to_http":     types.BoolType,
		"forward_host_header":        types.BoolType,
		"proxy_cache_methods_set":    types.BoolType,
		"disable_proxy_force_ranges": types.BoolType,
		"ignore_cookie":              types.BoolType,
		"enable_ip_url_signing":      types.BoolType,

		// Cache settings - nested blocks
		"edge_cache_settings": types.ListType{
			ElemType: types.ObjectType{
				AttrTypes: GetEdgeCacheSettingsAttrTypes(),
			},
		},
		"browser_cache_settings": types.ListType{
			ElemType: types.ObjectType{
				AttrTypes: map[string]attr.Type{
					"enabled":    types.BoolType,
					"cache_time": types.Int64Type,
				},
			},
		},

		// String options
		"custom_host_header": types.StringType,
		"custom_server_name": types.StringType,
		"secure_key":         types.StringType,

		// List options
		"cache_http_headers":     types.ListType{ElemType: types.StringType},
		"query_params_whitelist": types.ListType{ElemType: types.StringType},
		"query_params_blacklist": types.ListType{ElemType: types.StringType},
		"cors":                   types.ListType{ElemType: types.StringType},
		"allowed_http_methods":   types.ListType{ElemType: types.StringType},
		"stale":                  types.ListType{ElemType: types.StringType},

		// Map options
		"static_response_headers": types.MapType{ElemType: types.StringType},
		"static_request_headers":  types.MapType{ElemType: types.StringType},

		// Nested objects
		"ip_address_acl": types.ListType{
			ElemType: types.ObjectType{
				AttrTypes: map[string]attr.Type{
					"policy_type":     types.StringType,
					"excepted_values": types.ListType{ElemType: types.StringType},
				},
			},
		},
		"rewrite": types.ListType{
			ElemType: types.ObjectType{
				AttrTypes: map[string]attr.Type{
					"enabled": types.BoolType,
					"body":    types.StringType,
					"flag":    types.StringType,
				},
			},
		},

		// New options (go-genproto v0.57.0)
		"websockets":         types.BoolType,
		"brotli_compression": types.ListType{ElemType: types.StringType},
		"geo_acl": types.ListType{
			ElemType: types.ObjectType{
				AttrTypes: GetGeoACLAttrTypes(),
			},
		},
		"referrer_acl": types.ListType{
			ElemType: types.ObjectType{
				AttrTypes: GetReferrerACLAttrTypes(),
			},
		},
		"header_filter": types.ListType{
			ElemType: types.ObjectType{
				AttrTypes: GetHeaderFilterAttrTypes(),
			},
		},
		"follow_redirects": types.ListType{
			ElemType: types.ObjectType{
				AttrTypes: GetFollowRedirectsAttrTypes(),
			},
		},
		"static_response": types.ListType{
			ElemType: types.ObjectType{
				AttrTypes: GetStaticResponseAttrTypes(),
			},
		},
	}
}

func GetEdgeCacheSettingsAttrTypes() map[string]attr.Type {
	return map[string]attr.Type{
		"enabled":       types.BoolType,
		"value":         types.Int64Type,
		"custom_values": types.MapType{ElemType: types.Int64Type},
		"default_value": types.Int64Type,
	}
}

// flattenOriginProtocol converts CDN API OriginProtocol enum to string value
func flattenOriginProtocol(ctx context.Context, apiProtocol cdn.OriginProtocol, diags *diag.Diagnostics) types.String {
	switch apiProtocol {
	case cdn.OriginProtocol_HTTP:
		return types.StringValue("http")
	case cdn.OriginProtocol_HTTPS:
		return types.StringValue("https")
	case cdn.OriginProtocol_MATCH:
		return types.StringValue("match")
	default:
		diags.AddError(
			"Unexpected origin protocol",
			fmt.Sprintf("Got unexpected origin_protocol value from API: %v", apiProtocol),
		)
		return types.StringNull()
	}
}

// --- Attr type helpers for new nested blocks ---

func GetGeoACLAttrTypes() map[string]attr.Type {
	return map[string]attr.Type{
		"policy_type": types.StringType,
		"countries":   types.ListType{ElemType: types.StringType},
	}
}

func GetReferrerACLAttrTypes() map[string]attr.Type {
	return map[string]attr.Type{
		"policy_type": types.StringType,
		"referrers":   types.ListType{ElemType: types.StringType},
	}
}

func GetHeaderFilterAttrTypes() map[string]attr.Type {
	return map[string]attr.Type{
		"enabled": types.BoolType,
		"headers": types.ListType{ElemType: types.StringType},
	}
}

func GetFollowRedirectsAttrTypes() map[string]attr.Type {
	return map[string]attr.Type{
		"enabled":         types.BoolType,
		"codes":           types.ListType{ElemType: types.Int64Type},
		"use_custom_host": types.BoolType,
	}
}

func GetStaticResponseAttrTypes() map[string]attr.Type {
	return map[string]attr.Type{
		"enabled": types.BoolType,
		"code":    types.Int64Type,
		"content": types.StringType,
	}
}

// --- Flatten functions for new options ---

// flattenWebsocketsOption converts WebsocketsOption to types.Bool
func flattenWebsocketsOption(ws *cdn.ResourceOptions_WebsocketsOption) types.Bool {
	if ws == nil {
		return types.BoolNull()
	}
	return types.BoolValue(ws.Enabled)
}

// flattenTLSProfile converts TLS proto to Terraform string
func flattenTLSProfile(tls *cdn.TLS) types.String {
	if tls == nil || tls.Profile == cdn.TLS_PROFILE_UNSPECIFIED {
		return types.StringNull()
	}
	switch tls.Profile {
	case cdn.TLS_PROFILE_COMPATIBLE:
		return types.StringValue("compatible")
	case cdn.TLS_PROFILE_LEGACY:
		return types.StringValue("legacy")
	case cdn.TLS_PROFILE_SECURE:
		return types.StringValue("secure")
	case cdn.TLS_PROFILE_STRICT:
		return types.StringValue("strict")
	default:
		return types.StringNull()
	}
}

// flattenGeoACL converts API GeoACLOption to Terraform state
func flattenGeoACL(ctx context.Context, geoACL *cdn.ResourceOptions_GeoACLOption, opt *CDNOptionsModel, diags *diag.Diagnostics) {
	objType := types.ObjectType{AttrTypes: GetGeoACLAttrTypes()}

	if geoACL == nil || !geoACL.Enabled {
		opt.GeoACL = types.ListNull(objType)
		return
	}

	var policyType string
	switch geoACL.Mode {
	case cdn.ResourceOptions_GeoACLOption_MODE_ALLOW:
		policyType = "allow"
	case cdn.ResourceOptions_GeoACLOption_MODE_DENY:
		policyType = "deny"
	default:
		policyType = "allow"
	}

	countriesList, d := types.ListValueFrom(ctx, types.StringType, geoACL.Countries)
	diags.Append(d...)

	model := GeoACLModel{
		PolicyType: types.StringValue(policyType),
		Countries:  countriesList,
	}

	list, d := types.ListValueFrom(ctx, objType, []GeoACLModel{model})
	diags.Append(d...)
	opt.GeoACL = list
}

// flattenReferrerACL converts API ReferrerACLOption to Terraform state
func flattenReferrerACL(ctx context.Context, referrerACL *cdn.ResourceOptions_ReferrerACLOption, opt *CDNOptionsModel, diags *diag.Diagnostics) {
	objType := types.ObjectType{AttrTypes: GetReferrerACLAttrTypes()}

	if referrerACL == nil || !referrerACL.Enabled {
		opt.ReferrerACL = types.ListNull(objType)
		return
	}

	var policyType string
	switch referrerACL.Mode {
	case cdn.ResourceOptions_ReferrerACLOption_MODE_ALLOW:
		policyType = "allow"
	case cdn.ResourceOptions_ReferrerACLOption_MODE_DENY:
		policyType = "deny"
	default:
		policyType = "allow"
	}

	referrersList, d := types.ListValueFrom(ctx, types.StringType, referrerACL.Referrers)
	diags.Append(d...)

	model := ReferrerACLModel{
		PolicyType: types.StringValue(policyType),
		Referrers:  referrersList,
	}

	list, d := types.ListValueFrom(ctx, objType, []ReferrerACLModel{model})
	diags.Append(d...)
	opt.ReferrerACL = list
}

// flattenHeaderFilter converts API HeaderFilterOption to Terraform state
// planOptionsModel: optional plan options to preserve explicitly disabled blocks
func flattenHeaderFilter(ctx context.Context, hf *cdn.ResourceOptions_HeaderFilterOption, opt *CDNOptionsModel, planOptionsModel *CDNOptionsModel, diags *diag.Diagnostics) {
	objType := types.ObjectType{AttrTypes: GetHeaderFilterAttrTypes()}

	if hf == nil || !hf.Enabled {
		// If plan contains an explicit header_filter block (e.g. enabled=false), preserve it.
		// Copy the plan block verbatim — it has the user's real values (headers list)
		// which must match state to avoid "inconsistent result" errors.
		if planOptionsModel != nil && !planOptionsModel.HeaderFilter.IsNull() &&
			len(planOptionsModel.HeaderFilter.Elements()) > 0 {
			opt.HeaderFilter = planOptionsModel.HeaderFilter
			return
		}
		opt.HeaderFilter = types.ListNull(objType)
		return
	}

	headersList, d := types.ListValueFrom(ctx, types.StringType, hf.Headers)
	diags.Append(d...)

	model := HeaderFilterModel{
		Enabled: types.BoolValue(hf.Enabled),
		Headers: headersList,
	}

	list, d := types.ListValueFrom(ctx, objType, []HeaderFilterModel{model})
	diags.Append(d...)
	opt.HeaderFilter = list
}

// flattenFollowRedirects converts API FollowRedirectsOption to Terraform state
// planOptionsModel: optional plan options to preserve explicitly disabled blocks
func flattenFollowRedirects(ctx context.Context, fr *cdn.ResourceOptions_FollowRedirectsOption, opt *CDNOptionsModel, planOptionsModel *CDNOptionsModel, diags *diag.Diagnostics) {
	objType := types.ObjectType{AttrTypes: GetFollowRedirectsAttrTypes()}

	if fr == nil || !fr.Enabled {
		// If plan contains an explicit follow_redirects block (e.g. enabled=false), preserve it.
		// Copy the plan block verbatim to avoid "inconsistent result" errors.
		if planOptionsModel != nil && !planOptionsModel.FollowRedirects.IsNull() &&
			len(planOptionsModel.FollowRedirects.Elements()) > 0 {
			opt.FollowRedirects = planOptionsModel.FollowRedirects
			return
		}
		opt.FollowRedirects = types.ListNull(objType)
		return
	}

	var codesList types.List
	if len(fr.Codes) > 0 {
		var d diag.Diagnostics
		codesList, d = types.ListValueFrom(ctx, types.Int64Type, fr.Codes)
		diags.Append(d...)
	} else {
		codesList = types.ListNull(types.Int64Type)
	}

	model := FollowRedirectsModel{
		Enabled:       types.BoolValue(fr.Enabled),
		Codes:         codesList,
		UseCustomHost: types.BoolValue(fr.UseCustomHost),
	}

	list, d := types.ListValueFrom(ctx, objType, []FollowRedirectsModel{model})
	diags.Append(d...)
	opt.FollowRedirects = list
}

// flattenStaticResponse converts API StaticResponseOption to Terraform state
// planOptionsModel: optional plan options to preserve explicitly disabled blocks
func flattenStaticResponse(ctx context.Context, sr *cdn.ResourceOptions_StaticResponseOption, opt *CDNOptionsModel, planOptionsModel *CDNOptionsModel, diags *diag.Diagnostics) {
	objType := types.ObjectType{AttrTypes: GetStaticResponseAttrTypes()}

	if sr == nil || !sr.Enabled {
		// If plan contains an explicit static_response block (e.g. enabled=false), preserve it.
		// Copy the plan block verbatim — it has the user's real values (code, content)
		// which must match state to avoid "inconsistent result" errors.
		if planOptionsModel != nil && !planOptionsModel.StaticResponseOpt.IsNull() &&
			len(planOptionsModel.StaticResponseOpt.Elements()) > 0 {
			opt.StaticResponseOpt = planOptionsModel.StaticResponseOpt
			return
		}
		opt.StaticResponseOpt = types.ListNull(objType)
		return
	}

	model := StaticResponseModel{
		Enabled: types.BoolValue(sr.Enabled),
		Code:    types.Int64Value(sr.Code),
		Content: types.StringValue(sr.Content),
	}

	list, d := types.ListValueFrom(ctx, objType, []StaticResponseModel{model})
	diags.Append(d...)
	opt.StaticResponseOpt = list
}
