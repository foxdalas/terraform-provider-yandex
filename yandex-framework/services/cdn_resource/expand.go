package cdn_resource

import (
	"context"
	"fmt"

	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"
	"github.com/yandex-cloud/go-genproto/yandex/cloud/cdn/v1"
)

// Helper functions for expand operations to reduce code duplication

// expandBoolOptionIfSet creates BoolOption if the value is not null
func expandBoolOptionIfSet(value types.Bool) *cdn.ResourceOptions_BoolOption {
	if value.IsNull() {
		return nil
	}
	return &cdn.ResourceOptions_BoolOption{
		Enabled: true,
		Value:   value.ValueBool(),
	}
}

// expandStringsListOption creates StringsListOption from a Terraform list
// - null or empty list: returns Enabled: false to explicitly disable/clear the option
// - list with values: returns Enabled: true with the values
func expandStringsListOption(ctx context.Context, list types.List, diags *diag.Diagnostics) *cdn.ResourceOptions_StringsListOption {
	// Both null AND empty list mean "disable/clear the option"
	// Send Enabled: false to explicitly disable
	if list.IsNull() || len(list.Elements()) == 0 {
		return &cdn.ResourceOptions_StringsListOption{
			Enabled: false,
		}
	}

	var values []string
	diags.Append(list.ElementsAs(ctx, &values, false)...)
	if diags.HasError() || len(values) == 0 {
		return &cdn.ResourceOptions_StringsListOption{
			Enabled: false,
		}
	}

	return &cdn.ResourceOptions_StringsListOption{
		Enabled: true,
		Value:   values,
	}
}

// expandStringsMapOption creates StringsMapOption from a Terraform map
// - null or empty map: returns Enabled: false to explicitly disable/clear headers
// - map with values: returns Enabled: true with the values
func expandStringsMapOption(ctx context.Context, m types.Map, diags *diag.Diagnostics) *cdn.ResourceOptions_StringsMapOption {
	// Both null AND empty map mean "disable/clear headers"
	// Send Enabled: false to explicitly disable the option
	if m.IsNull() || len(m.Elements()) == 0 {
		return &cdn.ResourceOptions_StringsMapOption{
			Enabled: false,
		}
	}

	values := make(map[string]string)
	diags.Append(m.ElementsAs(ctx, &values, false)...)
	if diags.HasError() || len(values) == 0 {
		return &cdn.ResourceOptions_StringsMapOption{
			Enabled: false,
		}
	}

	return &cdn.ResourceOptions_StringsMapOption{
		Enabled: true,
		Value:   values,
	}
}

// ExpandCDNResourceOptions converts Terraform plan options to CDN API ResourceOptions
// CRITICAL: This function properly handles tristate booleans using types.Bool.IsNull()
// Exported for reuse in cdn_rule package
func ExpandCDNResourceOptions(ctx context.Context, planOptions []CDNOptionsModel, diags *diag.Diagnostics) *cdn.ResourceOptions {
	if len(planOptions) == 0 {
		return nil
	}

	opt := planOptions[0]
	result := &cdn.ResourceOptions{}

	// Boolean options - using helper to reduce duplication
	result.Slice = expandBoolOptionIfSet(opt.Slice)
	result.IgnoreCookie = expandBoolOptionIfSet(opt.IgnoreCookie)
	result.ProxyCacheMethodsSet = expandBoolOptionIfSet(opt.ProxyCacheMethodsSet)

	if !opt.DisableProxyForceRanges.IsNull() && opt.DisableProxyForceRanges.ValueBool() {
		result.DisableProxyForceRanges = &cdn.ResourceOptions_BoolOption{
			Enabled: true,
			Value:   true,
		}
	} else {
		result.DisableProxyForceRanges = nil
	}

	// Cache settings - nested blocks
	expandEdgeCacheSettings(ctx, opt.EdgeCacheSettings, result, diags)
	expandBrowserCacheSettings(ctx, opt.BrowserCacheSettings, result, diags)

	// String options
	if !opt.CustomServerName.IsNull() && opt.CustomServerName.ValueString() != "" {
		result.CustomServerName = &cdn.ResourceOptions_StringOption{
			Enabled: true,
			Value:   opt.CustomServerName.ValueString(),
		}
	}

	// SecureKey - combines secure_key and enable_ip_url_signing
	if !opt.SecureKey.IsNull() && opt.SecureKey.ValueString() != "" {
		urlType := cdn.SecureKeyURLType_DISABLE_IP_SIGNING
		if !opt.EnableIPURLSigning.IsNull() && opt.EnableIPURLSigning.ValueBool() {
			urlType = cdn.SecureKeyURLType_ENABLE_IP_SIGNING
		}

		result.SecureKey = &cdn.ResourceOptions_SecureKeyOption{
			Enabled: true,
			Key:     opt.SecureKey.ValueString(),
			Type:    urlType,
		}
	}

	// List options - using helper to reduce duplication
	// DEPRECATED: cache_http_headers - removed as it does not affect anything
	// Kept in schema for backward compatibility, but not sent to API
	result.Cors = expandStringsListOption(ctx, opt.Cors, diags)
	result.AllowedHttpMethods = expandStringsListOption(ctx, opt.AllowedHTTPMethods, diags)
	result.Stale = expandStringsListOption(ctx, opt.Stale, diags)

	// Map options - using helper to reduce duplication
	result.StaticHeaders = expandStringsMapOption(ctx, opt.StaticResponseHeaders, diags)
	result.StaticRequestHeaders = expandStringsMapOption(ctx, opt.StaticRequestHeaders, diags)

	// Mutually exclusive options groups
	expandHostOptions(&opt, result, diags)
	expandQueryParamsOptions(ctx, &opt, result, diags)
	expandCompressionOptions(&opt, result, diags)
	expandRedirectOptions(&opt, result, diags)

	// Nested blocks
	expandIPAddressACL(ctx, opt.IPAddressACL, result, diags)
	expandRewrite(ctx, opt.Rewrite, result, diags)

	// New options (go-genproto v0.57.0)
	result.Websockets = expandWebsocketsOption(opt.Websockets)
	expandGeoACL(ctx, opt.GeoACL, result, diags)
	expandReferrerACL(ctx, opt.ReferrerACL, result, diags)
	expandHeaderFilter(ctx, opt.HeaderFilter, result, diags)
	expandFollowRedirects(ctx, opt.FollowRedirects, result, diags)
	expandStaticResponse(ctx, opt.StaticResponseOpt, result, diags)

	return result
}

// expandHostOptions handles mutually exclusive forward_host_header and custom_host_header
// CRITICAL FIX: This properly handles forward_host_header tristate using IsNull()
func expandHostOptions(opt *CDNOptionsModel, result *cdn.ResourceOptions, diags *diag.Diagnostics) {
	// custom_host_header takes precedence over forward_host_header
	if !opt.CustomHostHeader.IsNull() && opt.CustomHostHeader.ValueString() != "" {
		result.HostOptions = &cdn.ResourceOptions_HostOptions{
			HostVariant: &cdn.ResourceOptions_HostOptions_Host{
				Host: &cdn.ResourceOptions_StringOption{
					Enabled: true,
					Value:   opt.CustomHostHeader.ValueString(),
				},
			},
		}
	} else if !opt.ForwardHostHeader.IsNull() {
		// CRITICAL: This is the fix for the forward_host_header bug
		// In SDKv2, GetOk couldn't distinguish between "not set" and "false"
		// In Framework, IsNull() perfectly handles this:
		//   - IsNull() == true  → user didn't set it, don't send to API
		//   - IsNull() == false → user set it (true or false), send Enabled=true
		result.HostOptions = &cdn.ResourceOptions_HostOptions{
			HostVariant: &cdn.ResourceOptions_HostOptions_ForwardHostHeader{
				ForwardHostHeader: &cdn.ResourceOptions_BoolOption{
					Enabled: true,
					Value:   opt.ForwardHostHeader.ValueBool(),
				},
			},
		}
	}
}

// expandQueryParamsOptions handles mutually exclusive query params options
// Priority: explicit list (whitelist/blacklist) > boolean (ignore)
// This handles UseStateForUnknown copying stale boolean values from state
func expandQueryParamsOptions(ctx context.Context, opt *CDNOptionsModel, result *cdn.ResourceOptions, diags *diag.Diagnostics) {
	// 1st priority: Whitelist - user explicitly set a list of params to consider
	if !opt.QueryParamsWhitelist.IsNull() && len(opt.QueryParamsWhitelist.Elements()) > 0 {
		var params []string
		diags.Append(opt.QueryParamsWhitelist.ElementsAs(ctx, &params, false)...)
		if !diags.HasError() && len(params) > 0 {
			result.QueryParamsOptions = &cdn.ResourceOptions_QueryParamsOptions{
				QueryParamsVariant: &cdn.ResourceOptions_QueryParamsOptions_QueryParamsWhitelist{
					QueryParamsWhitelist: &cdn.ResourceOptions_StringsListOption{
						Enabled: true,
						Value:   params,
					},
				},
			}
		}
		return
	}

	// 2nd priority: Blacklist - user explicitly set a list of params to ignore
	if !opt.QueryParamsBlacklist.IsNull() && len(opt.QueryParamsBlacklist.Elements()) > 0 {
		var params []string
		diags.Append(opt.QueryParamsBlacklist.ElementsAs(ctx, &params, false)...)
		if !diags.HasError() && len(params) > 0 {
			result.QueryParamsOptions = &cdn.ResourceOptions_QueryParamsOptions{
				QueryParamsVariant: &cdn.ResourceOptions_QueryParamsOptions_QueryParamsBlacklist{
					QueryParamsBlacklist: &cdn.ResourceOptions_StringsListOption{
						Enabled: true,
						Value:   params,
					},
				},
			}
		}
		return
	}

	// 3rd priority: IgnoreQueryString
	if !opt.IgnoreQueryParams.IsNull() {
		result.QueryParamsOptions = &cdn.ResourceOptions_QueryParamsOptions{
			QueryParamsVariant: &cdn.ResourceOptions_QueryParamsOptions_IgnoreQueryString{
				IgnoreQueryString: &cdn.ResourceOptions_BoolOption{
					Enabled: true,
					Value:   opt.IgnoreQueryParams.ValueBool(),
				},
			},
		}
	}
}

// expandCompressionOptions handles mutually exclusive gzip_on, fetched_compressed, and brotli_compression
// For oneof fields, only sends option when value is true/non-empty
// Priority: fetched_compressed=true > brotli_compression (non-empty) > gzip_on=true
// false/null values are NOT sent (for oneof, false means "don't select this variant")
func expandCompressionOptions(opt *CDNOptionsModel, result *cdn.ResourceOptions, diags *diag.Diagnostics) {
	// Check if values are explicitly set to true
	fetchedTrue := !opt.FetchedCompressed.IsNull() && opt.FetchedCompressed.ValueBool()
	brotliSet := !opt.BrotliCompression.IsNull() && len(opt.BrotliCompression.Elements()) > 0
	gzipTrue := !opt.GzipOn.IsNull() && opt.GzipOn.ValueBool()

	if fetchedTrue {
		// Priority 1: fetched_compressed=true
		result.CompressionOptions = &cdn.ResourceOptions_CompressionOptions{
			CompressionVariant: &cdn.ResourceOptions_CompressionOptions_FetchCompressed{
				FetchCompressed: &cdn.ResourceOptions_BoolOption{
					Enabled: true,
					Value:   true,
				},
			},
		}
	} else if brotliSet {
		// Priority 2: brotli_compression with content-types
		var contentTypes []string
		d := opt.BrotliCompression.ElementsAs(context.Background(), &contentTypes, false)
		diags.Append(d...)
		if !diags.HasError() && len(contentTypes) > 0 {
			result.CompressionOptions = &cdn.ResourceOptions_CompressionOptions{
				CompressionVariant: &cdn.ResourceOptions_CompressionOptions_BrotliCompression{
					BrotliCompression: &cdn.ResourceOptions_StringsListOption{
						Enabled: true,
						Value:   contentTypes,
					},
				},
			}
		}
	} else if gzipTrue {
		// Priority 3: gzip_on=true
		result.CompressionOptions = &cdn.ResourceOptions_CompressionOptions{
			CompressionVariant: &cdn.ResourceOptions_CompressionOptions_GzipOn{
				GzipOn: &cdn.ResourceOptions_BoolOption{
					Enabled: true,
					Value:   true,
				},
			},
		}
	}
	// If all false/null → don't send (API uses defaults)
}

// expandRedirectOptions handles mutually exclusive redirect options
// For oneof fields, sends option when explicitly set (non-null) with actual value
// Unlike compression, redirect supports both true and false values being sent
// Priority: redirect_http_to_https > redirect_https_to_http
func expandRedirectOptions(opt *CDNOptionsModel, result *cdn.ResourceOptions, diags *diag.Diagnostics) {
	if !opt.RedirectHttpToHttps.IsNull() {
		result.RedirectOptions = &cdn.ResourceOptions_RedirectOptions{
			RedirectVariant: &cdn.ResourceOptions_RedirectOptions_RedirectHttpToHttps{
				RedirectHttpToHttps: &cdn.ResourceOptions_BoolOption{
					Enabled: true,
					Value:   opt.RedirectHttpToHttps.ValueBool(),
				},
			},
		}
	} else if !opt.RedirectHttpsToHttp.IsNull() {
		result.RedirectOptions = &cdn.ResourceOptions_RedirectOptions{
			RedirectVariant: &cdn.ResourceOptions_RedirectOptions_RedirectHttpsToHttp{
				RedirectHttpsToHttp: &cdn.ResourceOptions_BoolOption{
					Enabled: true,
					Value:   opt.RedirectHttpsToHttp.ValueBool(),
				},
			},
		}
	}
}

// expandIPAddressACL converts IP address ACL block to API format
func expandIPAddressACL(ctx context.Context, aclList types.List, result *cdn.ResourceOptions, diags *diag.Diagnostics) {
	if aclList.IsNull() || len(aclList.Elements()) == 0 {
		return
	}

	var aclModels []IPAddressACLModel
	diags.Append(aclList.ElementsAs(ctx, &aclModels, false)...)
	if diags.HasError() || len(aclModels) == 0 {
		return
	}

	acl := aclModels[0]
	if acl.ExceptedValues.IsNull() {
		return
	}

	var exceptedValues []string
	diags.Append(acl.ExceptedValues.ElementsAs(ctx, &exceptedValues, false)...)
	if diags.HasError() {
		return
	}

	var policyType cdn.PolicyType
	switch acl.PolicyType.ValueString() {
	case "allow":
		policyType = cdn.PolicyType_POLICY_TYPE_ALLOW
	case "deny":
		policyType = cdn.PolicyType_POLICY_TYPE_DENY
	default:
		diags.AddError(
			"Invalid ACL policy type",
			fmt.Sprintf("policy_type must be 'allow' or 'deny', got: %s", acl.PolicyType.ValueString()),
		)
		return
	}

	result.IpAddressAcl = &cdn.ResourceOptions_IPAddressACLOption{
		Enabled:        true,
		PolicyType:     policyType,
		ExceptedValues: exceptedValues,
	}
}

// expandRewrite converts rewrite block to API format
func expandRewrite(ctx context.Context, rewriteList types.List, result *cdn.ResourceOptions, diags *diag.Diagnostics) {
	if rewriteList.IsNull() || len(rewriteList.Elements()) == 0 {
		return
	}

	var rewriteModels []RewriteModel
	diags.Append(rewriteList.ElementsAs(ctx, &rewriteModels, false)...)
	if diags.HasError() || len(rewriteModels) == 0 {
		return
	}

	rewrite := rewriteModels[0]

	// Determine rewrite flag
	var flag cdn.RewriteFlag
	flagStr := "break" // default
	if !rewrite.Flag.IsNull() && rewrite.Flag.ValueString() != "" {
		flagStr = rewrite.Flag.ValueString()
	}

	switch flagStr {
	case "last":
		flag = cdn.RewriteFlag_LAST
	case "break":
		flag = cdn.RewriteFlag_BREAK
	case "redirect":
		flag = cdn.RewriteFlag_REDIRECT
	case "permanent":
		flag = cdn.RewriteFlag_PERMANENT
	default:
		diags.AddError(
			"Invalid rewrite flag",
			fmt.Sprintf("flag must be one of: last, break, redirect, permanent, got: %s", flagStr),
		)
		return
	}

	// Determine enabled status
	enabled := false
	if !rewrite.Enabled.IsNull() {
		enabled = rewrite.Enabled.ValueBool()
	}

	result.Rewrite = &cdn.ResourceOptions_RewriteOption{
		Enabled: enabled,
		Body:    rewrite.Body.ValueString(),
		Flag:    flag,
	}
}

// expandEdgeCacheSettings converts edge_cache_settings block to API format
// Matches master expandCDNResourceOptions_EdgeCacheSettings logic:
// - value → SimpleValue (cache 200, 206, 301, 302 ONLY)
// - custom_values → CustomValues (per-code overrides, "any" = all codes)
// - Both can be specified, CustomValues has higher priority
func expandEdgeCacheSettings(ctx context.Context, edgeCacheList types.List, result *cdn.ResourceOptions, diags *diag.Diagnostics) {
	if edgeCacheList.IsNull() || len(edgeCacheList.Elements()) == 0 {
		return
	}

	var edgeCacheModels []EdgeCacheSettingsModel
	diags.Append(edgeCacheList.ElementsAs(ctx, &edgeCacheModels, true)...)
	if diags.HasError() || len(edgeCacheModels) == 0 {
		return
	}

	edgeCache := edgeCacheModels[0]

	// Determine enabled status (defaults to true if not set)
	enabled := true
	if !edgeCache.Enabled.IsNull() {
		enabled = edgeCache.Enabled.ValueBool()
	}

	// If user set enabled=false, they want to DISABLE caching
	// API way to disable: send cache_time=0
	if !enabled {
		tflog.Debug(ctx, "EdgeCacheSettings: User set enabled=false, translating to cache_time=0 for API")
		result.EdgeCacheSettings = &cdn.ResourceOptions_EdgeCacheSettings{
			Enabled: true, // API requires true to apply our value
			ValuesVariant: &cdn.ResourceOptions_EdgeCacheSettings_DefaultValue{
				DefaultValue: 0, // 0 = disable caching per proto spec
			},
		}
		return
	}

	// enabled=true, process value and/or custom_values
	hasValue := !edgeCache.Value.IsNull()
	hasCustomValues := !edgeCache.CustomValues.IsNull() && len(edgeCache.CustomValues.Elements()) > 0
	hasDefaultValue := !edgeCache.DefaultValue.IsNull() && !edgeCache.DefaultValue.IsUnknown()

	if hasDefaultValue {
		result.EdgeCacheSettings = &cdn.ResourceOptions_EdgeCacheSettings{
			Enabled: true,
			ValuesVariant: &cdn.ResourceOptions_EdgeCacheSettings_DefaultValue{
				DefaultValue: edgeCache.DefaultValue.ValueInt64(),
			},
		}
		return
	}

	if !hasValue && !hasCustomValues {
		// Neither value nor custom_values specified - don't send anything
		return
	}

	// NEW API from master (commit 042b2e91):
	// Use CachingTimes with SimpleValue and/or CustomValues
	cachingTimes := &cdn.ResourceOptions_CachingTimes{}

	if hasValue {
		cachingTimes.SimpleValue = edgeCache.Value.ValueInt64()
	}

	if hasCustomValues {
		customValues := make(map[string]int64)
		diags.Append(edgeCache.CustomValues.ElementsAs(ctx, &customValues, false)...)
		if !diags.HasError() {
			cachingTimes.CustomValues = customValues
		}
	}

	result.EdgeCacheSettings = &cdn.ResourceOptions_EdgeCacheSettings{
		Enabled: true,
		ValuesVariant: &cdn.ResourceOptions_EdgeCacheSettings_Value{
			Value: cachingTimes,
		},
	}
}

// expandBrowserCacheSettings converts browser_cache_settings block to API format
func expandBrowserCacheSettings(ctx context.Context, browserCacheList types.List, result *cdn.ResourceOptions, diags *diag.Diagnostics) {
	if browserCacheList.IsNull() || len(browserCacheList.Elements()) == 0 {
		return
	}

	var browserCacheModels []BrowserCacheSettingsModel
	diags.Append(browserCacheList.ElementsAs(ctx, &browserCacheModels, false)...)
	if diags.HasError() || len(browserCacheModels) == 0 {
		return
	}

	browserCache := browserCacheModels[0]

	// CRITICAL: Same semantics as EdgeCacheSettings
	// User-facing: enabled=false means "disable caching"
	// API-facing: Enabled=true + Value=0 means "disable caching"

	// Determine enabled status (defaults to true if not set)
	enabled := true
	if !browserCache.Enabled.IsNull() {
		enabled = browserCache.Enabled.ValueBool()
	}

	// If user set enabled=false, they want to DISABLE caching
	// API way to disable: send cache_time=0
	if !enabled {
		tflog.Debug(ctx, "BrowserCacheSettings: User set enabled=false, translating to cache_time=0 for API")
		result.BrowserCacheSettings = &cdn.ResourceOptions_Int64Option{
			Enabled: true, // API requires true to apply our value
			Value:   0,    // 0 = disable caching per proto spec
		}
		return
	}

	// enabled=true, process cache_time
	if browserCache.CacheTime.IsNull() {
		// This should not happen due to validator, but handle gracefully
		return
	}

	result.BrowserCacheSettings = &cdn.ResourceOptions_Int64Option{
		Enabled: true,
		Value:   browserCache.CacheTime.ValueInt64(),
	}
}

// expandOriginProtocol converts string protocol value to CDN API OriginProtocol enum
func expandOriginProtocol(ctx context.Context, protocolValue string, diags *diag.Diagnostics) cdn.OriginProtocol {
	switch protocolValue {
	case "http":
		return cdn.OriginProtocol_HTTP
	case "https":
		return cdn.OriginProtocol_HTTPS
	case "match":
		return cdn.OriginProtocol_MATCH
	default:
		diags.AddError(
			"Invalid origin_protocol value",
			fmt.Sprintf("origin_protocol must be 'http', 'https', or 'match', got: %s", protocolValue),
		)
		return cdn.OriginProtocol_ORIGIN_PROTOCOL_UNSPECIFIED
	}
}

// expandWebsocketsOption converts Terraform bool to WebsocketsOption
func expandWebsocketsOption(value types.Bool) *cdn.ResourceOptions_WebsocketsOption {
	if value.IsNull() {
		return nil
	}
	return &cdn.ResourceOptions_WebsocketsOption{
		Enabled: value.ValueBool(),
	}
}

// expandTLSProfile converts Terraform string to TLS proto struct
func expandTLSProfile(value types.String) *cdn.TLS {
	if value.IsNull() || value.ValueString() == "" {
		return nil
	}
	var profile cdn.TLS_Profile
	switch value.ValueString() {
	case "compatible":
		profile = cdn.TLS_PROFILE_COMPATIBLE
	case "legacy":
		profile = cdn.TLS_PROFILE_LEGACY
	case "secure":
		profile = cdn.TLS_PROFILE_SECURE
	case "strict":
		profile = cdn.TLS_PROFILE_STRICT
	default:
		return nil
	}
	return &cdn.TLS{Profile: profile}
}

// expandGeoACL converts geo_acl block to API format
func expandGeoACL(ctx context.Context, geoACLList types.List, result *cdn.ResourceOptions, diags *diag.Diagnostics) {
	if geoACLList.IsNull() || len(geoACLList.Elements()) == 0 {
		return
	}

	var models []GeoACLModel
	diags.Append(geoACLList.ElementsAs(ctx, &models, false)...)
	if diags.HasError() || len(models) == 0 {
		return
	}

	m := models[0]
	var countries []string
	diags.Append(m.Countries.ElementsAs(ctx, &countries, false)...)
	if diags.HasError() {
		return
	}

	var mode cdn.ResourceOptions_GeoACLOption_Mode
	switch m.PolicyType.ValueString() {
	case "allow":
		mode = cdn.ResourceOptions_GeoACLOption_MODE_ALLOW
	case "deny":
		mode = cdn.ResourceOptions_GeoACLOption_MODE_DENY
	default:
		diags.AddError("Invalid geo_acl policy_type",
			fmt.Sprintf("policy_type must be 'allow' or 'deny', got: %s", m.PolicyType.ValueString()))
		return
	}

	result.GeoAcl = &cdn.ResourceOptions_GeoACLOption{
		Enabled:   true,
		Mode:      mode,
		Countries: countries,
	}
}

// expandReferrerACL converts referrer_acl block to API format
func expandReferrerACL(ctx context.Context, referrerACLList types.List, result *cdn.ResourceOptions, diags *diag.Diagnostics) {
	if referrerACLList.IsNull() || len(referrerACLList.Elements()) == 0 {
		return
	}

	var models []ReferrerACLModel
	diags.Append(referrerACLList.ElementsAs(ctx, &models, false)...)
	if diags.HasError() || len(models) == 0 {
		return
	}

	m := models[0]
	var referrers []string
	diags.Append(m.Referrers.ElementsAs(ctx, &referrers, false)...)
	if diags.HasError() {
		return
	}

	var mode cdn.ResourceOptions_ReferrerACLOption_Mode
	switch m.PolicyType.ValueString() {
	case "allow":
		mode = cdn.ResourceOptions_ReferrerACLOption_MODE_ALLOW
	case "deny":
		mode = cdn.ResourceOptions_ReferrerACLOption_MODE_DENY
	default:
		diags.AddError("Invalid referrer_acl policy_type",
			fmt.Sprintf("policy_type must be 'allow' or 'deny', got: %s", m.PolicyType.ValueString()))
		return
	}

	result.ReferrerAcl = &cdn.ResourceOptions_ReferrerACLOption{
		Enabled:   true,
		Mode:      mode,
		Referrers: referrers,
	}
}

// expandHeaderFilter converts header_filter block to API format
func expandHeaderFilter(ctx context.Context, headerFilterList types.List, result *cdn.ResourceOptions, diags *diag.Diagnostics) {
	if headerFilterList.IsNull() || len(headerFilterList.Elements()) == 0 {
		return
	}

	var models []HeaderFilterModel
	diags.Append(headerFilterList.ElementsAs(ctx, &models, false)...)
	if diags.HasError() || len(models) == 0 {
		return
	}

	m := models[0]

	enabled := true
	if !m.Enabled.IsNull() {
		enabled = m.Enabled.ValueBool()
	}

	var headers []string
	if !m.Headers.IsNull() && len(m.Headers.Elements()) > 0 {
		diags.Append(m.Headers.ElementsAs(ctx, &headers, false)...)
		if diags.HasError() {
			return
		}
	}

	result.HeaderFilter = &cdn.ResourceOptions_HeaderFilterOption{
		Enabled: enabled,
		Headers: headers,
	}
}

// expandFollowRedirects converts follow_redirects block to API format
func expandFollowRedirects(ctx context.Context, followRedirectsList types.List, result *cdn.ResourceOptions, diags *diag.Diagnostics) {
	if followRedirectsList.IsNull() || len(followRedirectsList.Elements()) == 0 {
		return
	}

	var models []FollowRedirectsModel
	diags.Append(followRedirectsList.ElementsAs(ctx, &models, false)...)
	if diags.HasError() || len(models) == 0 {
		return
	}

	m := models[0]
	enabled := true
	if !m.Enabled.IsNull() {
		enabled = m.Enabled.ValueBool()
	}

	var codes []int64
	if !m.Codes.IsNull() && len(m.Codes.Elements()) > 0 {
		diags.Append(m.Codes.ElementsAs(ctx, &codes, false)...)
		if diags.HasError() {
			return
		}
	}

	useCustomHost := false
	if !m.UseCustomHost.IsNull() {
		useCustomHost = m.UseCustomHost.ValueBool()
	}

	result.FollowRedirects = &cdn.ResourceOptions_FollowRedirectsOption{
		Enabled:       enabled,
		Codes:         codes,
		UseCustomHost: useCustomHost,
	}
}

// expandStaticResponse converts static_response block to API format
func expandStaticResponse(ctx context.Context, staticResponseList types.List, result *cdn.ResourceOptions, diags *diag.Diagnostics) {
	if staticResponseList.IsNull() || len(staticResponseList.Elements()) == 0 {
		return
	}

	var models []StaticResponseModel
	diags.Append(staticResponseList.ElementsAs(ctx, &models, false)...)
	if diags.HasError() || len(models) == 0 {
		return
	}

	m := models[0]
	enabled := true
	if !m.Enabled.IsNull() {
		enabled = m.Enabled.ValueBool()
	}

	result.StaticResponse = &cdn.ResourceOptions_StaticResponseOption{
		Enabled: enabled,
		Code:    m.Code.ValueInt64(),
		Content: m.Content.ValueString(),
	}
}
