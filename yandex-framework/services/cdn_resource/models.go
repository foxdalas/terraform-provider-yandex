package cdn_resource

import (
	"github.com/hashicorp/terraform-plugin-framework-timeouts/resource/timeouts"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

// CDNResourceModel represents the Terraform resource model for yandex_cdn_resource
type CDNResourceModel struct {
	Timeouts           timeouts.Value `tfsdk:"timeouts"`
	ID                 types.String   `tfsdk:"id"`
	Cname              types.String   `tfsdk:"cname"`
	ProviderType       types.String   `tfsdk:"provider_type"`
	FolderID           types.String   `tfsdk:"folder_id"`
	Labels             types.Map      `tfsdk:"labels"`
	Active             types.Bool     `tfsdk:"active"`
	SecondaryHostnames types.Set      `tfsdk:"secondary_hostnames"`
	OriginProtocol     types.String   `tfsdk:"origin_protocol"`
	CreatedAt          types.String   `tfsdk:"created_at"`
	UpdatedAt          types.String   `tfsdk:"updated_at"`
	OriginGroupID      types.String   `tfsdk:"origin_group_id"`
	OriginGroupName    types.String   `tfsdk:"origin_group_name"`
	Shielding          types.String   `tfsdk:"shielding"`
	SSLCertificate     types.List     `tfsdk:"ssl_certificate"`
	ProviderCname      types.String   `tfsdk:"provider_cname"`
	TLSProfile         types.String   `tfsdk:"tls_profile"`
	Options            types.List     `tfsdk:"options"`
}

// CDNResourceDataSource represents the Terraform data source model for yandex_cdn_resource
type CDNResourceDataSource struct {
	ID                 types.String `tfsdk:"id"`
	ResourceID         types.String `tfsdk:"resource_id"`
	Cname              types.String `tfsdk:"cname"`
	ProviderType       types.String `tfsdk:"provider_type"`
	FolderID           types.String `tfsdk:"folder_id"`
	Labels             types.Map    `tfsdk:"labels"`
	Active             types.Bool   `tfsdk:"active"`
	SecondaryHostnames types.Set    `tfsdk:"secondary_hostnames"`
	OriginProtocol     types.String `tfsdk:"origin_protocol"`
	CreatedAt          types.String `tfsdk:"created_at"`
	UpdatedAt          types.String `tfsdk:"updated_at"`
	OriginGroupID      types.String `tfsdk:"origin_group_id"`
	OriginGroupName    types.String `tfsdk:"origin_group_name"`
	Shielding          types.String `tfsdk:"shielding"`
	SSLCertificate     types.List   `tfsdk:"ssl_certificate"`
	ProviderCname      types.String `tfsdk:"provider_cname"`
	TLSProfile         types.String `tfsdk:"tls_profile"`
	Options            types.List   `tfsdk:"options"`
}

// CDNOptionsModel represents the CDN resource options block
type CDNOptionsModel struct {
	// Boolean options - using types.Bool for tristate support (null/true/false)
	IgnoreQueryParams       types.Bool `tfsdk:"ignore_query_params"`
	Slice                   types.Bool `tfsdk:"slice"`
	FetchedCompressed       types.Bool `tfsdk:"fetched_compressed"`
	GzipOn                  types.Bool `tfsdk:"gzip_on"`
	RedirectHttpToHttps     types.Bool `tfsdk:"redirect_http_to_https"`
	RedirectHttpsToHttp     types.Bool `tfsdk:"redirect_https_to_http"`
	ForwardHostHeader       types.Bool `tfsdk:"forward_host_header"` // Critical fix for tristate
	ProxyCacheMethodsSet    types.Bool `tfsdk:"proxy_cache_methods_set"`
	DisableProxyForceRanges types.Bool `tfsdk:"disable_proxy_force_ranges"`
	IgnoreCookie            types.Bool `tfsdk:"ignore_cookie"`
	EnableIPURLSigning      types.Bool `tfsdk:"enable_ip_url_signing"`

	// Cache settings - nested blocks
	EdgeCacheSettings    types.List `tfsdk:"edge_cache_settings"`    // List of EdgeCacheSettingsModel (MaxItems: 1)
	BrowserCacheSettings types.List `tfsdk:"browser_cache_settings"` // List of BrowserCacheSettingsModel (MaxItems: 1)

	// String options
	CustomHostHeader types.String `tfsdk:"custom_host_header"`
	CustomServerName types.String `tfsdk:"custom_server_name"`
	SecureKey        types.String `tfsdk:"secure_key"`

	// List options
	CacheHTTPHeaders     types.List `tfsdk:"cache_http_headers"`
	QueryParamsWhitelist types.List `tfsdk:"query_params_whitelist"`
	QueryParamsBlacklist types.List `tfsdk:"query_params_blacklist"`
	Cors                 types.List `tfsdk:"cors"`
	AllowedHTTPMethods   types.List `tfsdk:"allowed_http_methods"`
	Stale                types.List `tfsdk:"stale"`

	// Map options
	StaticResponseHeaders types.Map `tfsdk:"static_response_headers"`
	StaticRequestHeaders  types.Map `tfsdk:"static_request_headers"`

	// Nested objects
	IPAddressACL types.List `tfsdk:"ip_address_acl"`
	Rewrite      types.List `tfsdk:"rewrite"`

	// New options (go-genproto v0.57.0)
	Websockets        types.Bool `tfsdk:"websockets"`
	BrotliCompression types.List `tfsdk:"brotli_compression"` // List of content-type strings
	GeoACL            types.List `tfsdk:"geo_acl"`            // List of GeoACLModel (MaxItems: 1)
	ReferrerACL       types.List `tfsdk:"referrer_acl"`       // List of ReferrerACLModel (MaxItems: 1)
	HeaderFilter      types.List `tfsdk:"header_filter"`      // List of HeaderFilterModel (MaxItems: 1)
	FollowRedirects   types.List `tfsdk:"follow_redirects"`   // List of FollowRedirectsModel (MaxItems: 1)
	StaticResponseOpt types.List `tfsdk:"static_response"`    // List of StaticResponseModel (MaxItems: 1)
}

// SSLCertificateModel represents the SSL certificate block
type SSLCertificateModel struct {
	Type                 types.String `tfsdk:"type"`
	Status               types.String `tfsdk:"status"`
	CertificateManagerID types.String `tfsdk:"certificate_manager_id"`
}

// IPAddressACLModel represents the IP address ACL block
type IPAddressACLModel struct {
	PolicyType     types.String `tfsdk:"policy_type"`
	ExceptedValues types.List   `tfsdk:"excepted_values"`
}

// RewriteModel represents the rewrite rules block
type RewriteModel struct {
	Enabled types.Bool   `tfsdk:"enabled"`
	Body    types.String `tfsdk:"body"`
	Flag    types.String `tfsdk:"flag"`
}

// EdgeCacheSettingsModel represents the edge cache settings block
// Matches master schema edge_cache_settings_codes with value + custom_values
// - value (SimpleValue): cache time for 200, 206, 301, 302 ONLY (4xx/5xx NOT cached)
// - custom_values (CustomValues): per-code overrides with higher priority, "any" = all codes
type EdgeCacheSettingsModel struct {
	Enabled      types.Bool  `tfsdk:"enabled"`       // Controls whether caching is enabled
	Value        types.Int64 `tfsdk:"value"`         // SimpleValue: cache time for success codes (200, 206, 301, 302)
	CustomValues types.Map   `tfsdk:"custom_values"` // CustomValues: per-code overrides, "any" = all response codes
	DefaultValue types.Int64 `tfsdk:"default_value"` // DefaultValue: cache time for success codes (200, 206, 301, 302)
}

// BrowserCacheSettingsModel represents the browser cache settings block
type BrowserCacheSettingsModel struct {
	Enabled   types.Bool  `tfsdk:"enabled"`    // Controls whether browser caching is enabled
	CacheTime types.Int64 `tfsdk:"cache_time"` // Cache time in seconds for browsers
}

// GeoACLModel represents the geo ACL block
type GeoACLModel struct {
	PolicyType types.String `tfsdk:"policy_type"` // "allow" or "deny"
	Countries  types.List   `tfsdk:"countries"`   // List of ISO 3166 country codes
}

// ReferrerACLModel represents the referrer ACL block
type ReferrerACLModel struct {
	PolicyType types.String `tfsdk:"policy_type"` // "allow" or "deny"
	Referrers  types.List   `tfsdk:"referrers"`   // List of referrer patterns
}

// HeaderFilterModel represents the header filter block
type HeaderFilterModel struct {
	Enabled types.Bool `tfsdk:"enabled"` // Enable/disable header filtering
	Headers types.List `tfsdk:"headers"` // List of header names to whitelist
}

// FollowRedirectsModel represents the follow redirects block
type FollowRedirectsModel struct {
	Enabled       types.Bool `tfsdk:"enabled"`         // Enable/disable following redirects
	Codes         types.List `tfsdk:"codes"`           // Redirect HTTP status codes (e.g., 301, 302)
	UseCustomHost types.Bool `tfsdk:"use_custom_host"` // Use redirect target domain as Host header
}

// StaticResponseModel represents the static response block
type StaticResponseModel struct {
	Enabled types.Bool   `tfsdk:"enabled"` // Enable/disable static response
	Code    types.Int64  `tfsdk:"code"`    // HTTP status code
	Content types.String `tfsdk:"content"` // Response content (Location header for 3xx, body for others)
}
