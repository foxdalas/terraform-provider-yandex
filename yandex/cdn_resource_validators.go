package yandex

import (
	"fmt"
	"net"
	"regexp"
	"strings"

	"github.com/hashicorp/go-cty/cty"
	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/validation"
)

// CDN resource field validators
var (
	// Validates edge_cache_settings (0-365 days in seconds)
	validateEdgeCacheSettings = validation.IntBetween(0, 31536000)

	// Validates browser_cache_settings (0-365 days in seconds)
	validateBrowserCacheSettings = validation.IntBetween(0, 31536000)

	// Validates HTTP methods
	validateHTTPMethods = validation.StringInSlice([]string{
		"GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS",
	}, false)

	// Validates CORS origins
	validateCORSOrigin = validation.StringMatch(
		regexp.MustCompile(`^(\*|https?://[\w\-._~:/?#[\]@!$&'()*+,;=]+)$`),
		"must be '*' or valid HTTP(S) origin",
	)

	// Validates custom_server_name (SNI)
	validateCustomServerName = validation.StringMatch(
		regexp.MustCompile(`^[a-z0-9]([-a-z0-9]*[a-z0-9])?(\.[a-z0-9]([-a-z0-9]*[a-z0-9])?)*$`),
		"must be a valid domain name",
	)

	// Validates secure_key
	validateSecureKey = validation.StringLenBetween(6, 32)
)

// validateIPAddressOrCIDR validates that a string is a valid IP address or CIDR notation
func validateIPAddressOrCIDR(val interface{}, path cty.Path) diag.Diagnostics {
	var diags diag.Diagnostics
	v, ok := val.(string)
	if !ok {
		diags = append(diags, diag.Diagnostic{
			Severity: diag.Error,
			Summary:  "Invalid type",
			Detail:   "Expected a string value",
		})
		return diags
	}
	
	// Try parsing as CIDR first
	if _, _, err := net.ParseCIDR(v); err == nil {
		return diags
	}
	
	// Try parsing as IP address
	if ip := net.ParseIP(v); ip != nil {
		return diags
	}
	
	diags = append(diags, diag.Diagnostic{
		Severity: diag.Error,
		Summary:  "Invalid IP address or CIDR",
		Detail:   fmt.Sprintf("%q must be a valid IP address (e.g., 192.168.1.1) or CIDR notation (e.g., 192.168.1.0/24)", v),
	})
	return diags
}

// validateCDNResourceOptions performs complex validation of CDN resource options
func validateCDNResourceOptions() schema.SchemaValidateDiagFunc {
	return func(val interface{}, path cty.Path) diag.Diagnostics {
		var diags diag.Diagnostics

		options, ok := val.([]interface{})
		if !ok || len(options) == 0 {
			return diags
		}

		opt, ok := options[0].(map[string]interface{})
		if !ok {
			return diags
		}

		// Check logical correctness of options
		if err := validateOptionsLogic(opt); err != nil {
			diags = append(diags, diag.Diagnostic{
				Severity: diag.Error,
				Summary:  "Invalid CDN options logic",
				Detail:   err.Error(),
			})
		}

		// Check dependent options
		if err := validateDependentOptions(opt); err != nil {
			diags = append(diags, diag.Diagnostic{
				Severity: diag.Error,
				Summary:  "Invalid CDN options dependency",
				Detail:   err.Error(),
			})
		}

		return diags
	}
}

// validateOptionsLogic checks logical correctness of CDN options
func validateOptionsLogic(opt map[string]interface{}) error {
	// edge_cache_settings has no effect when disable_cache is true
	if getBool(opt, "disable_cache") && isFieldSet(opt, "edge_cache_settings") {
		return fmt.Errorf("edge_cache_settings has no effect when disable_cache is true")
	}

	// browser_cache_settings should be less than or equal to edge_cache_settings
	if isFieldSet(opt, "browser_cache_settings") && isFieldSet(opt, "edge_cache_settings") {
		browserCache := getInt(opt, "browser_cache_settings")
		edgeCache := getInt(opt, "edge_cache_settings")

		if browserCache > edgeCache {
			return fmt.Errorf(
				"browser_cache_settings (%d) cannot be greater than edge_cache_settings (%d)",
				browserCache, edgeCache,
			)
		}
	}

	return nil
}

// validateDependentOptions checks dependencies between CDN options
func validateDependentOptions(opt map[string]interface{}) error {
	// ip_address_acl requires proper structure
	if acl, ok := opt["ip_address_acl"].([]interface{}); ok && len(acl) > 0 {
		aclMap, ok := acl[0].(map[string]interface{})
		if !ok {
			return fmt.Errorf("ip_address_acl must be a valid structure")
		}

		if _, ok := aclMap["policy_type"]; !ok {
			return fmt.Errorf("ip_address_acl requires policy_type to be set")
		}

		excepted, ok := aclMap["excepted_values"].([]interface{})
		if !ok || len(excepted) == 0 {
			return fmt.Errorf("ip_address_acl requires at least one excepted_value")
		}

		// Validate IP addresses/subnets
		for i, v := range excepted {
			ipStr, ok := v.(string)
			if !ok {
				return fmt.Errorf("ip_address_acl.excepted_values[%d]: must be a string", i)
			}

			if _, _, err := net.ParseCIDR(ipStr); err != nil {
				if ip := net.ParseIP(ipStr); ip == nil {
					return fmt.Errorf("ip_address_acl.excepted_values[%d]: invalid IP address or CIDR: %s", i, ipStr)
				}
			}
		}
	}

	return nil
}

// validateIPAddressACL validates IP address ACL configuration
func validateIPAddressACL() schema.SchemaValidateDiagFunc {
	return func(val interface{}, path cty.Path) diag.Diagnostics {
		var diags diag.Diagnostics

		aclList, ok := val.([]interface{})
		if !ok || len(aclList) == 0 {
			return diags
		}

		acl, ok := aclList[0].(map[string]interface{})
		if !ok {
			return diags
		}

		// Check policy_type
		policyType, ok := acl["policy_type"].(string)
		if !ok {
			return diags
		}

		if policyType != "allow" && policyType != "deny" {
			diags = append(diags, diag.Diagnostic{
				Severity: diag.Error,
				Summary:  "Invalid policy_type",
				Detail:   fmt.Sprintf("policy_type must be 'allow' or 'deny', got: %s", policyType),
			})
		}

		// Check excepted_values
		values, ok := acl["excepted_values"].([]interface{})
		if !ok {
			return diags
		}

		if len(values) > 200 {
			diags = append(diags, diag.Diagnostic{
				Severity: diag.Error,
				Summary:  "Too many IP addresses",
				Detail:   fmt.Sprintf("Maximum 200 IP addresses allowed, got: %d", len(values)),
			})
		}

		return diags
	}
}

// validateStaticHeaders validates static HTTP headers
func validateStaticHeaders() schema.SchemaValidateDiagFunc {
	return func(val interface{}, path cty.Path) diag.Diagnostics {
		var diags diag.Diagnostics

		headers, ok := val.(map[string]interface{})
		if !ok {
			return diags
		}

		// Forbidden headers according to CDN standards
		forbiddenHeaders := []string{
			"Host", "Content-Length", "Transfer-Encoding",
			"Connection", "Keep-Alive", "Proxy-Authenticate",
			"Proxy-Authorization", "TE", "Trailer", "Upgrade",
		}

		for key := range headers {
			// Check for forbidden headers
			for _, forbidden := range forbiddenHeaders {
				if strings.EqualFold(key, forbidden) {
					diags = append(diags, diag.Diagnostic{
						Severity: diag.Error,
						Summary:  "Forbidden header",
						Detail:   fmt.Sprintf("Header '%s' cannot be set as static header", key),
					})
				}
			}

			// Validate header name format
			if !regexp.MustCompile(`^[A-Za-z0-9\-]+$`).MatchString(key) {
				diags = append(diags, diag.Diagnostic{
					Severity: diag.Error,
					Summary:  "Invalid header name",
					Detail:   fmt.Sprintf("Header name '%s' contains invalid characters", key),
				})
			}
		}

		return diags
	}
}

// Helper functions for working with options

// isFieldSet checks if a field is set in the options map
func isFieldSet(opt map[string]interface{}, field string) bool {
	val, exists := opt[field]
	if !exists {
		return false
	}

	switch v := val.(type) {
	case bool:
		return true // Even false is considered a set value
	case string:
		return v != ""
	case []interface{}:
		return len(v) > 0
	case map[string]interface{}:
		return len(v) > 0
	case int:
		return true
	default:
		return val != nil
	}
}

// getBool safely retrieves a boolean value from options map
func getBool(opt map[string]interface{}, field string) bool {
	if val, ok := opt[field].(bool); ok {
		return val
	}
	return false
}

// getInt safely retrieves an integer value from options map
func getInt(opt map[string]interface{}, field string) int {
	if val, ok := opt[field].(int); ok {
		return val
	}
	return 0
}