---
subcategory: "Cloud Content Delivery Network (CDN)"
page_title: "Yandex: yandex_cdn_rule"
description: |-
  Get information about a Yandex Cloud CDN Resource Rule.
---

# yandex_cdn_rule (Data Source)

Use this data source to get information about a Yandex Cloud CDN Resource Rule.

## Example Usage

### Using Rule ID

```terraform
data "yandex_cdn_rule" "my_rule" {
  resource_id = "bc3e321d-f332-44e3-9bfa-25ccb8e011d4"
  rule_id     = "123456"
}

output "rule_pattern" {
  value = data.yandex_cdn_rule.my_rule.rule_pattern
}

output "rule_weight" {
  value = data.yandex_cdn_rule.my_rule.weight
}
```

### Using Rule Name (requires resource reference)

```terraform
data "yandex_cdn_resource" "my_resource" {
  cname = "cdn.example.com"
}

data "yandex_cdn_rule" "my_rule" {
  resource_id = data.yandex_cdn_resource.my_resource.id
  name        = "redirect-old-urls"
}

# Use the rule data in another resource
resource "yandex_cdn_rule" "similar_rule" {
  resource_id  = yandex_cdn_resource.other_resource.id
  name         = "similar-redirect"
  rule_pattern = data.yandex_cdn_rule.my_rule.rule_pattern
  weight       = data.yandex_cdn_rule.my_rule.weight + 10
  
  options {
    # Copy options from existing rule
    redirect_http_to_https = data.yandex_cdn_rule.my_rule.options[0].redirect_http_to_https
    custom_host_header     = data.yandex_cdn_rule.my_rule.options[0].custom_host_header
  }
}
```

### Listing All Rules for a Resource

```terraform
data "yandex_cdn_resource" "my_resource" {
  cname = "cdn.example.com"
}

# Note: This example assumes a hypothetical data source for listing rules
# Currently, individual rule lookup is supported
data "yandex_cdn_rule" "api_rule" {
  resource_id = data.yandex_cdn_resource.my_resource.id
  name        = "api-security"
}

data "yandex_cdn_rule" "static_rule" {
  resource_id = data.yandex_cdn_resource.my_resource.id
  name        = "static-assets"
}

output "all_rules" {
  value = {
    api_pattern    = data.yandex_cdn_rule.api_rule.rule_pattern
    static_pattern = data.yandex_cdn_rule.static_rule.rule_pattern
  }
}
```

## Argument Reference

The following arguments are supported:

* `resource_id` - (Required) The ID of the CDN resource that contains the rule.

* Either `rule_id` or `name` must be specified:
  * `rule_id` - (Optional) The ID of the CDN rule. If specified, the rule will be looked up by ID.
  * `name` - (Optional) The name of the CDN rule. If specified, the rule will be looked up by name within the resource.

## Attributes Reference

In addition to the arguments listed above, the following computed attributes are exported:

* `id` - The ID of the rule (same as `rule_id`).
* `rule_pattern` - The regular expression pattern used to match request URLs.
* `weight` - The execution priority of the rule (lower values have higher priority).
* `options` - The CDN options that override resource defaults for matching URLs. The structure is documented below.

### Options

The `options` block contains:

* `allowed_http_methods` - List of allowed HTTP methods.
* `browser_cache_settings` - Browser cache duration in seconds.
* `cache_http_headers` - List of HTTP headers to include in responses.
* `cors` - CORS configuration for cross-origin requests.
* `custom_host_header` - Custom Host header value.
* `custom_server_name` - Wildcard additional CNAME.
* `disable_cache` - Whether caching is disabled.
* `disable_proxy_force_ranges` - Whether proxy force ranges is disabled.
* `edge_cache_settings` - Edge cache duration in seconds.
* `enable_ip_url_signing` - Whether IP-based URL signing is enabled.
* `fetched_compressed` - Whether to fetch compressed content from origin.
* `forward_host_header` - Whether to forward the original Host header.
* `gzip_on` - Whether GZip compression is enabled.
* `ignore_cookie` - Whether to ignore cookies.
* `ignore_query_params` - Whether to ignore query parameters for caching.
* `ip_address_acl` - IP address access control configuration:
  * `policy_type` - ACL policy type (`allow` or `deny`).
  * `excepted_values` - List of IP addresses or CIDR blocks.
* `proxy_cache_methods_set` - Whether to cache GET, HEAD and POST requests.
* `query_params_blacklist` - List of query parameters to ignore for cache key.
* `query_params_whitelist` - List of query parameters to include in cache key.
* `redirect_http_to_https` - Whether to redirect HTTP to HTTPS.
* `redirect_https_to_http` - Whether to redirect HTTPS to HTTP.
* `secure_key` - Secure key for URL signing.
* `slice` - Whether to use slice (byte-range) requests.
* `static_request_headers` - Map of static headers to send to origin.
* `static_response_headers` - Map of static headers to send to clients.