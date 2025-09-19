---
subcategory: "Cloud Content Delivery Network (CDN)"
page_title: "Yandex: yandex_cdn_rule"
description: |-
  Allows management of a Yandex Cloud CDN Resource Rule.
---

# yandex_cdn_rule (Resource)

Allows management of [Yandex Cloud CDN Resource Rules](https://yandex.cloud/docs/cdn/concepts/rules). Rules allow you to apply different CDN settings to specific URL patterns within a CDN resource.

~> **Note:** CDN Rules are pattern-based configurations that override the default CDN resource settings for specific URL paths. Rules are executed in order of their weight (lower weight executes first).

~> **Note:** The rule pattern must be a valid regular expression. The pattern is matched against the request path starting after the domain name.

## Example usage

### Basic Rule with Redirect

```terraform
resource "yandex_cdn_resource" "my_resource" {
  cname           = "cdn.example.com"
  origin_group_id = yandex_cdn_origin_group.my_group.id
  origin_protocol = "https"
}

resource "yandex_cdn_rule" "redirect_old_urls" {
  resource_id  = yandex_cdn_resource.my_resource.id
  name         = "redirect-old-urls"
  rule_pattern = "^/old-api/.*"
  weight       = 100

  options {
    redirect_http_to_https = true
    custom_host_header     = "api.example.com"
  }
}
```

### Cache Override Rule

```terraform
resource "yandex_cdn_rule" "no_cache_admin" {
  resource_id  = yandex_cdn_resource.my_resource.id
  name         = "no-cache-admin-panel"
  rule_pattern = "^/admin/.*"
  weight       = 50  # Lower weight = higher priority

  options {
    disable_cache = true
    ignore_cookie = false
  }
}
```

### Static Assets Optimization

```terraform
resource "yandex_cdn_rule" "static_assets" {
  resource_id  = yandex_cdn_resource.my_resource.id
  name         = "optimize-static-assets"
  rule_pattern = "\\.(js|css|jpg|png|gif|svg|woff|woff2)$"
  weight       = 200

  options {
    edge_cache_settings    = 2592000  # 30 days in seconds
    browser_cache_settings = 604800   # 7 days in seconds
    gzip_on               = true
    slice                 = true
    
    static_response_headers = {
      "cache-control" = "public, max-age=604800"
      "x-content-type-options" = "nosniff"
    }
  }
}
```

### API Endpoint Rule with Security

```terraform
resource "yandex_cdn_rule" "api_security" {
  resource_id  = yandex_cdn_resource.my_resource.id
  name         = "api-v2-security"
  rule_pattern = "^/api/v2/.*"
  weight       = 150

  options {
    allowed_http_methods = ["GET", "POST", "PUT", "DELETE"]
    forward_host_header  = true
    
    cors = ["*"]
    
    static_request_headers = {
      "x-api-version" = "v2"
      "x-cdn-rule"    = "api-security"
    }

    ip_address_acl {
      policy_type     = "allow"
      excepted_values = ["192.168.1.0/24", "10.0.0.0/8"]
    }
  }
}
```

### Multiple Rules with Different Weights

```terraform
# Default rule for all images - high cache
resource "yandex_cdn_rule" "images_default" {
  resource_id  = yandex_cdn_resource.my_resource.id
  name         = "images-default-cache"
  rule_pattern = "\\.(jpg|jpeg|png|gif|webp)$"
  weight       = 500  # Lower priority

  options {
    edge_cache_settings    = 86400  # 1 day
    browser_cache_settings = 3600   # 1 hour
  }
}

# Override for user avatars - no cache
resource "yandex_cdn_rule" "user_avatars" {
  resource_id  = yandex_cdn_resource.my_resource.id
  name         = "user-avatars-no-cache"
  rule_pattern = "^/avatars/.*\\.(jpg|jpeg|png)$"
  weight       = 100  # Higher priority (lower weight)

  options {
    disable_cache = true
    forward_host_header = true
  }
}

# Override for product images - moderate cache
resource "yandex_cdn_rule" "product_images" {
  resource_id  = yandex_cdn_resource.my_resource.id
  name         = "product-images-cache"
  rule_pattern = "^/products/.*\\.(jpg|jpeg|png|webp)$"
  weight       = 200  # Medium priority

  options {
    edge_cache_settings    = 7200   # 2 hours
    browser_cache_settings = 1800   # 30 minutes
    fetched_compressed = true
  }
}
```

### Query Parameters Handling

```terraform
resource "yandex_cdn_rule" "api_with_params" {
  resource_id  = yandex_cdn_resource.my_resource.id
  name         = "api-query-params"
  rule_pattern = "^/api/search.*"
  weight       = 300

  options {
    # Cache only specific query parameters
    query_params_whitelist = ["q", "page", "limit", "sort"]
    
    edge_cache_settings = 300  # 5 minutes for search results
    
    static_response_headers = {
      "vary" = "Accept-Encoding"
    }
  }
}
```

### URL Rewrite Examples

```terraform
# Rewrite API versioning - strip version from path
resource "yandex_cdn_rule" "api_version_rewrite" {
  resource_id  = yandex_cdn_resource.my_resource.id
  name         = "api-version-rewrite"
  rule_pattern = "^/api/v[0-9]+/.*"
  weight       = 50

  options {
    # Remove API version from path: /api/v2/users -> /users
    rewrite {
      enabled = true
      body    = "^/api/v[0-9]+/(.*) /$1"
      flag    = "break"  # Stop processing after rewrite
    }
    
    forward_host_header = true
  }
}

# Permanent redirect from old URLs to new structure
resource "yandex_cdn_rule" "legacy_redirect" {
  resource_id  = yandex_cdn_resource.my_resource.id
  name         = "legacy-url-redirect"
  rule_pattern = "^/old/.*"
  weight       = 100

  options {
    rewrite {
      enabled = true
      body    = "^/old/(.*) /new/$1"
      flag    = "permanent"  # Send 301 redirect to client
    }
  }
}

# Serve index.html for directory requests in specific paths
resource "yandex_cdn_rule" "docs_index" {
  resource_id  = yandex_cdn_resource.my_resource.id
  name         = "docs-index-rewrite"
  rule_pattern = "^/docs/.*/$"
  weight       = 150

  options {
    rewrite {
      enabled = true
      body    = "^/(.*)/$ /$1/index.html"
      flag    = "last"  # Re-evaluate all rules with new URL
    }
    
    edge_cache_settings = 3600
  }
}
```

## Schema

### Required

- `name` (String) Name of the CDN rule. Must be unique within the resource. Maximum length is 50 characters.
- `resource_id` (String) ID of the CDN resource to which this rule belongs.
- `rule_pattern` (String) Regular expression pattern to match request URLs. Maximum length is 100 characters. The pattern is matched against the request path after the domain name.

### Optional

- `options` (Block List, Max: 1) CDN rule-specific settings that override the resource's default options for URLs matching the pattern. Uses the same schema as CDN resource options. (see [below for nested schema](#nestedblock--options))
- `weight` (Number) Rule execution priority. Rules with lower weights are executed first. Valid range is 0-9999. Default value is 0.

### Read-Only

- `id` (String) The ID of this resource.
- `rule_id` (String) The unique identifier of the rule assigned by the CDN service.

<a id="nestedblock--options"></a>
### Nested Schema for `options`

The options block supports all the same fields as the CDN resource options. When a rule matches, these options override the default resource options.

Optional:

- `allowed_http_methods` (List of String) HTTP methods for your CDN content. By default the following methods are allowed: GET, HEAD, POST, PUT, PATCH, DELETE, OPTIONS. In case some methods are not allowed to the user, they will get the 405 (Method Not Allowed) response.
- `browser_cache_settings` (Number) Set up a cache period for the end-users browser. Content will be cached due to origin settings. The list of HTTP response codes that can be cached in browsers: 200, 201, 204, 206, 301, 302, 303, 304, 307, 308.
- `cache_http_headers` (List of String) List HTTP headers that must be included in responses to clients.
- `cors` (List of String) Parameter that lets browsers get access to selected resources from a domain different to a domain from which the request is received.
- `custom_host_header` (String) Custom value for the Host header. Your server must be able to process requests with the chosen header.
- `custom_server_name` (String) Wildcard additional CNAME. If a resource has a wildcard additional CNAME, you can use your own certificate for content delivery via HTTPS.
- `disable_cache` (Boolean) Setup a cache status.
- `disable_proxy_force_ranges` (Boolean) Disabling proxy force ranges.
- `edge_cache_settings` (Number) Content will be cached according to origin cache settings. The value applies for a response with codes 200, 201, 204, 206, 301, 302, 303, 304, 307, 308 if an origin server does not have caching HTTP headers.
- `enable_ip_url_signing` (Boolean) Enable access limiting by IP addresses, option available only with setting secure_key.
- `fetched_compressed` (Boolean) Option helps you to reduce the bandwidth between origin and CDN servers. Also, content delivery speed becomes higher because of reducing the time for compressing files in a CDN. **Conflicts with** `gzip_on`.
- `forward_host_header` (Boolean) Choose the Forward Host header option if is important to send in the request to the Origin the same Host header as was sent in the request to CDN server.
- `gzip_on` (Boolean) GZip compression at CDN servers reduces file size by 70% and can be as high as 90%. **Conflicts with** `fetched_compressed`.
- `ignore_cookie` (Boolean) Set for ignoring cookie.
- `ignore_query_params` (Boolean) Files with different query parameters are cached as objects with the same key regardless of the parameter value.
- `ip_address_acl` (Block List, Max: 1) IP address access control list. (see [below for nested schema](#nestedblock--options--ip_address_acl))
- `proxy_cache_methods_set` (Boolean) Allows caching for GET, HEAD and POST requests.
- `query_params_blacklist` (List of String) Files with the specified query parameters are cached as objects with the same key, files with other parameters are cached as objects with different keys. **Conflicts with** `query_params_whitelist`.
- `query_params_whitelist` (List of String) Files with the specified query parameters are cached as objects with different keys, files with other parameters are cached as objects with the same key. **Conflicts with** `query_params_blacklist`.
- `redirect_http_to_https` (Boolean) Set up a redirect from HTTP to HTTPS. **Conflicts with** `redirect_https_to_http`.
- `redirect_https_to_http` (Boolean) Set up a redirect from HTTPS to HTTP. **Conflicts with** `redirect_http_to_https`.
- `secure_key` (String) Set secure key for url encoding to protect content and limit access by IP addresses and time limits.
- `slice` (Boolean) Files larger than 10 MB will be requested and cached in parts (no larger than 10 MB each part). It reduces time to first byte.
- `static_request_headers` (Map of String) Set up custom headers that CDN servers will send in requests to origins.
- `static_response_headers` (Map of String) Set up a static response header. The header name must be lowercase.
- `rewrite` (Block List, Max: 1) An option for changing or redirecting query paths. (see [below for nested schema](#nestedblock--options--rewrite))

<a id="nestedblock--options--ip_address_acl"></a>
### Nested Schema for `options.ip_address_acl`

Optional:

- `excepted_values` (List of String) The list of specified IP addresses to be allowed or denied depending on acl policy type.
- `policy_type` (String) The policy type for ACL. One of `allow` or `deny` values.

<a id="nestedblock--options--rewrite"></a>
### Nested Schema for `options.rewrite`

Required:

- `body` (String) Pattern for rewrite. The value must have the following format: `<source path> <destination path>`, where both paths are regular expressions which use at least one group. E.g., `/foo/(.*) /bar/$1`.

Optional:

- `enabled` (Boolean) True - the rewrite option is enabled and its flag is applied to the rule. False - the rewrite option is disabled. Default is false.
- `flag` (String) Rewrite flag determines how the rewrite is processed. Available values:
  - `'break'` (default) - Stop processing further rules after this rewrite
  - `'last'` - Apply this rewrite and re-evaluate all rules with the new URL
  - `'redirect'` - Send HTTP 302 temporary redirect to the client
  - `'permanent'` - Send HTTP 301 permanent redirect to the client

## Import

CDN rules can be imported using a composite ID in the format `resource_id/rule_id`:

```bash
# Get the resource ID and rule ID from the Yandex Cloud Console or YC CLI
# terraform import yandex_cdn_rule.<resource_name> <resource_id>/<rule_id>
terraform import yandex_cdn_rule.my_rule bc3e321d-f332-44e3-9bfa-25ccb8e011d4/123456
```

To list all rules for a CDN resource using YC CLI:
```bash
yc cdn resource list-rules --resource-id <resource_id>
```

## Rule Pattern Examples

The `rule_pattern` field accepts regular expressions. Here are common patterns:

| Pattern | Description |
|---------|-------------|
| `^/api/.*` | Match all paths starting with `/api/` |
| `\\.jpg$` | Match all JPEG images |
| `\\.(jpg\|png\|gif)$` | Match multiple image types |
| `^/static/.*\\.css$` | Match CSS files in static folder |
| `^/users/[0-9]+/avatar` | Match user avatar URLs with numeric IDs |
| `.*\\?.*version=.*` | Match URLs with version query parameter |
| `^/products/.*/images/` | Match product image paths |
| `^(?!/admin/).*` | Match all paths except those starting with `/admin/` |

## Important Notes

1. **Weight Priority**: Rules are evaluated in order of weight (ascending). Lower weight values have higher priority.

2. **Pattern Matching**: The pattern is matched against the request path after the domain. For example, for URL `https://cdn.example.com/images/logo.png`, the pattern is matched against `/images/logo.png`.

3. **Options Override**: When a rule matches, its options completely override the corresponding options from the CDN resource. Options not specified in the rule will use the resource defaults.

4. **Performance Consideration**: Too many rules or complex regex patterns can impact CDN performance. It's recommended to keep the number of rules reasonable and patterns optimized.

5. **Validation**: The rule pattern is validated to ensure it's a valid regular expression. Invalid patterns will cause resource creation to fail.

6. **Rule Limits**: Check the Yandex Cloud documentation for limits on the number of rules per CDN resource.