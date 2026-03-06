//
// CDN Resource with advanced caching: edge_cache with custom_values,
// browser_cache disabled, stale, and query params whitelist
//
resource "yandex_cdn_resource" "advanced_caching" {
  cname           = "cdn-cached.example.com"
  origin_protocol = "https"
  origin_group_id = yandex_cdn_origin_group.my_group.id

  options {
    edge_cache_settings {
      enabled       = true
      default_value = 86400
      custom_values = {
        "200" = 604800
        "404" = 60
        "301" = 86400
      }
    }

    browser_cache_settings {
      enabled = false
    }

    query_params_whitelist = ["utm_source", "utm_medium", "lang"]

    stale = ["error", "updating"]
  }
}
