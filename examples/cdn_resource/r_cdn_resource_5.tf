//
// CDN Resource with follow_redirects, static_response,
// header_filter, websockets, and rewrite
//
resource "yandex_cdn_resource" "advanced_features" {
  cname           = "cdn-advanced.example.com"
  origin_protocol = "https"
  origin_group_id = yandex_cdn_origin_group.my_group.id

  options {
    websockets = true

    follow_redirects {
      enabled = true
      codes   = [301, 302]
    }

    rewrite {
      enabled = true
      body    = "/old-path/(.*) /new-path/$1"
      flag    = "last"
    }

    header_filter {
      enabled = true
      headers = ["Content-Type", "Cache-Control", "X-Custom-Header"]
    }

    static_response {
      enabled = true
      code    = 403
      content = "Access denied"
    }
  }
}
