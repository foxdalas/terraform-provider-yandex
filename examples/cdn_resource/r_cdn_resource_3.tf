//
// CDN Resource with access control: geo_acl, referrer_acl, ip_address_acl
//
resource "yandex_cdn_resource" "with_acl" {
  cname           = "cdn-protected.example.com"
  origin_protocol = "https"
  origin_group_id = yandex_cdn_origin_group.my_group.id

  options {
    geo_acl {
      policy_type = "allow"
      countries   = ["RU", "KZ", "BY"]
    }

    referrer_acl {
      policy_type = "allow"
      referrers   = ["example.com", "*.example.com"]
    }

    ip_address_acl {
      policy_type     = "deny"
      excepted_values = ["192.0.2.0/24", "198.51.100.0/24"]
    }
  }
}
