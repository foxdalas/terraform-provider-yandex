//
// CDN Resource with SSL certificate and HTTPS redirect
//
resource "yandex_cdn_resource" "with_ssl" {
  cname           = "cdn-secure.example.com"
  origin_protocol = "https"
  origin_group_id = yandex_cdn_origin_group.my_group.id

  ssl_certificate {
    type                   = "certificate_manager"
    certificate_manager_id = yandex_cm_certificate.my_cert.id
  }

  tls_profile = "strict"

  options {
    redirect_http_to_https = true
    custom_server_name     = "cdn-secure.example.com"
  }
}
