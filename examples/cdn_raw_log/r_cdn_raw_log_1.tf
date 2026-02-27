resource "yandex_cdn_raw_log" "example" {
  resource_id = yandex_cdn_resource.example.id

  settings {
    bucket_name   = "my-cdn-logs-bucket"
    bucket_region = "ru-central1"
    file_prefix   = "cdn-logs/"
  }
}