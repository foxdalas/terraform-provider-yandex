---
subcategory: "CDN"
description: |-
  Allows management of a Yandex.Cloud CDN Raw Log configuration.
---

# yandex_cdn_raw_log

Allows management of a Yandex.Cloud CDN Raw Log configuration. Raw logs provide access to detailed CDN access logs that are stored in Object Storage.

## Example Usage

```hcl
resource "yandex_cdn_raw_log" "example" {
  resource_id = yandex_cdn_resource.example.id

  settings {
    bucket_name   = "my-cdn-logs-bucket"
    bucket_region = "ru-central1"
    file_prefix   = "cdn-logs/"
  }
}
```

## Argument Reference

The following arguments are supported:

* `resource_id` - (Required) CDN resource ID for which raw logs are configured.

* `settings` - (Required) Raw logs settings configuration. Structure is documented below.

The `settings` block supports:

* `bucket_name` - (Required) Object Storage bucket name where logs will be stored.

* `bucket_region` - (Optional) Object Storage bucket region. Defaults to `ru-central1`.

* `file_prefix` - (Optional) Prefix for log files in the bucket.

## Attributes Reference

In addition to the arguments listed above, the following computed attributes are exported:

* `id` - The ID of the CDN Raw Log configuration.

* `status` - The status of the raw logs configuration (`ACTIVE`, `NOT_ACTIVATED`, `SUSPENDED`).

## Import

CDN Raw Log configurations can be imported using the CDN resource ID:

```
$ terraform import yandex_cdn_raw_log.example <cdn_resource_id>
```