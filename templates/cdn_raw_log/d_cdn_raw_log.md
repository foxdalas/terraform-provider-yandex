---
subcategory: "CDN"
description: |-
  Get information about a Yandex.Cloud CDN Raw Log configuration.
---

# yandex_cdn_raw_log

Get information about a Yandex.Cloud CDN Raw Log configuration.

## Example Usage

```hcl
data "yandex_cdn_raw_log" "example" {
  resource_id = "your-cdn-resource-id"
}
```

## Argument Reference

The following arguments are supported:

* `resource_id` - (Required) CDN resource ID for which to retrieve raw logs configuration.

## Attributes Reference

The following attributes are exported:

* `id` - The ID of the CDN Raw Log configuration.

* `status` - The status of the raw logs configuration (`ACTIVE`, `NOT_ACTIVATED`, `SUSPENDED`).

* `settings` - Raw logs settings configuration. Structure is documented below.

The `settings` block contains:

* `bucket_name` - Object Storage bucket name where logs are stored.

* `bucket_region` - Object Storage bucket region.

* `file_prefix` - Prefix for log files in the bucket.