package cdn_raw_log

import (
	"github.com/hashicorp/terraform-plugin-framework/types"
)

// CDNRawLogResource описывает модель ресурса для CDN Raw Log
type CDNRawLogResource struct {
	ID         types.String `tfsdk:"id"`
	ResourceID types.String `tfsdk:"resource_id"`
	Settings   *Settings    `tfsdk:"settings"`
	Status     types.String `tfsdk:"status"`
}

// CDNRawLogDataSource описывает модель data source для CDN Raw Log
type CDNRawLogDataSource struct {
	ID         types.String `tfsdk:"id"`
	ResourceID types.String `tfsdk:"resource_id"`
	Settings   *Settings    `tfsdk:"settings"`
	Status     types.String `tfsdk:"status"`
}

// Settings описывает настройки CDN Raw Log
type Settings struct {
	BucketName   types.String `tfsdk:"bucket_name"`
	BucketRegion types.String `tfsdk:"bucket_region"`
	FilePrefix   types.String `tfsdk:"file_prefix"`
}
