package cdn_raw_log

import (
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/stretchr/testify/assert"
)

func TestCDNRawLogResource_Model(t *testing.T) {
	// Test that the resource model is properly structured
	resource := CDNRawLogResource{
		ID:         types.StringValue("test-id"),
		ResourceID: types.StringValue("cdn-resource-123"),
		Status:     types.StringValue("ACTIVE"),
		Settings: &Settings{
			BucketName:   types.StringValue("test-bucket"),
			BucketRegion: types.StringValue("ru-central1"),
			FilePrefix:   types.StringValue("logs/"),
		},
	}

	assert.Equal(t, "test-id", resource.ID.ValueString())
	assert.Equal(t, "cdn-resource-123", resource.ResourceID.ValueString())
	assert.Equal(t, "ACTIVE", resource.Status.ValueString())
	assert.NotNil(t, resource.Settings)
	assert.Equal(t, "test-bucket", resource.Settings.BucketName.ValueString())
	assert.Equal(t, "ru-central1", resource.Settings.BucketRegion.ValueString())
	assert.Equal(t, "logs/", resource.Settings.FilePrefix.ValueString())
}

func TestCDNRawLogDataSource_Model(t *testing.T) {
	// Test that the data source model is properly structured
	dataSource := CDNRawLogDataSource{
		ID:         types.StringValue("test-id"),
		ResourceID: types.StringValue("cdn-resource-123"),
		Status:     types.StringValue("ACTIVE"),
		Settings: &Settings{
			BucketName:   types.StringValue("test-bucket"),
			BucketRegion: types.StringValue("ru-central1"),
			FilePrefix:   types.StringValue("logs/"),
		},
	}

	assert.Equal(t, "test-id", dataSource.ID.ValueString())
	assert.Equal(t, "cdn-resource-123", dataSource.ResourceID.ValueString())
	assert.Equal(t, "ACTIVE", dataSource.Status.ValueString())
	assert.NotNil(t, dataSource.Settings)
	assert.Equal(t, "test-bucket", dataSource.Settings.BucketName.ValueString())
	assert.Equal(t, "ru-central1", dataSource.Settings.BucketRegion.ValueString())
	assert.Equal(t, "logs/", dataSource.Settings.FilePrefix.ValueString())
}

func TestSettings_Model(t *testing.T) {
	// Test Settings structure
	settings := Settings{
		BucketName:   types.StringValue("my-logs-bucket"),
		BucketRegion: types.StringValue("ru-central1"),
		FilePrefix:   types.StringValue("cdn-logs/"),
	}

	assert.Equal(t, "my-logs-bucket", settings.BucketName.ValueString())
	assert.Equal(t, "ru-central1", settings.BucketRegion.ValueString())
	assert.Equal(t, "cdn-logs/", settings.FilePrefix.ValueString())
}
