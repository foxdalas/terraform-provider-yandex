package converter

import (
	"github.com/hashicorp/terraform-plugin-framework/diag"

	"github.com/yandex-cloud/terraform-provider-yandex/yandex-framework/provider/config"
)

func GetCloudID(stateValue string, providerConfig *config.Config, diags *diag.Diagnostics) string {
	switch {
	case stateValue != "":
		return stateValue
	case !providerConfig.ProviderState.CloudID.IsUnknown() && !providerConfig.ProviderState.CloudID.IsNull():
		return providerConfig.ProviderState.CloudID.ValueString()
	default:
		diags.AddError(
			"Cannot determine cloud_id",
			"Please set 'cloud_id' key in this resource or at provider level",
		)
		return ""
	}
}

func GetFolderID(stateValue string, providerConfig *config.Config, diags *diag.Diagnostics) string {
	switch {
	case stateValue != "":
		return stateValue
	case !providerConfig.ProviderState.FolderID.IsUnknown() && !providerConfig.ProviderState.FolderID.IsNull():
		return providerConfig.ProviderState.FolderID.ValueString()
	default:
		diags.AddError(
			"Cannot determine folder_id",
			"Please set 'folder_id' key in this resource or at provider level",
		)
		return ""
	}
}

func GetOrganizationID(stateValue string, providerConfig *config.Config, diags *diag.Diagnostics) string {
	switch {
	case stateValue != "":
		return stateValue
	case !providerConfig.ProviderState.OrganizationID.IsUnknown() && !providerConfig.ProviderState.OrganizationID.IsNull():
		return providerConfig.ProviderState.OrganizationID.ValueString()
	default:
		diags.AddError(
			"Cannot determine organization_id",
			"Please set 'organization_id' key in this resource or at provider level",
		)
		return ""
	}
}

func GetZone(stateValue string, providerConfig *config.Config, diags *diag.Diagnostics) string {
	switch {
	case stateValue != "":
		return stateValue
	case !providerConfig.ProviderState.Zone.IsUnknown() && !providerConfig.ProviderState.Zone.IsNull():
		return providerConfig.ProviderState.Zone.ValueString()
	default:
		diags.AddError(
			"Cannot determine zone",
			"Please set 'zone' key in this resource or at provider level",
		)
		return ""
	}
}
