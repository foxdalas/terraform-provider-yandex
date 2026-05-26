package cdn_raw_log

import (
	"context"
	"fmt"

	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"
	"github.com/yandex-cloud/go-genproto/yandex/cloud/cdn/v1"
	provider_config "github.com/yandex-cloud/terraform-provider-yandex/yandex-framework/provider/config"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// Ensure provider defined types fully satisfy framework interfaces
var (
	_ resource.Resource                = &cdnRawLogResource{}
	_ resource.ResourceWithConfigure   = &cdnRawLogResource{}
	_ resource.ResourceWithImportState = &cdnRawLogResource{}
)

type cdnRawLogResource struct {
	providerConfig *provider_config.Config
	// backend, when non-nil, replaces the SDK-backed implementation derived from
	// providerConfig. Set by tests; nil in production.
	backend rawLogsBackend
}

func NewResource() resource.Resource {
	return &cdnRawLogResource{}
}

func (r *cdnRawLogResource) api() rawLogsBackend {
	if r.backend != nil {
		return r.backend
	}
	return newSDKBackend(r.providerConfig)
}

func rawLogsSettingsFromPlan(s *Settings) *cdn.RawLogsSettings {
	if s == nil {
		return nil
	}
	region := s.BucketRegion.ValueString()
	if s.BucketRegion.IsNull() {
		region = "ru-central1"
	}
	return &cdn.RawLogsSettings{
		BucketName:   s.BucketName.ValueString(),
		BucketRegion: region,
		FilePrefix:   s.FilePrefix.ValueString(),
	}
}

func (r *cdnRawLogResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_cdn_raw_log"
}

func (r *cdnRawLogResource) Schema(ctx context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = CDNRawLogResourceSchema(ctx)
}

func (r *cdnRawLogResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	if req.ProviderData == nil {
		return
	}

	providerConfig, ok := req.ProviderData.(*provider_config.Config)
	if !ok {
		resp.Diagnostics.AddError(
			"Unexpected Resource Configure Type",
			fmt.Sprintf("Expected *provider_config.Config, got: %T. Please report this issue to the provider developers.", req.ProviderData),
		)
		return
	}

	r.providerConfig = providerConfig
}

func (r *cdnRawLogResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan CDNRawLogResource

	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	resourceID := plan.ResourceID.ValueString()

	tflog.Debug(ctx, "Creating CDN Raw Log", map[string]interface{}{
		"resource_id": resourceID,
	})

	err := r.api().Activate(ctx, &cdn.ActivateRawLogsRequest{
		ResourceId: resourceID,
		Settings:   rawLogsSettingsFromPlan(plan.Settings),
	})
	if err != nil {
		resp.Diagnostics.AddError(
			"Error activating CDN Raw Logs",
			fmt.Sprintf("Error while activating CDN Raw Logs: %s", err),
		)
		return
	}

	plan.ID = types.StringValue(resourceID)

	rawLog, err := r.api().Get(ctx, &cdn.GetRawLogsRequest{ResourceId: resourceID})
	if err != nil {
		resp.Diagnostics.AddError(
			"Error reading CDN Raw Log",
			fmt.Sprintf("Could not read CDN Raw Log after creation: %s", err),
		)
		return
	}

	r.updateStateFromRawLog(&plan, rawLog)

	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *cdnRawLogResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state CDNRawLogResource

	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	resourceID := state.ResourceID.ValueString()

	tflog.Debug(ctx, "Reading CDN Raw Log", map[string]interface{}{
		"resource_id": resourceID,
	})

	rawLog, err := r.api().Get(ctx, &cdn.GetRawLogsRequest{ResourceId: resourceID})
	if err != nil {
		if status.Code(err) == codes.NotFound {
			resp.State.RemoveResource(ctx)
			return
		}
		resp.Diagnostics.AddError(
			"Error reading CDN Raw Log",
			fmt.Sprintf("Could not read CDN Raw Log: %s", err),
		)
		return
	}

	r.updateStateFromRawLog(&state, rawLog)

	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

func (r *cdnRawLogResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan, state CDNRawLogResource

	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	resourceID := plan.ResourceID.ValueString()

	tflog.Debug(ctx, "Updating CDN Raw Log", map[string]interface{}{
		"resource_id": resourceID,
	})

	err := r.api().Update(ctx, &cdn.UpdateRawLogsRequest{
		ResourceId: resourceID,
		Settings:   rawLogsSettingsFromPlan(plan.Settings),
	})
	if err != nil {
		resp.Diagnostics.AddError(
			"Error updating CDN Raw Logs",
			fmt.Sprintf("Error while updating CDN Raw Logs: %s", err),
		)
		return
	}

	rawLog, err := r.api().Get(ctx, &cdn.GetRawLogsRequest{ResourceId: resourceID})
	if err != nil {
		resp.Diagnostics.AddError(
			"Error reading CDN Raw Log",
			fmt.Sprintf("Could not read CDN Raw Log after update: %s", err),
		)
		return
	}

	r.updateStateFromRawLog(&plan, rawLog)

	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *cdnRawLogResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state CDNRawLogResource

	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	resourceID := state.ResourceID.ValueString()

	tflog.Debug(ctx, "Deleting CDN Raw Log", map[string]interface{}{
		"resource_id": resourceID,
	})

	err := r.api().Deactivate(ctx, &cdn.DeactivateRawLogsRequest{ResourceId: resourceID})
	if err != nil {
		if status.Code(err) == codes.NotFound {
			return
		}
		resp.Diagnostics.AddError(
			"Error deactivating CDN Raw Logs",
			fmt.Sprintf("Error while deactivating CDN Raw Logs: %s", err),
		)
		return
	}
}

func (r *cdnRawLogResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	resource.ImportStatePassthroughID(ctx, path.Root("resource_id"), req, resp)
}

func (r *cdnRawLogResource) updateStateFromRawLog(state *CDNRawLogResource, rawLog *cdn.GetRawLogsResponse) {
	state.Status = types.StringValue(rawLog.Status.String())

	if settings := rawLog.GetSettings(); settings != nil {
		if state.Settings == nil {
			state.Settings = &Settings{}
		}
		state.Settings.BucketName = types.StringValue(settings.BucketName)
		if settings.BucketRegion != "" {
			state.Settings.BucketRegion = types.StringValue(settings.BucketRegion)
		}
		if settings.FilePrefix != "" {
			state.Settings.FilePrefix = types.StringValue(settings.FilePrefix)
		}
	}
}
