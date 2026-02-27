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
}

func NewResource() resource.Resource {
	return &cdnRawLogResource{}
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

	activateReq := &cdn.ActivateRawLogsRequest{
		ResourceId: resourceID,
	}

	if plan.Settings != nil {
		activateReq.Settings = &cdn.RawLogsSettings{
			BucketName: plan.Settings.BucketName.ValueString(),
			BucketRegion: func() string {
				if !plan.Settings.BucketRegion.IsNull() {
					return plan.Settings.BucketRegion.ValueString()
				}
				return "ru-central1"
			}(),
			FilePrefix: plan.Settings.FilePrefix.ValueString(),
		}
	}

	tflog.Debug(ctx, "Creating CDN Raw Log", map[string]interface{}{
		"resource_id": resourceID,
	})

	op, err := r.providerConfig.SDK.WrapOperation(
		r.providerConfig.SDK.CDN().RawLogs().Activate(ctx, activateReq),
	)
	if err != nil {
		resp.Diagnostics.AddError(
			"Error activating CDN Raw Logs",
			fmt.Sprintf("Error while requesting API to activate CDN Raw Logs: %s", err),
		)
		return
	}

	err = op.Wait(ctx)
	if err != nil {
		resp.Diagnostics.AddError(
			"Error activating CDN Raw Logs",
			fmt.Sprintf("Error while waiting for operation to complete: %s", err),
		)
		return
	}

	plan.ID = types.StringValue(resourceID)

	// Get the current status
	rawLog, err := r.getRawLog(ctx, resourceID)
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

	rawLog, err := r.getRawLog(ctx, resourceID)
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

	updateReq := &cdn.UpdateRawLogsRequest{
		ResourceId: resourceID,
	}

	if plan.Settings != nil {
		updateReq.Settings = &cdn.RawLogsSettings{
			BucketName: plan.Settings.BucketName.ValueString(),
			BucketRegion: func() string {
				if !plan.Settings.BucketRegion.IsNull() {
					return plan.Settings.BucketRegion.ValueString()
				}
				return "ru-central1"
			}(),
			FilePrefix: plan.Settings.FilePrefix.ValueString(),
		}
	}

	tflog.Debug(ctx, "Updating CDN Raw Log", map[string]interface{}{
		"resource_id": resourceID,
	})

	op, err := r.providerConfig.SDK.WrapOperation(
		r.providerConfig.SDK.CDN().RawLogs().Update(ctx, updateReq),
	)
	if err != nil {
		resp.Diagnostics.AddError(
			"Error updating CDN Raw Logs",
			fmt.Sprintf("Error while requesting API to update CDN Raw Logs: %s", err),
		)
		return
	}

	err = op.Wait(ctx)
	if err != nil {
		resp.Diagnostics.AddError(
			"Error updating CDN Raw Logs",
			fmt.Sprintf("Error while waiting for operation to complete: %s", err),
		)
		return
	}
	if err != nil {
		resp.Diagnostics.AddError(
			"Error updating CDN Raw Logs",
			fmt.Sprintf("Error while waiting for operation to complete: %s", err),
		)
		return
	}

	// Get the updated status
	rawLog, err := r.getRawLog(ctx, resourceID)
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

	op, err := r.providerConfig.SDK.WrapOperation(
		r.providerConfig.SDK.CDN().RawLogs().Deactivate(ctx, &cdn.DeactivateRawLogsRequest{
			ResourceId: resourceID,
		}),
	)
	if err != nil {
		if status.Code(err) == codes.NotFound {
			return
		}
		resp.Diagnostics.AddError(
			"Error deactivating CDN Raw Logs",
			fmt.Sprintf("Error while requesting API to deactivate CDN Raw Logs: %s", err),
		)
		return
	}

	err = op.Wait(ctx)
	if err != nil {
		resp.Diagnostics.AddError(
			"Error deactivating CDN Raw Logs",
			fmt.Sprintf("Error while waiting for operation to complete: %s", err),
		)
		return
	}
}

func (r *cdnRawLogResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	resource.ImportStatePassthroughID(ctx, path.Root("resource_id"), req, resp)
}

func (r *cdnRawLogResource) getRawLog(ctx context.Context, resourceID string) (*cdn.GetRawLogsResponse, error) {
	return r.providerConfig.SDK.CDN().RawLogs().Get(ctx, &cdn.GetRawLogsRequest{
		ResourceId: resourceID,
	})
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
