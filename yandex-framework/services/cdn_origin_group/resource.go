package cdn_origin_group

import (
	"context"
	"fmt"
	"strconv"
	"time"

	"github.com/golang/protobuf/ptypes/wrappers"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"
	"github.com/yandex-cloud/go-genproto/yandex/cloud/cdn/v1"
	provider_config "github.com/yandex-cloud/terraform-provider-yandex/yandex-framework/provider/config"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

const (
	yandexCDNOriginGroupDefaultTimeout = 2 * time.Minute
)

// Ensure provider defined types fully satisfy framework interfaces
var (
	_ resource.Resource                = &cdnOriginGroupResource{}
	_ resource.ResourceWithConfigure   = &cdnOriginGroupResource{}
	_ resource.ResourceWithImportState = &cdnOriginGroupResource{}
)

type cdnOriginGroupResource struct {
	providerConfig *provider_config.Config
	// backend, when non-nil, replaces the SDK-backed implementation derived
	// from providerConfig. Set by tests; nil in production.
	backend originGroupBackend
}

// NewResource creates a new CDN origin group resource
func NewResource() resource.Resource {
	return &cdnOriginGroupResource{}
}

func (r *cdnOriginGroupResource) api() originGroupBackend {
	if r.backend != nil {
		return r.backend
	}
	return newSDKBackend(r.providerConfig)
}

func (r *cdnOriginGroupResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_cdn_origin_group"
}

func (r *cdnOriginGroupResource) Schema(ctx context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = CDNOriginGroupSchema(ctx)
}

func (r *cdnOriginGroupResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
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

func (r *cdnOriginGroupResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan CDNOriginGroupModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	createTimeout, diags := plan.Timeouts.Create(ctx, yandexCDNOriginGroupDefaultTimeout)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	ctx, cancel := context.WithTimeout(ctx, createTimeout)
	defer cancel()

	folderID := r.getFolderID(&plan, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}

	providerType := "ourcdn"
	if !plan.ProviderType.IsNull() && plan.ProviderType.ValueString() != "" {
		providerType = plan.ProviderType.ValueString()
	}

	var origins []OriginModel
	resp.Diagnostics.Append(plan.Origins.ElementsAs(ctx, &origins, false)...)
	if resp.Diagnostics.HasError() {
		return
	}

	createReq := &cdn.CreateOriginGroupRequest{
		FolderId:     folderID,
		Name:         plan.Name.ValueString(),
		ProviderType: providerType,
		UseNext:      &wrappers.BoolValue{Value: plan.UseNext.ValueBool()},
		Origins:      expandOrigins(ctx, origins, &resp.Diagnostics),
	}

	tflog.Debug(ctx, "Creating CDN origin group", map[string]interface{}{
		"name":          createReq.Name,
		"folder_id":     createReq.FolderId,
		"provider_type": createReq.ProviderType,
	})

	createdID, err := r.api().Create(ctx, createReq)
	if err != nil {
		resp.Diagnostics.AddError("Failed to create CDN origin group", err.Error())
		return
	}

	plan.ID = types.StringValue(strconv.FormatInt(createdID, 10))

	// Read the created resource to populate computed fields.
	if status, err := r.readOriginGroupInto(ctx, &plan); err != nil {
		resp.Diagnostics.AddError("Failed to read CDN origin group after create", err.Error())
		return
	} else if status == readNotFound {
		resp.Diagnostics.AddError("CDN origin group disappeared right after create", fmt.Sprintf("id=%d", createdID))
		return
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *cdnOriginGroupResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state CDNOriginGroupModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	switch result, err := r.readOriginGroupInto(ctx, &state); {
	case err != nil:
		// Real error — surface it, do NOT wipe state.
		resp.Diagnostics.AddError("Failed to read CDN origin group", err.Error())
		return
	case result == readNotFound:
		// Drift: API says the group is gone; clear it from state so the next
		// plan recreates it.
		resp.State.RemoveResource(ctx)
		return
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

func (r *cdnOriginGroupResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan CDNOriginGroupModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	updateTimeout, diags := plan.Timeouts.Update(ctx, yandexCDNOriginGroupDefaultTimeout)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	ctx, cancel := context.WithTimeout(ctx, updateTimeout)
	defer cancel()

	folderID := r.getFolderID(&plan, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}

	groupID, err := strconv.ParseInt(plan.ID.ValueString(), 10, 64)
	if err != nil {
		resp.Diagnostics.AddError("Invalid origin group ID", err.Error())
		return
	}

	var origins []OriginModel
	resp.Diagnostics.Append(plan.Origins.ElementsAs(ctx, &origins, false)...)
	if resp.Diagnostics.HasError() {
		return
	}

	updateReq := &cdn.UpdateOriginGroupRequest{
		FolderId:      folderID,
		OriginGroupId: groupID,
		GroupName:     &wrappers.StringValue{Value: plan.Name.ValueString()},
		UseNext:       &wrappers.BoolValue{Value: plan.UseNext.ValueBool()},
		Origins:       expandOrigins(ctx, origins, &resp.Diagnostics),
	}

	tflog.Debug(ctx, "Updating CDN origin group", map[string]interface{}{
		"id":   plan.ID.ValueString(),
		"name": updateReq.GroupName.Value,
	})

	if err := r.api().Update(ctx, updateReq); err != nil {
		resp.Diagnostics.AddError("Failed to update CDN origin group", err.Error())
		return
	}

	if status, err := r.readOriginGroupInto(ctx, &plan); err != nil {
		resp.Diagnostics.AddError("Failed to read CDN origin group after update", err.Error())
		return
	} else if status == readNotFound {
		resp.Diagnostics.AddError("CDN origin group disappeared right after update", fmt.Sprintf("id=%d", groupID))
		return
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *cdnOriginGroupResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state CDNOriginGroupModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	deleteTimeout, diags := state.Timeouts.Delete(ctx, yandexCDNOriginGroupDefaultTimeout)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	ctx, cancel := context.WithTimeout(ctx, deleteTimeout)
	defer cancel()

	folderID := r.getFolderID(&state, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}

	groupID, err := strconv.ParseInt(state.ID.ValueString(), 10, 64)
	if err != nil {
		resp.Diagnostics.AddError("Invalid origin group ID", err.Error())
		return
	}

	tflog.Debug(ctx, "Deleting CDN origin group", map[string]interface{}{
		"id": state.ID.ValueString(),
	})

	err = r.api().Delete(ctx, &cdn.DeleteOriginGroupRequest{
		FolderId:      folderID,
		OriginGroupId: groupID,
	})
	if err != nil {
		if st, ok := status.FromError(err); ok && st.Code() == codes.NotFound {
			tflog.Info(ctx, "CDN origin group already deleted", map[string]interface{}{
				"id": state.ID.ValueString(),
			})
			return
		}
		resp.Diagnostics.AddError("Failed to delete CDN origin group", err.Error())
		return
	}

	tflog.Info(ctx, "CDN origin group deleted", map[string]interface{}{
		"id": state.ID.ValueString(),
	})
}

func (r *cdnOriginGroupResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	if _, err := strconv.ParseInt(req.ID, 10, 64); err != nil {
		resp.Diagnostics.AddError(
			"Invalid Import ID",
			fmt.Sprintf("Expected origin group ID to be a number, got: %s", req.ID),
		)
		return
	}

	resource.ImportStatePassthroughID(ctx, path.Root("id"), req, resp)
}

// getFolderID returns folder ID from model or provider config.
func (r *cdnOriginGroupResource) getFolderID(model *CDNOriginGroupModel, diags *diag.Diagnostics) string {
	if !model.FolderID.IsNull() && model.FolderID.ValueString() != "" {
		return model.FolderID.ValueString()
	}
	if r.providerConfig.ProviderState.FolderID.ValueString() != "" {
		return r.providerConfig.ProviderState.FolderID.ValueString()
	}
	diags.AddError("folder_id is required", "Please set folder_id in this resource or at provider level")
	return ""
}

type readResult int

const (
	readOK readResult = iota
	readNotFound
)

// readOriginGroupInto reads the origin group from the API and merges it into
// the supplied model. It separates "drift, drop from state" (readNotFound +
// nil error) from "transport / unmarshal failure" (non-nil error) so callers
// can react correctly — wiping state on a transient API error would be wrong.
func (r *cdnOriginGroupResource) readOriginGroupInto(ctx context.Context, state *CDNOriginGroupModel) (readResult, error) {
	folderID := state.FolderID.ValueString()
	if folderID == "" {
		folderID = r.providerConfig.ProviderState.FolderID.ValueString()
	}
	if folderID == "" {
		return readOK, fmt.Errorf("folder_id is not set on state and no default is configured on the provider")
	}

	groupID, err := strconv.ParseInt(state.ID.ValueString(), 10, 64)
	if err != nil {
		return readOK, fmt.Errorf("invalid origin group ID %q: %w", state.ID.ValueString(), err)
	}

	tflog.Debug(ctx, "Reading CDN origin group", map[string]interface{}{
		"id": state.ID.ValueString(),
	})

	originGroup, err := r.api().Get(ctx, &cdn.GetOriginGroupRequest{
		FolderId:      folderID,
		OriginGroupId: groupID,
	})
	if err != nil {
		if st, ok := status.FromError(err); ok && st.Code() == codes.NotFound {
			tflog.Info(ctx, "CDN origin group not found", map[string]interface{}{
				"id": state.ID.ValueString(),
			})
			return readNotFound, nil
		}
		return readOK, err
	}

	var diags diag.Diagnostics
	flattenCDNOriginGroup(ctx, state, originGroup, &diags)
	if diags.HasError() {
		return readOK, fmt.Errorf("flatten origin group: %v", diags.Errors())
	}
	return readOK, nil
}
