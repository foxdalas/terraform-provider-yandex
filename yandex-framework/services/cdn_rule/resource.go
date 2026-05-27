package cdn_rule

import (
	"context"
	"fmt"
	"regexp"
	"strconv"
	"time"

	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"
	"github.com/yandex-cloud/go-genproto/yandex/cloud/cdn/v1"
	provider_config "github.com/yandex-cloud/terraform-provider-yandex/yandex-framework/provider/config"
	cdn_resource "github.com/yandex-cloud/terraform-provider-yandex/yandex-framework/services/cdn_resource"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

const (
	yandexCDNRuleDefaultTimeout = 5 * time.Minute
)

// cdnRuleIDRegex is compiled once at package initialization for performance.
// Format: resource_id/rule_id (e.g., "bc851ft45fne********/123")
var cdnRuleIDRegex = regexp.MustCompile(`^([^/]+)/(\d+)$`)

// Ensure provider defined types fully satisfy framework interfaces
var (
	_ resource.Resource                = &cdnRuleResource{}
	_ resource.ResourceWithConfigure   = &cdnRuleResource{}
	_ resource.ResourceWithImportState = &cdnRuleResource{}
)

type cdnRuleResource struct {
	providerConfig *provider_config.Config
	// backend, when non-nil, replaces the SDK-backed implementation derived
	// from providerConfig. Set by tests; nil in production.
	backend ruleBackend
}

// NewResource creates a new CDN rule resource
func NewResource() resource.Resource {
	return &cdnRuleResource{}
}

func (r *cdnRuleResource) api() ruleBackend {
	if r.backend != nil {
		return r.backend
	}
	return newSDKBackend(r.providerConfig)
}

func (r *cdnRuleResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_cdn_rule"
}

func (r *cdnRuleResource) Schema(ctx context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = CDNRuleSchema(ctx)
}

func (r *cdnRuleResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
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

func (r *cdnRuleResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan CDNRuleModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	createTimeout, diags := plan.Timeouts.Create(ctx, yandexCDNRuleDefaultTimeout)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	ctx, cancel := context.WithTimeout(ctx, createTimeout)
	defer cancel()

	tflog.Debug(ctx, "Creating CDN rule", map[string]interface{}{
		"resource_id":  plan.ResourceID.ValueString(),
		"name":         plan.Name.ValueString(),
		"rule_pattern": plan.RulePattern.ValueString(),
	})

	options := expandOptions(ctx, &plan, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}

	resourceID := plan.ResourceID.ValueString()
	request := &cdn.CreateResourceRuleRequest{
		ResourceId:  resourceID,
		Name:        plan.Name.ValueString(),
		RulePattern: plan.RulePattern.ValueString(),
		Weight:      plan.Weight.ValueInt64(),
		Options:     options,
	}

	ruleID, err := r.api().Create(ctx, request)
	if err != nil {
		resp.Diagnostics.AddError(
			"Failed to create CDN rule",
			fmt.Sprintf("Error creating CDN rule: %s", err),
		)
		return
	}

	ruleIDStr := strconv.FormatInt(ruleID, 10)
	compositeID := fmt.Sprintf("%s/%s", resourceID, ruleIDStr)
	plan.ID = types.StringValue(compositeID)
	plan.RuleID = types.StringValue(ruleIDStr)

	tflog.Info(ctx, "CDN rule created successfully", map[string]interface{}{
		"id": compositeID,
	})

	switch result, err := r.readRuleInto(ctx, &plan); {
	case err != nil:
		resp.Diagnostics.AddError("Failed to read CDN rule after create", err.Error())
		return
	case result == readNotFound:
		resp.Diagnostics.AddError(
			"CDN rule disappeared right after create",
			fmt.Sprintf("id=%s", compositeID),
		)
		return
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *cdnRuleResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state CDNRuleModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	readTimeout, diags := state.Timeouts.Read(ctx, yandexCDNRuleDefaultTimeout)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	ctx, cancel := context.WithTimeout(ctx, readTimeout)
	defer cancel()

	switch result, err := r.readRuleInto(ctx, &state); {
	case err != nil:
		// Real error — surface it, do NOT wipe state.
		resp.Diagnostics.AddError("Failed to read CDN rule", err.Error())
		return
	case result == readNotFound:
		// Drift: API says the rule is gone; clear it so the next plan recreates.
		resp.State.RemoveResource(ctx)
		return
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

func (r *cdnRuleResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan CDNRuleModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	var state CDNRuleModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	updateTimeout, diags := plan.Timeouts.Update(ctx, yandexCDNRuleDefaultTimeout)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	ctx, cancel := context.WithTimeout(ctx, updateTimeout)
	defer cancel()

	resourceID, ruleID, err := parseCDNRuleID(plan.ID.ValueString())
	if err != nil {
		resp.Diagnostics.AddError(
			"Invalid ID format",
			fmt.Sprintf("Error parsing CDN rule ID: %s", err),
		)
		return
	}

	tflog.Debug(ctx, "Updating CDN rule", map[string]interface{}{
		"id":   plan.ID.ValueString(),
		"name": plan.Name.ValueString(),
	})

	// CRITICAL: ResourceOptions uses "replace semantics" — sending Options
	// REPLACES ALL options completely, so we MUST merge plan + state to keep
	// Optional+Computed fields that aren't being changed. Same pattern as
	// cdn_resource's Update.
	options, mergeErr := r.mergedOptionsForUpdate(ctx, &plan, &state, &resp.Diagnostics)
	if mergeErr || resp.Diagnostics.HasError() {
		return
	}

	// CRITICAL: Name and RulePattern in proto3 UpdateResourceRuleRequest are
	// optional, BUT empty strings ("") are INVALID and cause Internal errors
	// on server validation. Proto3 doesn't distinguish "unset" vs "empty
	// string" for regular string fields, so fall back to state values if
	// plan contains empty strings.
	name := plan.Name.ValueString()
	if name == "" {
		name = state.Name.ValueString()
	}
	rulePattern := plan.RulePattern.ValueString()
	if rulePattern == "" {
		rulePattern = state.RulePattern.ValueString()
	}

	weight := plan.Weight.ValueInt64()
	updateReq := &cdn.UpdateResourceRuleRequest{
		ResourceId:  resourceID,
		RuleId:      ruleID,
		Name:        name,
		RulePattern: rulePattern,
		Weight:      &weight,
		Options:     options,
	}

	newRuleID, err := r.api().Update(ctx, updateReq)
	if err != nil {
		resp.Diagnostics.AddError(
			"Failed to update CDN rule",
			fmt.Sprintf("Error updating CDN rule: %s", err),
		)
		return
	}

	// CDN ResourceRules.Update has "clone with new ID" semantics: a successful
	// Update creates a fresh rule with a new ID containing the requested
	// changes, while the old rule lingers and would otherwise leak. The
	// resource compensates by (1) re-pointing state to the new ID and
	// (2) deleting the old rule. If newRuleID is 0 (zero value from a missing
	// metadata) we fall back to the request's ruleID — the old behavior.
	effectiveRuleID := newRuleID
	if effectiveRuleID == 0 {
		effectiveRuleID = ruleID
	}
	if effectiveRuleID != ruleID {
		tflog.Info(ctx, "CDN rule Update renumbered the rule; cleaning up the stale entity", map[string]interface{}{
			"old_rule_id": ruleID,
			"new_rule_id": effectiveRuleID,
		})
		if cleanupErr := r.api().Delete(ctx, &cdn.DeleteResourceRuleRequest{
			ResourceId: resourceID,
			RuleId:     ruleID,
		}); cleanupErr != nil {
			if st, ok := status.FromError(cleanupErr); !(ok && st.Code() == codes.NotFound) {
				resp.Diagnostics.AddWarning(
					"Stale CDN rule could not be deleted after Update",
					fmt.Sprintf("Update renumbered rule %d → %d, but deleting the old %d failed: %s. "+
						"The new rule is in place; you may need to delete the old rule manually.",
						ruleID, effectiveRuleID, ruleID, cleanupErr),
				)
			}
		}
		newID := fmt.Sprintf("%s/%d", resourceID, effectiveRuleID)
		plan.ID = types.StringValue(newID)
		plan.RuleID = types.StringValue(strconv.FormatInt(effectiveRuleID, 10))
	}

	tflog.Info(ctx, "CDN rule updated successfully", map[string]interface{}{
		"id": plan.ID.ValueString(),
	})

	switch result, err := r.readRuleInto(ctx, &plan); {
	case err != nil:
		resp.Diagnostics.AddError("Failed to read CDN rule after update", err.Error())
		return
	case result == readNotFound:
		resp.Diagnostics.AddError(
			"CDN rule disappeared right after update",
			fmt.Sprintf("id=%s", plan.ID.ValueString()),
		)
		return
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *cdnRuleResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state CDNRuleModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	deleteTimeout, diags := state.Timeouts.Delete(ctx, yandexCDNRuleDefaultTimeout)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	ctx, cancel := context.WithTimeout(ctx, deleteTimeout)
	defer cancel()

	resourceID, ruleID, err := parseCDNRuleID(state.ID.ValueString())
	if err != nil {
		resp.Diagnostics.AddError(
			"Invalid ID format",
			fmt.Sprintf("Error parsing CDN rule ID: %s", err),
		)
		return
	}

	tflog.Debug(ctx, "Deleting CDN rule", map[string]interface{}{
		"id": state.ID.ValueString(),
	})

	err = r.api().Delete(ctx, &cdn.DeleteResourceRuleRequest{
		ResourceId: resourceID,
		RuleId:     ruleID,
	})
	if err != nil {
		if st, ok := status.FromError(err); ok && st.Code() == codes.NotFound {
			tflog.Debug(ctx, "CDN rule already deleted")
			return
		}
		resp.Diagnostics.AddError(
			"Failed to delete CDN rule",
			fmt.Sprintf("Error deleting CDN rule: %s", err),
		)
		return
	}

	tflog.Info(ctx, "CDN rule deleted successfully", map[string]interface{}{
		"id": state.ID.ValueString(),
	})
}

func (r *cdnRuleResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	resourceID, ruleID, err := parseCDNRuleID(req.ID)
	if err != nil {
		resp.Diagnostics.AddError(
			"Invalid import ID format",
			fmt.Sprintf("Expected format: resource_id/rule_id, got: %s", req.ID),
		)
		return
	}

	tflog.Debug(ctx, "Importing CDN rule", map[string]interface{}{
		"id":          req.ID,
		"resource_id": resourceID,
		"rule_id":     ruleID,
	})

	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("id"), req.ID)...)
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("resource_id"), resourceID)...)
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("rule_id"), strconv.FormatInt(ruleID, 10))...)
}

type readResult int

const (
	readOK readResult = iota
	readNotFound
)

// readRuleInto reads the rule from the API and merges it into the supplied
// model. It separates "drift, drop from state" (readNotFound + nil error)
// from "transport / unmarshal failure" (non-nil error) so callers can react
// correctly — wiping state on a transient API error would be wrong.
func (r *cdnRuleResource) readRuleInto(ctx context.Context, model *CDNRuleModel) (readResult, error) {
	resourceID, ruleID, err := parseCDNRuleID(model.ID.ValueString())
	if err != nil {
		return readOK, fmt.Errorf("invalid CDN rule ID %q: %w", model.ID.ValueString(), err)
	}

	tflog.Debug(ctx, "Reading CDN rule from API", map[string]interface{}{
		"resource_id": resourceID,
		"rule_id":     ruleID,
	})

	rule, err := r.api().Get(ctx, &cdn.GetResourceRuleRequest{
		ResourceId: resourceID,
		RuleId:     ruleID,
	})
	if err != nil {
		if st, ok := status.FromError(err); ok && st.Code() == codes.NotFound {
			tflog.Info(ctx, "CDN rule not found", map[string]interface{}{
				"id": model.ID.ValueString(),
			})
			return readNotFound, nil
		}
		return readOK, err
	}

	model.ResourceID = types.StringValue(resourceID)
	model.RuleID = types.StringValue(strconv.FormatInt(rule.Id, 10))
	model.Name = types.StringValue(rule.Name)
	model.RulePattern = types.StringValue(rule.RulePattern)
	model.Weight = types.Int64Value(rule.Weight)

	var diags diag.Diagnostics
	model.Options = flattenOptions(ctx, rule.Options, &diags)
	if diags.HasError() {
		return readOK, fmt.Errorf("flatten rule options: %v", diags.Errors())
	}
	return readOK, nil
}

// mergedOptionsForUpdate computes the *cdn.ResourceOptions to send on Update.
// When plan.Options matches state.Options exactly, returns nil to skip the
// options update entirely (a real API optimization). Otherwise merges
// Optional+Computed fields from state into plan to preserve unchanged values
// across the ResourceOptions "replace-all" semantics.
//
// The bool return is true when the diagnostics already carry an error and the
// caller should bail out — Go doesn't have an obvious "abort sentinel" type
// here.
func (r *cdnRuleResource) mergedOptionsForUpdate(ctx context.Context, plan, state *CDNRuleModel, diags *diag.Diagnostics) (*cdn.ResourceOptions, bool) {
	if plan.Options.Equal(state.Options) {
		return nil, false
	}

	var planOptionsModels, stateOptionsModels []cdn_resource.CDNOptionsModel
	if !plan.Options.IsNull() && len(plan.Options.Elements()) > 0 {
		diags.Append(plan.Options.ElementsAs(ctx, &planOptionsModels, false)...)
	}
	if !state.Options.IsNull() && len(state.Options.Elements()) > 0 {
		diags.Append(state.Options.ElementsAs(ctx, &stateOptionsModels, false)...)
	}
	if diags.HasError() {
		return nil, true
	}

	if len(planOptionsModels) == 0 {
		return expandOptions(ctx, plan, diags), diags.HasError()
	}

	merged := planOptionsModels[0]
	if len(stateOptionsModels) > 0 {
		stateOpt := stateOptionsModels[0]
		merged.EdgeCacheSettings = cdn_resource.MergeField(merged.EdgeCacheSettings, stateOpt.EdgeCacheSettings)
		merged.BrowserCacheSettings = cdn_resource.MergeField(merged.BrowserCacheSettings, stateOpt.BrowserCacheSettings)
		merged.GzipOn = cdn_resource.MergeField(merged.GzipOn, stateOpt.GzipOn)
		merged.RedirectHttpToHttps = cdn_resource.MergeField(merged.RedirectHttpToHttps, stateOpt.RedirectHttpToHttps)
		merged.DisableProxyForceRanges = cdn_resource.MergeField(merged.DisableProxyForceRanges, stateOpt.DisableProxyForceRanges)
		merged.Rewrite = cdn_resource.MergeField(merged.Rewrite, stateOpt.Rewrite)
		merged.Websockets = cdn_resource.MergeField(merged.Websockets, stateOpt.Websockets)
		merged.GeoACL = cdn_resource.MergeField(merged.GeoACL, stateOpt.GeoACL)
		merged.ReferrerACL = cdn_resource.MergeField(merged.ReferrerACL, stateOpt.ReferrerACL)
		merged.HeaderFilter = cdn_resource.MergeField(merged.HeaderFilter, stateOpt.HeaderFilter)
		merged.FollowRedirects = cdn_resource.MergeField(merged.FollowRedirects, stateOpt.FollowRedirects)
		merged.StaticResponseOpt = cdn_resource.MergeField(merged.StaticResponseOpt, stateOpt.StaticResponseOpt)
	}

	optionsList, d := types.ListValueFrom(ctx, types.ObjectType{
		AttrTypes: cdn_resource.GetCDNOptionsAttrTypes(),
	}, []cdn_resource.CDNOptionsModel{merged})
	diags.Append(d...)
	if diags.HasError() {
		return nil, true
	}

	mergedPlan := *plan
	mergedPlan.Options = optionsList
	return expandOptions(ctx, &mergedPlan, diags), diags.HasError()
}

// parseCDNRuleID parses composite ID format: resource_id/rule_id
func parseCDNRuleID(id string) (string, int64, error) {
	parts := cdnRuleIDRegex.FindStringSubmatch(id)
	if len(parts) != 3 {
		return "", 0, fmt.Errorf("invalid CDN rule ID format: %s (expected: resource_id/rule_id)", id)
	}

	ruleID, err := strconv.ParseInt(parts[2], 10, 64)
	if err != nil {
		return "", 0, fmt.Errorf("invalid rule ID in CDN rule ID %s: %w", id, err)
	}

	return parts[1], ruleID, nil
}
