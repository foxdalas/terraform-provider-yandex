package cdn_resource

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/yandex-cloud/go-genproto/yandex/cloud/cdn/v1"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
)

// Fixtures-driven tests: replay captured API responses through the resource
// and verify state. Produced by scripts/cdn_resource_capture; skip when absent.

const resourceFixturesDir = "testdata/fixtures"

type resourceFixtureFile struct {
	Step     string          `json:"step"`
	Request  json.RawMessage `json:"request,omitempty"`
	Response json.RawMessage `json:"response,omitempty"`
	GRPCCode string          `json:"grpc_code,omitempty"`
	Error    string          `json:"error,omitempty"`
}

func loadResourceFixture(t *testing.T, name string) resourceFixtureFile {
	t.Helper()
	path := filepath.Join(resourceFixturesDir, name)
	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		t.Skipf("fixture %s not present — run `go run ./scripts/cdn_resource_capture` to generate it", path)
	}
	require.NoError(t, err, "read fixture %s", path)
	var f resourceFixtureFile
	require.NoError(t, json.Unmarshal(data, &f), "unmarshal %s", path)
	return f
}

func decodeResourceProto(t *testing.T, raw json.RawMessage, into proto.Message) {
	t.Helper()
	require.NotEmpty(t, raw, "empty proto payload")
	require.NoError(t, (protojson.UnmarshalOptions{DiscardUnknown: true}).Unmarshal(raw, into),
		"protojson unmarshal into %T", into)
}

func TestResourceGolden_ReadAgainstCreatedFixture(t *testing.T) {
	f := loadResourceFixture(t, "02_get_after_create.json")
	if f.Error != "" {
		t.Skipf("fixture recorded an error (%s); skipping", f.Error)
	}

	var resource cdn.Resource
	decodeResourceProto(t, f.Response, &resource)
	require.NotEmpty(t, resource.Id, "fixture must contain a resource with a non-empty id")

	be := &fakeResourceBackend{
		getFn: func(_ context.Context, _ *cdn.GetResourceRequest) (*cdn.Resource, error) {
			return &resource, nil
		},
	}
	r := newResourceForTest(be)

	state := newResourceState(t, CDNResourceModel{
		ID:    types.StringValue(resource.Id),
		Cname: types.StringValue("placeholder"),
	})
	resp := readResponse(state)
	r.Read(context.Background(), readRequest(state), &resp)

	require.False(t, resp.Diagnostics.HasError(), "%v", resp.Diagnostics)

	got := readResourceModel(t, resp.State)
	assert.Equal(t, resource.Cname, got.Cname.ValueString())
	assert.Equal(t, resource.FolderId, got.FolderID.ValueString())
}

// TestResourceGolden_Lifecycle replays the captured Create + three Updates and,
// after each Update, asserts the resource's options round-trip: the options
// Terraform planned must equal the options the provider produces from the API
// read-back. A mismatch is exactly the "Provider produced inconsistent result
// after apply" failure Terraform raises in production.
//
// The three updates are captured with contrasting values: update #1 enables
// everything, update #2 flips booleans to false (the tristate case where the
// API echoes a sent {Enabled:true, Value:false} back as disabled), update #3
// disables/clears options.
func TestResourceGolden_Lifecycle(t *testing.T) {
	ctx := context.Background()

	createFx := loadResourceFixture(t, "01_create.json")
	afterCreate := loadResourceFixture(t, "02_get_after_create.json")

	updateSteps := []struct {
		name       string
		updateFile string
		getFile    string
		// fullRoundTrip asserts the entire options block round-trips. Disabled
		// for update #3 because the API normalizes several "disable" requests
		// (e.g. edge_cache enabled=false → value 0) in ways unrelated to the
		// tristate-boolean behavior this test guards.
		fullRoundTrip bool
	}{
		{"update1_all_on", "03_update.json", "04_get_after_update.json", true},
		{"update2_flipped", "05_update.json", "06_get_after_update_2.json", true},
		{"update3_disabled", "07_update.json", "08_get_after_update_3.json", false},
	}

	var capturedCreate cdn.CreateResourceRequest
	var postCreate cdn.Resource
	decodeResourceProto(t, createFx.Request, &capturedCreate)
	decodeResourceProto(t, afterCreate.Response, &postCreate)

	createdID := postCreate.Id
	require.NotEmpty(t, createdID, "post-create fixture must include an id")

	// GET responses returned in order: once after Create, then once per Update.
	getResponses := []*cdn.Resource{&postCreate}
	capturedUpdates := make([]*cdn.UpdateResourceRequest, len(updateSteps))
	for i, s := range updateSteps {
		updateFx := loadResourceFixture(t, s.updateFile)
		getFx := loadResourceFixture(t, s.getFile)
		var ureq cdn.UpdateResourceRequest
		var gresp cdn.Resource
		decodeResourceProto(t, updateFx.Request, &ureq)
		decodeResourceProto(t, getFx.Response, &gresp)
		capturedUpdates[i] = &ureq
		getResponses = append(getResponses, &gresp)
	}

	getCalls := 0
	be := &fakeResourceBackend{
		createFn: func(_ context.Context, _ *cdn.CreateResourceRequest) (string, error) {
			return createdID, nil
		},
		getFn: func(_ context.Context, _ *cdn.GetResourceRequest) (*cdn.Resource, error) {
			r := getResponses[len(getResponses)-1]
			if getCalls < len(getResponses) {
				r = getResponses[getCalls]
			}
			getCalls++
			return r, nil
		},
	}
	r := newResourceForTest(be)

	// --- Create ---
	planCreate := newResourcePlan(t, CDNResourceModel{
		Cname:          types.StringValue(capturedCreate.Cname),
		OriginGroupID:  types.StringValue(strconv.FormatInt(capturedCreate.GetOrigin().GetOriginGroupId(), 10)),
		Active:         types.BoolValue(capturedCreate.GetActive().GetValue()),
		OriginProtocol: types.StringValue(flattenOriginProtocolString(capturedCreate.OriginProtocol)),
	})
	respCreate := resource.CreateResponse{State: emptyResourceState(t)}
	r.Create(ctx, resource.CreateRequest{Plan: planCreate}, &respCreate)
	require.False(t, respCreate.Diagnostics.HasError(), "%v", respCreate.Diagnostics)
	require.Len(t, be.createReqs, 1)
	assertResourceCreateMatches(t, &capturedCreate, be.createReqs[0])

	stateAfterCreate := readResourceModel(t, respCreate.State)
	assert.Equal(t, createdID, stateAfterCreate.ID.ValueString(), "resource id from metadata")

	state := respCreate.State

	// --- Updates ---
	for i, s := range updateSteps {
		cu := capturedUpdates[i]
		prev := readResourceModel(t, state)

		// planOptions models "what the user configured" for this update: flatten
		// the options the request carried. This is the value Terraform commits to
		// the plan and therefore the value the post-apply read must reproduce.
		var d diag.Diagnostics
		planOptions := FlattenCDNResourceOptions(ctx, cu.GetOptions(), nullResourceOptionsList(), &d)
		require.False(t, d.HasError(), "%s: flatten plan options: %v", s.name, d)

		plan := newResourcePlan(t, CDNResourceModel{
			ID:             prev.ID,
			Cname:          prev.Cname,
			OriginGroupID:  prev.OriginGroupID,
			Active:         types.BoolValue(cu.GetActive().GetValue()),
			OriginProtocol: types.StringValue(flattenOriginProtocolString(cu.OriginProtocol)),
			Options:        planOptions,
		})

		respUpdate := resource.UpdateResponse{State: state}
		r.Update(ctx, resource.UpdateRequest{Plan: plan, State: state}, &respUpdate)
		require.False(t, respUpdate.Diagnostics.HasError(), "%s: %v", s.name, respUpdate.Diagnostics)

		newState := readResourceModel(t, respUpdate.State)

		if s.fullRoundTrip {
			assert.True(t, planOptions.Equal(newState.Options),
				"%s: options not consistent after apply\n  plan:  %s\n  state: %s",
				s.name, planOptions.String(), newState.Options.String())
		}

		// The four independent tristate booleans must match the plan regardless of
		// step: the API echoes a sent false back as disabled, and the provider must
		// not let that collapse a planned false into null.
		assertTristateBoolsConsistent(t, s.name, planOptions, newState.Options)

		state = respUpdate.State
	}

	// --- Delete ---
	respDelete := resource.DeleteResponse{State: state}
	r.Delete(ctx, resource.DeleteRequest{State: state}, &respDelete)
	require.False(t, respDelete.Diagnostics.HasError(), "%v", respDelete.Diagnostics)
	require.Len(t, be.deleteReqs, 1)
	assert.Equal(t, createdID, be.deleteReqs[0].ResourceId)
}

// assertTristateBoolsConsistent checks the independent boolean options (the ones
// flattened via flattenBoolOption) survive a Plan→Apply round-trip. These are
// the fields the CDN API normalizes a false into a disabled option for, so they
// are where the inconsistency bug surfaces.
func assertTristateBoolsConsistent(t *testing.T, step string, plan, state types.List) {
	t.Helper()
	planOpt := singleOptionsModel(t, plan)
	stateOpt := singleOptionsModel(t, state)
	if planOpt == nil || stateOpt == nil {
		return
	}
	assert.True(t, planOpt.Slice.Equal(stateOpt.Slice),
		"%s: slice plan=%s state=%s", step, planOpt.Slice, stateOpt.Slice)
	assert.True(t, planOpt.IgnoreCookie.Equal(stateOpt.IgnoreCookie),
		"%s: ignore_cookie plan=%s state=%s", step, planOpt.IgnoreCookie, stateOpt.IgnoreCookie)
	assert.True(t, planOpt.ProxyCacheMethodsSet.Equal(stateOpt.ProxyCacheMethodsSet),
		"%s: proxy_cache_methods_set plan=%s state=%s", step, planOpt.ProxyCacheMethodsSet, stateOpt.ProxyCacheMethodsSet)
	assert.True(t, planOpt.DisableProxyForceRanges.Equal(stateOpt.DisableProxyForceRanges),
		"%s: disable_proxy_force_ranges plan=%s state=%s", step, planOpt.DisableProxyForceRanges, stateOpt.DisableProxyForceRanges)
}

// singleOptionsModel extracts the lone CDNOptionsModel from an options list, or
// nil when the list is null/empty.
func singleOptionsModel(t *testing.T, list types.List) *CDNOptionsModel {
	t.Helper()
	if list.IsNull() || list.IsUnknown() || len(list.Elements()) == 0 {
		return nil
	}
	var models []CDNOptionsModel
	diags := list.ElementsAs(context.Background(), &models, false)
	require.False(t, diags.HasError(), "extract options model: %v", diags)
	if len(models) == 0 {
		return nil
	}
	return &models[0]
}

func assertResourceCreateMatches(t *testing.T, want, got *cdn.CreateResourceRequest) {
	t.Helper()
	assert.Equal(t, want.Cname, got.Cname, "Create.Cname")
	assert.Equal(t, want.OriginProtocol, got.OriginProtocol, "Create.OriginProtocol")
	assert.Equal(t, want.GetOrigin().GetOriginGroupId(), got.GetOrigin().GetOriginGroupId(), "Create.Origin.OriginGroupId")
}

func readResponse(st tfsdk.State) resource.ReadResponse {
	return resource.ReadResponse{State: st}
}

func readRequest(st tfsdk.State) resource.ReadRequest {
	return resource.ReadRequest{State: st}
}

func flattenOriginProtocolString(p cdn.OriginProtocol) string {
	switch p {
	case cdn.OriginProtocol_HTTP:
		return "http"
	case cdn.OriginProtocol_HTTPS:
		return "https"
	case cdn.OriginProtocol_MATCH:
		return "match"
	default:
		return "http"
	}
}
