package cdn_resource

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"testing"

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

func TestResourceGolden_Lifecycle(t *testing.T) {
	createFx := loadResourceFixture(t, "01_create.json")
	afterCreate := loadResourceFixture(t, "02_get_after_create.json")
	updateFx := loadResourceFixture(t, "03_update.json")
	afterUpdate := loadResourceFixture(t, "04_get_after_update.json")

	var (
		capturedCreate cdn.CreateResourceRequest
		capturedUpdate cdn.UpdateResourceRequest
		postCreate     cdn.Resource
		postUpdate     cdn.Resource
	)
	decodeResourceProto(t, createFx.Request, &capturedCreate)
	decodeResourceProto(t, updateFx.Request, &capturedUpdate)
	decodeResourceProto(t, afterCreate.Response, &postCreate)
	decodeResourceProto(t, afterUpdate.Response, &postUpdate)

	createdID := postCreate.Id
	require.NotEmpty(t, createdID, "post-create fixture must include an id")

	getCalls := 0
	be := &fakeResourceBackend{
		createFn: func(_ context.Context, _ *cdn.CreateResourceRequest) (string, error) {
			return createdID, nil
		},
		getFn: func(_ context.Context, _ *cdn.GetResourceRequest) (*cdn.Resource, error) {
			getCalls++
			if getCalls == 1 {
				return &postCreate, nil
			}
			return &postUpdate, nil
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
	r.Create(context.Background(), resource.CreateRequest{Plan: planCreate}, &respCreate)
	require.False(t, respCreate.Diagnostics.HasError(), "%v", respCreate.Diagnostics)
	require.Len(t, be.createReqs, 1)
	assertResourceCreateMatches(t, &capturedCreate, be.createReqs[0])

	stateAfterCreate := readResourceModel(t, respCreate.State)
	assert.Equal(t, createdID, stateAfterCreate.ID.ValueString(), "resource id from metadata")

	// --- Update ---
	planUpdate := newResourcePlan(t, CDNResourceModel{
		ID:             stateAfterCreate.ID,
		Cname:          stateAfterCreate.Cname,
		OriginGroupID:  stateAfterCreate.OriginGroupID,
		Active:         types.BoolValue(capturedUpdate.GetActive().GetValue()),
		OriginProtocol: stateAfterCreate.OriginProtocol,
	})
	respUpdate := resource.UpdateResponse{State: respCreate.State}
	r.Update(context.Background(), resource.UpdateRequest{Plan: planUpdate, State: respCreate.State}, &respUpdate)
	require.False(t, respUpdate.Diagnostics.HasError(), "%v", respUpdate.Diagnostics)

	// --- Delete ---
	respDelete := resource.DeleteResponse{State: respUpdate.State}
	r.Delete(context.Background(), resource.DeleteRequest{State: respUpdate.State}, &respDelete)
	require.False(t, respDelete.Diagnostics.HasError(), "%v", respDelete.Diagnostics)
	require.Len(t, be.deleteReqs, 1)
	assert.Equal(t, createdID, be.deleteReqs[0].ResourceId)
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
