package cdn_origin_group

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/yandex-cloud/go-genproto/yandex/cloud/cdn/v1"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
)

// Fixtures-driven tests: replay captured API responses through the resource
// and verify the resulting state shape. Fixtures are produced by
// scripts/cdn_origin_group_capture and live under testdata/fixtures/. If that
// directory is empty the tests skip.

const fixturesDir = "testdata/fixtures"

type fixtureFile struct {
	Step     string          `json:"step"`
	Request  json.RawMessage `json:"request,omitempty"`
	Response json.RawMessage `json:"response,omitempty"`
	GRPCCode string          `json:"grpc_code,omitempty"`
	Error    string          `json:"error,omitempty"`
}

func loadFixture(t *testing.T, name string) fixtureFile {
	t.Helper()
	path := filepath.Join(fixturesDir, name)
	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		t.Skipf("fixture %s not present — run `go run ./scripts/cdn_origin_group_capture` to generate it", path)
	}
	require.NoError(t, err, "read fixture %s", path)
	var f fixtureFile
	require.NoError(t, json.Unmarshal(data, &f), "unmarshal %s", path)
	return f
}

func decodeProto(t *testing.T, raw json.RawMessage, into proto.Message) {
	t.Helper()
	require.NotEmpty(t, raw, "empty proto payload")
	require.NoError(t, (protojson.UnmarshalOptions{DiscardUnknown: true}).Unmarshal(raw, into),
		"protojson unmarshal into %T", into)
}

// TestGolden_ReadAgainstCreatedFixture replays the post-create Get response
// through the resource and verifies the resulting state shape.
func TestGolden_ReadAgainstCreatedFixture(t *testing.T) {
	f := loadFixture(t, "02_get_after_create.json")
	if f.Error != "" {
		t.Skipf("fixture recorded an error (%s); skipping", f.Error)
	}

	var og cdn.OriginGroup
	decodeProto(t, f.Response, &og)
	require.NotZero(t, og.Id, "fixture must contain an origin group with a non-zero id")

	be := &fakeBackend{
		getFn: func(_ context.Context, _ *cdn.GetOriginGroupRequest) (*cdn.OriginGroup, error) {
			return &og, nil
		},
	}
	r := newResourceForTest(be, "")

	state := newState(t, CDNOriginGroupModel{
		ID:       types.StringValue(strconv.FormatInt(og.Id, 10)),
		FolderID: types.StringValue(og.FolderId),
		Name:     types.StringValue("placeholder"),
		UseNext:  types.BoolValue(true),
		Origins: buildOriginsList(t, []OriginModel{
			origin("placeholder", true, false),
		}),
	})
	resp := resource.ReadResponse{State: state}
	r.Read(context.Background(), resource.ReadRequest{State: state}, &resp)

	require.False(t, resp.Diagnostics.HasError(), "%v", resp.Diagnostics)
	got := readState(t, resp.State)
	assert.Equal(t, og.Name, got.Name.ValueString())
	assert.Equal(t, og.UseNext, got.UseNext.ValueBool())
	if og.ProviderType != "" {
		assert.Equal(t, og.ProviderType, got.ProviderType.ValueString())
	}
}

// TestGolden_Lifecycle replays the full captured lifecycle end-to-end:
// Create, Update, Delete each produce a wire request shape that should match
// what the capture script saw. The post-Create Get response is fed back so
// the resource can populate state.
func TestGolden_Lifecycle(t *testing.T) {
	createFx := loadFixture(t, "01_create.json")
	afterCreate := loadFixture(t, "02_get_after_create.json")
	updateFx := loadFixture(t, "03_update.json")
	afterUpdate := loadFixture(t, "04_get_after_update.json")

	var (
		capturedCreate cdn.CreateOriginGroupRequest
		capturedUpdate cdn.UpdateOriginGroupRequest
		postCreate     cdn.OriginGroup
		postUpdate     cdn.OriginGroup
	)
	decodeProto(t, createFx.Request, &capturedCreate)
	decodeProto(t, updateFx.Request, &capturedUpdate)
	decodeProto(t, afterCreate.Response, &postCreate)
	decodeProto(t, afterUpdate.Response, &postUpdate)

	createdID := postCreate.Id
	require.NotZero(t, createdID, "post-create fixture must include an id")

	getCalls := 0
	be := &fakeBackend{
		createFn: func(_ context.Context, _ *cdn.CreateOriginGroupRequest) (int64, error) {
			return createdID, nil
		},
		getFn: func(_ context.Context, _ *cdn.GetOriginGroupRequest) (*cdn.OriginGroup, error) {
			getCalls++
			if getCalls == 1 {
				return &postCreate, nil
			}
			return &postUpdate, nil
		},
	}
	r := newResourceForTest(be, "")

	// --- Create ---
	planCreate := newPlan(t, CDNOriginGroupModel{
		FolderID:     types.StringValue(capturedCreate.FolderId),
		Name:         types.StringValue(capturedCreate.Name),
		ProviderType: types.StringValue(capturedCreate.ProviderType),
		UseNext:      types.BoolValue(capturedCreate.GetUseNext().GetValue()),
		Origins:      buildOriginsList(t, originsFromParams(capturedCreate.Origins)),
	})
	respCreate := resource.CreateResponse{State: emptyState(t)}
	r.Create(context.Background(), resource.CreateRequest{Plan: planCreate}, &respCreate)
	require.False(t, respCreate.Diagnostics.HasError(), "%v", respCreate.Diagnostics)
	require.Len(t, be.createReqs, 1)
	assertCreateMatches(t, &capturedCreate, be.createReqs[0])

	stateAfterCreate := readState(t, respCreate.State)
	assert.Equal(t, strconv.FormatInt(createdID, 10), stateAfterCreate.ID.ValueString())

	// --- Update ---
	planUpdate := newPlan(t, CDNOriginGroupModel{
		ID:           types.StringValue(strconv.FormatInt(createdID, 10)),
		FolderID:     types.StringValue(capturedUpdate.FolderId),
		Name:         types.StringValue(capturedUpdate.GetGroupName().GetValue()),
		ProviderType: stateAfterCreate.ProviderType,
		UseNext:      types.BoolValue(capturedUpdate.GetUseNext().GetValue()),
		Origins:      buildOriginsList(t, originsFromParams(capturedUpdate.Origins)),
	})
	respUpdate := resource.UpdateResponse{State: respCreate.State}
	r.Update(context.Background(), resource.UpdateRequest{Plan: planUpdate, State: respCreate.State}, &respUpdate)
	require.False(t, respUpdate.Diagnostics.HasError(), "%v", respUpdate.Diagnostics)
	require.Len(t, be.updateReqs, 1)
	assertUpdateMatches(t, &capturedUpdate, be.updateReqs[0])

	// --- Delete ---
	respDelete := resource.DeleteResponse{State: respUpdate.State}
	r.Delete(context.Background(), resource.DeleteRequest{State: respUpdate.State}, &respDelete)
	require.False(t, respDelete.Diagnostics.HasError(), "%v", respDelete.Diagnostics)
	require.Len(t, be.deleteReqs, 1)
	assert.Equal(t, createdID, be.deleteReqs[0].OriginGroupId)
	assert.Equal(t, capturedUpdate.FolderId, be.deleteReqs[0].FolderId)
}

func originsFromParams(in []*cdn.OriginParams) []OriginModel {
	out := make([]OriginModel, 0, len(in))
	for _, p := range in {
		out = append(out, OriginModel{
			Source:        types.StringValue(p.Source),
			OriginGroupID: types.StringNull(),
			Enabled:       types.BoolValue(p.Enabled),
			Backup:        types.BoolValue(p.Backup),
		})
	}
	return out
}

func assertCreateMatches(t *testing.T, want, got *cdn.CreateOriginGroupRequest) {
	t.Helper()
	assert.Equal(t, want.FolderId, got.FolderId, "Create.FolderId")
	assert.Equal(t, want.Name, got.Name, "Create.Name")
	assert.Equal(t, want.ProviderType, got.ProviderType, "Create.ProviderType")
	assert.Equal(t, want.GetUseNext().GetValue(), got.GetUseNext().GetValue(), "Create.UseNext")
	require.Equal(t, len(want.Origins), len(got.Origins), "Create.Origins count")
	for i := range want.Origins {
		assert.Equal(t, want.Origins[i].Source, got.Origins[i].Source, "Create.Origins[%d].Source", i)
		assert.Equal(t, want.Origins[i].Enabled, got.Origins[i].Enabled, "Create.Origins[%d].Enabled", i)
		assert.Equal(t, want.Origins[i].Backup, got.Origins[i].Backup, "Create.Origins[%d].Backup", i)
	}
}

func assertUpdateMatches(t *testing.T, want, got *cdn.UpdateOriginGroupRequest) {
	t.Helper()
	assert.Equal(t, want.FolderId, got.FolderId, "Update.FolderId")
	assert.Equal(t, want.OriginGroupId, got.OriginGroupId, "Update.OriginGroupId")
	assert.Equal(t, want.GetGroupName().GetValue(), got.GetGroupName().GetValue(), "Update.GroupName")
	assert.Equal(t, want.GetUseNext().GetValue(), got.GetUseNext().GetValue(), "Update.UseNext")
	require.Equal(t, len(want.Origins), len(got.Origins), "Update.Origins count")
	for i := range want.Origins {
		assert.Equal(t, want.Origins[i].Source, got.Origins[i].Source, "Update.Origins[%d].Source", i)
	}
}
