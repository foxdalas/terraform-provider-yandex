package cdn_rule

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
// and verify state. Produced by scripts/cdn_rule_capture; skip when absent.

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
		t.Skipf("fixture %s not present — run `go run ./scripts/cdn_rule_capture` to generate it", path)
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

func TestGolden_ReadAgainstCreatedFixture(t *testing.T) {
	f := loadFixture(t, "02_get_after_create.json")
	if f.Error != "" {
		t.Skipf("fixture recorded an error (%s); skipping", f.Error)
	}

	var rule cdn.Rule
	decodeProto(t, f.Response, &rule)
	require.NotZero(t, rule.Id, "fixture must contain a rule with a non-zero id")

	be := &fakeBackend{
		getFn: func(_ context.Context, _ *cdn.GetResourceRuleRequest) (*cdn.Rule, error) {
			return &rule, nil
		},
	}
	r := newResourceForTest(be)

	state := newState(t, CDNRuleModel{
		ID:          types.StringValue("from-fixture/" + strconv.FormatInt(rule.Id, 10)),
		ResourceID:  types.StringValue("from-fixture"),
		RuleID:      types.StringValue(strconv.FormatInt(rule.Id, 10)),
		Name:        types.StringValue("placeholder"),
		RulePattern: types.StringValue("placeholder"),
		Weight:      types.Int64Value(0),
	})
	resp := resource.ReadResponse{State: state}
	r.Read(context.Background(), resource.ReadRequest{State: state}, &resp)

	require.False(t, resp.Diagnostics.HasError(), "%v", resp.Diagnostics)

	got := readState(t, resp.State)
	assert.Equal(t, rule.Name, got.Name.ValueString())
	assert.Equal(t, rule.RulePattern, got.RulePattern.ValueString())
	assert.Equal(t, rule.Weight, got.Weight.ValueInt64())
}

func TestGolden_Lifecycle(t *testing.T) {
	createFx := loadFixture(t, "01_create.json")
	afterCreate := loadFixture(t, "02_get_after_create.json")
	updateFx := loadFixture(t, "03_update.json")
	afterUpdate := loadFixture(t, "04_get_after_update.json")

	var (
		capturedCreate cdn.CreateResourceRuleRequest
		capturedUpdate cdn.UpdateResourceRuleRequest
		postCreate     cdn.Rule
		postUpdate     cdn.Rule
	)
	decodeProto(t, createFx.Request, &capturedCreate)
	decodeProto(t, updateFx.Request, &capturedUpdate)
	decodeProto(t, afterCreate.Response, &postCreate)
	decodeProto(t, afterUpdate.Response, &postUpdate)

	createdID := postCreate.Id
	require.NotZero(t, createdID, "post-create fixture must include an id")

	getCalls := 0
	be := &fakeBackend{
		createFn: func(_ context.Context, _ *cdn.CreateResourceRuleRequest) (int64, error) {
			return createdID, nil
		},
		getFn: func(_ context.Context, _ *cdn.GetResourceRuleRequest) (*cdn.Rule, error) {
			getCalls++
			if getCalls == 1 {
				return &postCreate, nil
			}
			return &postUpdate, nil
		},
	}
	r := newResourceForTest(be)

	// --- Create ---
	planCreate := newPlan(t, CDNRuleModel{
		ResourceID:  types.StringValue(capturedCreate.ResourceId),
		Name:        types.StringValue(capturedCreate.Name),
		RulePattern: types.StringValue(capturedCreate.RulePattern),
		Weight:      types.Int64Value(capturedCreate.Weight),
	})
	respCreate := resource.CreateResponse{State: emptyState(t)}
	r.Create(context.Background(), resource.CreateRequest{Plan: planCreate}, &respCreate)
	require.False(t, respCreate.Diagnostics.HasError(), "%v", respCreate.Diagnostics)
	require.Len(t, be.createReqs, 1)
	assertCreateMatches(t, &capturedCreate, be.createReqs[0])

	stateAfterCreate := readState(t, respCreate.State)
	assert.Equal(t, capturedCreate.ResourceId+"/"+strconv.FormatInt(createdID, 10),
		stateAfterCreate.ID.ValueString(), "composite ID")

	// --- Update ---
	planUpdate := newPlan(t, CDNRuleModel{
		ID:          stateAfterCreate.ID,
		ResourceID:  stateAfterCreate.ResourceID,
		RuleID:      stateAfterCreate.RuleID,
		Name:        types.StringValue(capturedUpdate.Name),
		RulePattern: types.StringValue(capturedUpdate.RulePattern),
		Weight:      types.Int64Value(capturedUpdate.GetWeight()),
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
	assert.Equal(t, createdID, be.deleteReqs[0].RuleId)
	assert.Equal(t, capturedCreate.ResourceId, be.deleteReqs[0].ResourceId)
}

func assertCreateMatches(t *testing.T, want, got *cdn.CreateResourceRuleRequest) {
	t.Helper()
	assert.Equal(t, want.ResourceId, got.ResourceId, "Create.ResourceId")
	assert.Equal(t, want.Name, got.Name, "Create.Name")
	assert.Equal(t, want.RulePattern, got.RulePattern, "Create.RulePattern")
	assert.Equal(t, want.Weight, got.Weight, "Create.Weight")
}

func assertUpdateMatches(t *testing.T, want, got *cdn.UpdateResourceRuleRequest) {
	t.Helper()
	assert.Equal(t, want.ResourceId, got.ResourceId, "Update.ResourceId")
	assert.Equal(t, want.RuleId, got.RuleId, "Update.RuleId")
	assert.Equal(t, want.Name, got.Name, "Update.Name")
	assert.Equal(t, want.RulePattern, got.RulePattern, "Update.RulePattern")
	assert.Equal(t, want.GetWeight(), got.GetWeight(), "Update.Weight")
}
