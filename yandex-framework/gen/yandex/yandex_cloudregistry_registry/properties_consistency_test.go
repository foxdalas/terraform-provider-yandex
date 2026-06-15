package yandex_cloudregistry_registry

import (
	"context"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

// TestFlattenProperties_ServerManagedKeyStaysConsistent guards against the
// "Provider produced inconsistent result after apply: .properties: new element
// \"subtype\" has appeared" failure. The cloudregistry API injects a
// server-managed `subtype` property the user never configured; when the prior
// plan/state pinned a known key set, the flattened value must not gain that key.
func TestFlattenProperties_ServerManagedKeyStaysConsistent(t *testing.T) {
	ctx := context.Background()

	knownMap := func(m map[string]string) types.Map {
		vals := make(map[string]attr.Value, len(m))
		for k, v := range m {
			vals[k] = types.StringValue(v)
		}
		return types.MapValueMust(types.StringType, vals)
	}

	cases := []struct {
		name     string
		apiProps map[string]string
		prior    types.Map
		want     map[string]string // nil => expect null map
	}{
		{
			name:     "prior known without subtype drops server-added subtype",
			apiProps: map[string]string{"team": "infra", "subtype": "managed"},
			prior:    knownMap(map[string]string{"team": "infra"}),
			want:     map[string]string{"team": "infra"},
		},
		{
			name:     "prior unknown surfaces full computed map",
			apiProps: map[string]string{"team": "infra", "subtype": "managed"},
			prior:    types.MapUnknown(types.StringType),
			want:     map[string]string{"team": "infra", "subtype": "managed"},
		},
		{
			name:     "prior null surfaces full computed map",
			apiProps: map[string]string{"team": "infra", "subtype": "managed"},
			prior:    types.MapNull(types.StringType),
			want:     map[string]string{"team": "infra", "subtype": "managed"},
		},
		{
			name:     "prior known keeps subtype when user configured it",
			apiProps: map[string]string{"subtype": "managed"},
			prior:    knownMap(map[string]string{"subtype": "managed"}),
			want:     map[string]string{"subtype": "managed"},
		},
		{
			name:     "value updates for kept keys",
			apiProps: map[string]string{"team": "platform", "subtype": "managed"},
			prior:    knownMap(map[string]string{"team": "infra"}),
			want:     map[string]string{"team": "platform"},
		},
		{
			name:     "prior known empty drops all server-added keys",
			apiProps: map[string]string{"subtype": "managed"},
			prior:    types.MapValueMust(types.StringType, map[string]attr.Value{}),
			want:     map[string]string{},
		},
	}

	for _, c := range cases {
		c := c
		t.Run(c.name, func(t *testing.T) {
			var diags diag.Diagnostics
			got := flattenYandexCloudregistryRegistryProperties(ctx, c.apiProps, c.prior, &diags)
			if diags.HasError() {
				t.Fatalf("unexpected diagnostics: %v", diags.Errors())
			}

			var gotMap map[string]string
			if !got.IsNull() {
				gotMap = make(map[string]string)
				d := got.ElementsAs(ctx, &gotMap, false)
				if d.HasError() {
					t.Fatalf("ElementsAs: %v", d.Errors())
				}
			}

			if len(gotMap) != len(c.want) {
				t.Fatalf("key count mismatch: got %v, want %v", gotMap, c.want)
			}
			for k, v := range c.want {
				if gotMap[k] != v {
					t.Fatalf("key %q: got %q, want %q (full got=%v)", k, gotMap[k], v, gotMap)
				}
			}
		})
	}
}
