package mdb_postgresql_cluster_v2

import (
	"fmt"
	"maps"

	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	config "github.com/yandex-cloud/go-genproto/yandex/cloud/mdb/postgresql/v1/config"
	"github.com/yandex-cloud/terraform-provider-yandex/pkg/mdbcommon"
)

var pgSettingsEnumNames = map[string]map[int32]string{
	"wal_level":                        config.PostgresqlConfig14_WalLevel_name,
	"synchronous_commit":               config.PostgresqlConfig14_SynchronousCommit_name,
	"constraint_exclusion":             config.PostgresqlConfig14_ConstraintExclusion_name,
	"force_parallel_mode":              config.PostgresqlConfig14_ForceParallelMode_name,
	"client_min_messages":              config.PostgresqlConfig14_LogLevel_name,
	"log_min_messages":                 config.PostgresqlConfig14_LogLevel_name,
	"log_min_error_statement":          config.PostgresqlConfig14_LogLevel_name,
	"log_error_verbosity":              config.PostgresqlConfig14_LogErrorVerbosity_name,
	"log_statement":                    config.PostgresqlConfig14_LogStatement_name,
	"default_transaction_isolation":    config.PostgresqlConfig14_TransactionIsolation_name,
	"bytea_output":                     config.PostgresqlConfig14_ByteaOutput_name,
	"xmlbinary":                        config.PostgresqlConfig14_XmlBinary_name,
	"xmloption":                        config.PostgresqlConfig14_XmlOption_name,
	"backslash_quote":                  config.PostgresqlConfig14_BackslashQuote_name,
	"plan_cache_mode":                  config.PostgresqlConfig14_PlanCacheMode_name,
	"pg_hint_plan_debug_print":         config.PostgresqlConfig14_PgHintPlanDebugPrint_name,
	"pg_hint_plan_message_level":       config.PostgresqlConfig14_LogLevel_name,
	"shared_preload_libraries.element": pgSharedPreloadLibrariesEnumNames(),
	"password_encryption":              config.PostgresqlConfig14_PasswordEncryption_name,
	"auto_explain_log_format":          config.PostgresqlConfig14_AutoExplainLogFormat_name,
}

func pgSharedPreloadLibrariesEnumNames() map[int32]string {
	namesMap := make(map[int32]string)
	maps.Copy(namesMap, config.PostgresqlConfig13_SharedPreloadLibraries_name)
	maps.Copy(namesMap, config.PostgresqlConfig13_1C_SharedPreloadLibraries_name)
	maps.Copy(namesMap, config.PostgresqlConfig14_SharedPreloadLibraries_name)
	maps.Copy(namesMap, config.PostgresqlConfig14_1C_SharedPreloadLibraries_name)
	maps.Copy(namesMap, config.PostgresqlConfig15_SharedPreloadLibraries_name)
	maps.Copy(namesMap, config.PostgresqlConfig15_1C_SharedPreloadLibraries_name)
	maps.Copy(namesMap, config.PostgresqlConfig16_SharedPreloadLibraries_name)
	maps.Copy(namesMap, config.PostgresqlConfig16_1C_SharedPreloadLibraries_name)
	maps.Copy(namesMap, config.PostgresqlConfig17_SharedPreloadLibraries_name)
	maps.Copy(namesMap, config.PostgresqlConfig17_1C_SharedPreloadLibraries_name)
	maps.Copy(namesMap, config.PostgresqlConfig18_SharedPreloadLibraries_name)
	maps.Copy(namesMap, config.PostgresqlConfig18_1C_SharedPreloadLibraries_name)
	return namesMap
}

var pgSettingsEnumValues = map[string]map[string]int32{
	"wal_level":                        config.PostgresqlConfig14_WalLevel_value,
	"synchronous_commit":               config.PostgresqlConfig14_SynchronousCommit_value,
	"constraint_exclusion":             config.PostgresqlConfig14_ConstraintExclusion_value,
	"force_parallel_mode":              config.PostgresqlConfig14_ForceParallelMode_value,
	"client_min_messages":              config.PostgresqlConfig14_LogLevel_value,
	"log_min_messages":                 config.PostgresqlConfig14_LogLevel_value,
	"log_min_error_statement":          config.PostgresqlConfig14_LogLevel_value,
	"log_error_verbosity":              config.PostgresqlConfig14_LogErrorVerbosity_value,
	"log_statement":                    config.PostgresqlConfig14_LogStatement_value,
	"default_transaction_isolation":    config.PostgresqlConfig14_TransactionIsolation_value,
	"bytea_output":                     config.PostgresqlConfig14_ByteaOutput_value,
	"xmlbinary":                        config.PostgresqlConfig14_XmlBinary_value,
	"xmloption":                        config.PostgresqlConfig14_XmlOption_value,
	"backslash_quote":                  config.PostgresqlConfig14_BackslashQuote_value,
	"plan_cache_mode":                  config.PostgresqlConfig14_PlanCacheMode_value,
	"pg_hint_plan_debug_print":         config.PostgresqlConfig14_PgHintPlanDebugPrint_value,
	"pg_hint_plan_message_level":       config.PostgresqlConfig14_LogLevel_value,
	"shared_preload_libraries.element": pgSharedPreloadLibrariesEnumValues(),
	"password_encryption":              config.PostgresqlConfig14_PasswordEncryption_value,
	"auto_explain_log_format":          config.PostgresqlConfig14_AutoExplainLogFormat_value,
}

func pgSharedPreloadLibrariesEnumValues() map[string]int32 {
	kek := MergeMaps(
		config.PostgresqlConfig13_SharedPreloadLibraries_value,
		config.PostgresqlConfig13_1C_SharedPreloadLibraries_value,
		config.PostgresqlConfig14_SharedPreloadLibraries_value,
		config.PostgresqlConfig14_1C_SharedPreloadLibraries_value,
		config.PostgresqlConfig15_SharedPreloadLibraries_value,
		config.PostgresqlConfig15_1C_SharedPreloadLibraries_value,
		config.PostgresqlConfig16_SharedPreloadLibraries_value,
		config.PostgresqlConfig16_1C_SharedPreloadLibraries_value,
		config.PostgresqlConfig17_SharedPreloadLibraries_value,
		config.PostgresqlConfig17_1C_SharedPreloadLibraries_value,
		config.PostgresqlConfig18_SharedPreloadLibraries_value,
		config.PostgresqlConfig18_1C_SharedPreloadLibraries_value,
	)
	return kek
}

func MergeMaps[M ~map[K]V, K comparable, V any](src ...M) M {
	merged := make(M)
	for _, m := range src {
		for k, v := range m {
			merged[k] = v
		}
	}
	return merged
}

var listAttributes = map[string]struct{}{
	"shared_preload_libraries": {},
}

var pgAttrProvider = &PgSettingsAttributeInfoProvider{}

type PgSettingsAttributeInfoProvider struct{}

func (p *PgSettingsAttributeInfoProvider) GetSettingsEnumNames() map[string]map[int32]string {
	return pgSettingsEnumNames
}

func (p *PgSettingsAttributeInfoProvider) GetSettingsEnumValues() map[string]map[string]int32 {
	return pgSettingsEnumValues
}

func (p *PgSettingsAttributeInfoProvider) GetSetAttributes() map[string]struct{} {
	return listAttributes
}

func NewPgSettingsMapType() mdbcommon.SettingsMapType {
	return mdbcommon.NewSettingsMapType(pgAttrProvider)
}

func NewPgSettingsMapValue(elements map[string]attr.Value) (mdbcommon.SettingsMapValue, diag.Diagnostics) {
	return mdbcommon.NewSettingsMapValue(elements, pgAttrProvider)
}

func NewPgSettingsMapValueMust(elements map[string]attr.Value) mdbcommon.SettingsMapValue {
	val, d := NewPgSettingsMapValue(elements)
	if d.HasError() {
		panic(fmt.Sprintf("%v", d))
	}

	return val
}

func NewPgSettingsMapNull() mdbcommon.SettingsMapValue {
	return mdbcommon.NewSettingsMapNull()
}
