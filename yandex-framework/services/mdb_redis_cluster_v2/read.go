package mdb_redis_cluster_v2

import (
	"context"

	"github.com/hashicorp/terraform-plugin-framework-timeouts/resource/timeouts"
	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/yandex-cloud/go-genproto/yandex/cloud/mdb/redis/v1" //nolint:depguard
	ycsdk "github.com/yandex-cloud/go-sdk"
	"github.com/yandex-cloud/terraform-provider-yandex/pkg/mdbcommon"
	"github.com/yandex-cloud/terraform-provider-yandex/pkg/timestamp"
)

func clusterRead(ctx context.Context, sdk *ycsdk.SDK, diagnostics *diag.Diagnostics, state *Cluster) {
	cid := state.ID.ValueString()
	cluster := redisAPI.GetCluster(ctx, sdk, diagnostics, cid)
	if diagnostics.HasError() {
		return
	}

	state.ClusterID = state.ID
	state.Name = types.StringValue(cluster.Name)
	state.NetworkID = types.StringValue(cluster.NetworkId)
	state.Environment = types.StringValue(cluster.GetEnvironment().String())
	state.Description = types.StringValue(cluster.Description)
	state.Sharded = types.BoolValue(cluster.Sharded)
	state.TlsEnabled = types.BoolValue(cluster.TlsEnabled)
	state.PersistenceMode = types.StringValue(cluster.GetPersistenceMode().String())
	state.AnnounceHostnames = types.BoolValue(cluster.AnnounceHostnames)
	state.FolderID = types.StringValue(cluster.FolderId)
	state.CreatedAt = types.StringValue(timestamp.Get(cluster.CreatedAt))
	state.DeletionProtection = types.BoolValue(cluster.DeletionProtection)
	state.AuthSentinel = types.BoolValue(cluster.AuthSentinel)
	state.DiskEncryptionKeyId = mdbcommon.FlattenStringWrapper(ctx, cluster.DiskEncryptionKeyId, diagnostics)

	labels, diags := types.MapValueFrom(ctx, types.StringType, cluster.Labels)
	state.Labels = labels
	diagnostics.Append(diags...)

	state.SecurityGroupIDs = mdbcommon.FlattenSetString(ctx, cluster.SecurityGroupIds, diagnostics)

	state.Resources = mdbcommon.FlattenResources[redis.Resources](ctx, cluster.GetConfig().GetResources(), diagnostics)

	conf := FlattenConfig(cluster.Config)
	if state.Config != nil {
		conf.Password = state.Config.Password
	}

	state.Config = &conf
	state.Config.BackupWindowStart = mdbcommon.FlattenBackupWindowStart(ctx, cluster.Config.GetBackupWindowStart(), diagnostics)

	state.Config.BackupRetainPeriodDays = types.Int64Value(cluster.Config.BackupRetainPeriodDays.GetValue())

	state.DiskSizeAutoscaling, diags = flattenAutoscaling(ctx, cluster.GetConfig().GetDiskSizeAutoscaling())
	diagnostics.Append(diags...)

	state.MaintenanceWindow = mdbcommon.FlattenMaintenanceWindow[
		redis.MaintenanceWindow,
		redis.WeeklyMaintenanceWindow,
		redis.AnytimeMaintenanceWindow,
		redis.WeeklyMaintenanceWindow_WeekDay,
	](ctx, cluster.MaintenanceWindow, diagnostics)

	state.Access, diags = flattenAccess(ctx, cluster.GetConfig().GetAccess())
	diagnostics.Append(diags...)

	var entityIdToApiHosts map[string]Host = mdbcommon.ReadHosts[Host, *redis.Host, *redis.HostSpec, redis.UpdateHostSpec](ctx, sdk, diagnostics, redisHostService, &redisAPI, state.HostSpecs, cid)

	state.HostSpecs, diags = types.MapValueFrom(ctx, HostType, entityIdToApiHosts)

	state.Timeouts = timeouts.Value{
		Object: types.ObjectNull(map[string]attr.Type{
			"create": types.StringType,
			"delete": types.StringType,
			"update": types.StringType,
		}),
	}

	diagnostics.Append(diags...)
	if diagnostics.HasError() {
		return
	}
}
