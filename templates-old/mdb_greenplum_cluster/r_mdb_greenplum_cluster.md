---
subcategory: "Managed Service for Greenplum"
page_title: "Yandex: {{.Name}}"
description: |-
  Manages a Greenplum cluster within Yandex Cloud.
---

# {{.Name}} ({{.Type}})

Manages a Greenplum cluster within the Yandex Cloud. For more information, see [the official documentation](https://yandex.cloud/docs/managed-greenplum/).

Please read [Pricing for Managed Service for Greenplum](https://yandex.cloud/docs/managed-greenplum/) before using Greenplum cluster.

Yandex Managed Service for Greenplum® is now in preview

## Example usage

{{ tffile "examples/mdb_greenplum_cluster/r_mdb_greenplum_cluster_1.tf" }}

## Argument Reference

The following arguments are supported:

* `name` - (Required) Name of the Greenplum cluster. Provided by the client when the cluster is created.

* `network_id` - (Required) ID of the network, to which the Greenplum cluster uses.

* `zone` - (Required) The availability zone where the Greenplum hosts will be created.

* `subnet_id` - (Required) The ID of the subnet, to which the hosts belongs. The subnet must be a part of the network to which the cluster belongs.

* `assign_public_ip` - (Required) Sets whether the master hosts should get a public IP address on creation. Changing this parameter for an existing host is not supported at the moment.

* `environment` - (Required) Deployment environment of the Greenplum cluster. (PRODUCTION, PRESTABLE)

* `version` - (Required) Version of the Greenplum cluster. (`6.28`)

* `master_host_count` - (Required) Number of hosts in master subcluster (1 or 2).

* `segment_host_count` - (Required) Number of hosts in segment subcluster (from 1 to 32).

* `segment_in_host` - (Required) Number of segments on segment host (not more then 1 + RAM/8).

* `master_subcluster` - (Required) Settings for master subcluster. The structure is documented below.

* `segment_subcluster` - (Required) Settings for segment subcluster. The structure is documented below.

* `service_account_id` - (Optional) ID of service account to use with Yandex Cloud resources (e.g. S3, Cloud Logging).

* `access` - (Optional) Access policy to the Greenplum cluster. The structure is documented below.

* `maintenance_window` - (Optional) Maintenance policy of the Greenplum cluster. The structure is documented below.

* `backup_window_start` - (Optional) Time to start the daily backup, in the UTC timezone. The structure is documented below.

* `pooler_config` - (Optional) Configuration of the connection pooler. The structure is documented below.

* `pxf_config` - (Optional) Configuration of the PXF daemon. The structure is documented below.

* `greenplum_config` - (Optional) Greenplum cluster config. Detail info in "Greenplum cluster settings" section (documented below).

* `cloud_storage` - (Optional) Cloud Storage settings of the Greenplum cluster. The structure is documented below.

* `master_host_group_ids` - (Optional) A list of IDs of the host groups to place master subclusters' VMs of the cluster on.

* `segment_host_group_ids` - (Optional) A list of IDs of the host groups to place segment subclusters' VMs of the cluster on.

* `logging` - (Optional) Block to configure log delivery to Yandex Cloud Logging .

---
* `user_name` - (Required) Greenplum cluster admin user name.

* `user_password` - (Required) Greenplum cluster admin password name.

---

* `description` - (Optional) Description of the Greenplum cluster.

* `folder_id` - (Optional) The ID of the folder that the resource belongs to. If it is not provided, the default provider folder is used.

* `labels` - (Optional) A set of key/value label pairs to assign to the Greenplum cluster.

* `security_group_ids` - (Optional) A set of ids of security groups assigned to hosts of the cluster.

* `deletion_protection` - (Optional) Inhibits deletion of the cluster. Can be either `true` or `false`.

---

The `master_subcluster` block supports:
* `resources` - (Required) Resources allocated to hosts for master subcluster of the Greenplum cluster. The structure is documented below.

The `segment_subcluster` block supports:
* `resources` - (Required) Resources allocated to hosts for segment subcluster of the Greenplum cluster. The structure is documented below.

The `backup_window_start` block supports:

* `hours` - (Optional) The hour at which backup will be started (UTC).

* `minutes` - (Optional) The minute at which backup will be started (UTC).

The `access` block supports:

* `data_lens` - (Optional) Allow access for [Yandex DataLens](https://yandex.cloud/services/datalens).

* `web_sql` - (Optional) Allows access for [SQL queries in the management console](https://yandex.cloud/docs/managed-mysql/operations/web-sql-query).

* `data_transfer` - (Optional) Allow access for [DataTransfer](https://yandex.cloud/services/data-transfer)

* `yandex_query` - (Optional) Allow access for [Yandex Query](https://yandex.cloud/services/query)

The `maintenance_window` block supports:

* `type` - (Required) Type of maintenance window. Can be either `ANYTIME` or `WEEKLY`. A day and hour of window need to be specified with weekly window.

* `day` - (Optional) Day of the week (in `DDD` format). Allowed values: "MON", "TUE", "WED", "THU", "FRI", "SAT", "SUN"

* `hour` - (Optional) Hour of the day in UTC (in `HH` format). Allowed value is between 0 and 23.

The `pooler_config` block supports:

* `pooling_mode` - (Optional) Mode that the connection pooler is working in. See descriptions of all modes in the [documentation for Odyssey](https://github.com/yandex/odyssey/blob/master/documentation/configuration.md#pool-string.

* `pool_size` - (Optional) Value for `pool_size` [parameter in Odyssey](https://github.com/yandex/odyssey/blob/master/documentation/configuration.md#pool_size-integer).

* `pool_client_idle_timeout` - (Optional) Value for `pool_client_idle_timeout` [parameter in Odyssey](https://github.com/yandex/odyssey/blob/master/documentation/configuration.md#pool_ttl-integer).

The `pxf_config` block supports:

* `connection_timeout` - (Optional) The Tomcat server connection timeout for read operations in seconds. Value is between 5 and 600.

* `upload_timeout` - (Optional) The Tomcat server connection timeout for write operations in seconds. Value is between 5 and 600.

* `max_threads` - (Optional) The maximum number of PXF tomcat threads. Value is between 1 and 1024.

* `pool_allow_core_thread_timeout` - (Optional) Identifies whether or not core streaming threads are allowed to time out.

* `pool_core_size` - (Optional) The number of core streaming threads. Value is between 1 and 1024.

* `pool_queue_capacity` - (Optional) The capacity of the core streaming thread pool queue. Value is positive.

* `pool_max_size` - (Optional) The maximum allowed number of core streaming threads. Value is between 1 and 1024.

* `xmx` - (Optional) Initial JVM heap size for PXF daemon. Value is between 64 and 16384.

* `xms` - (Optional) Maximum JVM heap size for PXF daemon. Value is between 64 and 16384.

The `cloud_storage` block supports:

* `enable` - (Optional) Whether to use cloud storage or not.

The `background_activities` block supports:

* `analyze_and_vacuum` - (Optional) Block to configure 'ANALYZE' and 'VACUUM' daily operations.
  * `start_time` - Time of day in 'HH:MM' format when scripts should run.
  * `analyze_timeout` - Maximum duration of the `ANALYZE` operation, in seconds. The default value is `36000`. As soon as this period expires, the `ANALYZE` operation will be forced to terminate.
  * `vacuum_timeout` - Maximum duration of the `VACUUM` operation, in seconds. The default value is `36000`. As soon as this period expires, the `VACUUM` operation will be forced to terminate.
* `query_killer_idle` - (Optional) Block to configure script that kills long running queries that are in `idle` state.
  * `enable` - Flag that indicates whether script is enabled.
  * `max_age` - Maximum duration for this type of queries (in seconds).
  * `ignore_users` - List of users to ignore when considering queries to terminate.
* `query_killer_idle_in_transaction` - (Optional) block to configure script that kills long running queries that are in `idle in transaction` state.
  * `enable` - Flag that indicates whether script is enabled.
  * `max_age` - Maximum duration for this type of queries (in seconds).
  * `ignore_users` - List of users to ignore when considering queries to terminate.
* `query_killer_long_running` - (Optional) block to configure script that kills long running queries (in any state).
  * `enable` - Flag that indicates whether script is enabled.
  * `max_age` - Maximum duration for this type of queries (in seconds).
  * `ignore_users` - List of users to ignore when considering queries to terminate.

## Attributes Reference

In addition to the arguments listed above, the following computed attributes are exported:

* `created_at` - Creation timestamp of the cluster.

* `health` - Aggregated health of the cluster.

* `status` - Status of the cluster.

---
* `master_hosts` - (Computed) Info about hosts in master subcluster. The structure is documented below.

* `segment_hosts` - (Computed) Info about hosts in segment subcluster. The structure is documented below.

---

The `master_hosts` block supports:
* `assign_public_ip` - (Computed) Flag indicating that master hosts should be created with a public IP address.
* `fqdn` - (Computed) The fully qualified domain name of the host.

The `segment_hosts` block supports:
* `fqdn` - (Computed) The fully qualified domain name of the host.

The `logging` block supports:
* `enabled` - Cloud Logging enable/disable switch.
* `log_group_id` - Use this log group to deliver cluster logs to.
* `folder_id` - Use this folder's default log group to deliver cluster logs to.
* `command_center_enabled` - Enable Yandex Command Center logs delivery.
* `greenplum_enabled` - Enable Greenplum logs delivery.
* `pooler_enabled` - Enable Pooler logs delivery.

## Import

The resource can be imported by using their `resource ID`. For getting the resource ID you can use Yandex Cloud [Web Console](https://console.yandex.cloud) or [YC CLI](https://yandex.cloud/docs/cli/quickstart).

{{ codefile "shell" "examples/mdb_greenplum_cluster/import.sh" }}


## Greenplum cluster settings

| Setting name and type \ Greenplum version                                                                                                                                             | 6.28      |
|---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|-----------|
| gp_add_column_inherits_table_setting : boolean                                                                                                                                        | supported |
| gp_enable_global_deadlock_detector : boolean                                                                                                                                          | supported |
| gp_global_deadlock_detector_period : integer                                                                                                                                          | supported |
| gp_workfile_compression : boolean                                                                                                                                                     | supported |
| gp_workfile_limit_files_per_query : integer                                                                                                                                           | supported |
| gp_workfile_limit_per_segment : integer                                                                                                                                               | supported |
| gp_workfile_limit_per_query : integer                                                                                                                                                 | supported |
| log_statement : one of<br> - 0: " LOG_STATEMENT_UNSPECIFIED"<br> - 1: " LOG_STATEMENT_NONE"<br> - 2: " LOG_STATEMENT_DDL"<br> - 3: " LOG_STATEMENT_MOD"<br> - 4: " LOG_STATEMENT_ALL" | supported |
| max_connections : integer                                                                                                                                                             | supported |
| max_prepared_transactions : integer                                                                                                                                                   | supported |
| max_slot_wal_keep_size : integer                                                                                                                                                      | supported |
| max_statement_mem : integer                                                                                                                                                           | supported |
