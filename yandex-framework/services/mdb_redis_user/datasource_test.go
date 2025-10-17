package mdb_redis_user_test

import (
	"context"
	"fmt"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/acctest"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/terraform"
	"github.com/yandex-cloud/go-genproto/yandex/cloud/mdb/redis/v1"
	"github.com/yandex-cloud/terraform-provider-yandex/pkg/resourceid"
	test "github.com/yandex-cloud/terraform-provider-yandex/pkg/testhelpers"
	yandex_framework "github.com/yandex-cloud/terraform-provider-yandex/yandex-framework/provider"
)

func TestAccDataSourceMDBRedisUser_basic(t *testing.T) {
	t.Parallel()

	clusterName := acctest.RandomWithPrefix("ds-redis-user")
	description := "Redis User Terraform Datasource Test"

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { test.AccPreCheck(t) },
		ProtoV6ProviderFactories: test.AccProviderFactories,
		CheckDestroy:             testAccCheckMDBRedisUserDestroy,
		Steps: []resource.TestStep{
			{
				Config: testAccDataSourceMDBRedisUserConfig(clusterName, description),
				Check: testAccDataSourceMDBMGUserCheck(
					"data.yandex_mdb_redis_user.bar", "yandex_mdb_redis_user.foo",
				),
			},
		},
	})
}

func testAccDataSourceMDBMGUserCheck(datasourceName string, resourceName string) resource.TestCheckFunc {
	return resource.ComposeTestCheckFunc(
		testAccDataSourceMDBMGUserAttributesCheck(datasourceName, resourceName),
		testAccDataSourceMDBRedisUserCheckResourceIDField(resourceName),
		resource.TestCheckResourceAttr(datasourceName, "name", "bob"),
	)
}

func testAccDataSourceMDBMGUserAttributesCheck(datasourceName string, resourceName string) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		ds, ok := s.RootModule().Resources[datasourceName]
		if !ok {
			return fmt.Errorf("root module has no resource called %s", datasourceName)
		}

		rs, ok := s.RootModule().Resources[resourceName]
		if !ok {
			return fmt.Errorf("can't find %s in state", resourceName)
		}

		if ds.Primary.ID != rs.Primary.ID {
			return fmt.Errorf("instance `data source` ID does not match `resource` ID: %s and %s", ds.Primary.ID, rs.Primary.ID)
		}

		datasourceAttributes := ds.Primary.Attributes
		resourceAttributes := rs.Primary.Attributes

		instanceAttrsToTest := []struct {
			dataSourcePath string
			resourcePath   string
		}{
			{
				"cluster_id",
				"cluster_id",
			},
			{
				"name",
				"name",
			},
			{
				"permissions.commands",
				"permissions.commands",
			},
			{
				"permissions.categories",
				"permissions.categories",
			},
			{
				"permissions.patterns",
				"permissions.patterns",
			},
			{
				"permissions.pub_sub_channels",
				"permissions.pub_sub_channels",
			},
			{
				"permissions.sanitize_payload",
				"permissions.sanitize_payload",
			},
			{
				"enabled",
				"enabled",
			},
		}

		for _, attrToCheck := range instanceAttrsToTest {
			if _, ok := datasourceAttributes[attrToCheck.dataSourcePath]; !ok {
				return fmt.Errorf("%s is not present in data source attributes", attrToCheck.dataSourcePath)
			}
			if _, ok := resourceAttributes[attrToCheck.resourcePath]; !ok {
				return fmt.Errorf("%s is not present in resource attributes", attrToCheck.resourcePath)
			}
			if datasourceAttributes[attrToCheck.dataSourcePath] != resourceAttributes[attrToCheck.resourcePath] {
				return fmt.Errorf(
					"%s is %s; want %s",
					attrToCheck.dataSourcePath,
					datasourceAttributes[attrToCheck.dataSourcePath],
					resourceAttributes[attrToCheck.resourcePath],
				)
			}
		}

		return nil
	}
}

func testAccDataSourceMDBRedisUserCheckResourceIDField(resourceName string) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		rs, ok := s.RootModule().Resources[resourceName]
		if !ok {
			return fmt.Errorf("not found: %s", resourceName)
		}

		if rs.Primary.ID == "" {
			return fmt.Errorf("no ID is set")
		}

		expectedResourceId := resourceid.Construct(rs.Primary.Attributes["cluster_id"], rs.Primary.Attributes["name"])

		if expectedResourceId != rs.Primary.ID {
			return fmt.Errorf("Wrong resource %s id. Expected %s, got %s", resourceName, expectedResourceId, rs.Primary.ID)
		}

		return nil
	}
}

func testAccDataSourceMDBRedisUserConfig(name string, description string) string {
	return fmt.Sprintf(VPCDependencies+`
resource "yandex_mdb_redis_cluster_v2" "foo" {
	name        = "%s"
	description = "%s"
	environment = "PRESTABLE"
	network_id  = yandex_vpc_network.foo.id

	config = {
		password = "mySecre4tP@ssw0rd"
	    version = "8.1-valkey"
	}

	resources = {
    	resource_preset_id = "hm1.nano"
    	disk_size          = 16
  	}

	hosts = {
		"aaa" = {
			zone      = "ru-central1-a"
			subnet_id  = yandex_vpc_subnet.foo.id
		}
	}
}

resource "yandex_mdb_redis_user" "foo" {
	cluster_id = yandex_mdb_redis_cluster_v2.foo.id
	name        = "bob"
	passwords   = ["mysecureP@ssw0rd"]
	permissions = {
    	commands = "+ping -set"
    	categories = "-@all +@geo"
		patterns = "~456*"
		pub_sub_channels = "&123*"
		sanitize_payload = "sanitize-payload"
  	}
	enabled = false
}

data "yandex_mdb_redis_user" "bar" {
	cluster_id = yandex_mdb_redis_cluster_v2.foo.id
	name       = yandex_mdb_redis_user.foo.name
}
`, name, description)
}

func testAccCheckMDBRedisUserDestroy(s *terraform.State) error {
	config := test.AccProvider.(*yandex_framework.Provider).GetConfig()

	for _, rs := range s.RootModule().Resources {
		if rs.Type != "yandex_mdb_redis_user" {
			continue
		}

		clusterId, userName, err := resourceid.Deconstruct(rs.Primary.ID)
		if err != nil {
			return err
		}

		_, err = config.SDK.MDB().Redis().User().Get(context.Background(), &redis.GetUserRequest{
			ClusterId: clusterId,
			UserName:  userName,
		})

		if err == nil {
			return fmt.Errorf("redis user still exists")
		}
	}

	return nil
}
