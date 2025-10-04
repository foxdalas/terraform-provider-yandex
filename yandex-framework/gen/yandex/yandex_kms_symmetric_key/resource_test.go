package yandex_kms_symmetric_key_test

import (
	"context"
	"fmt"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/acctest"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/plancheck"
	"github.com/hashicorp/terraform-plugin-testing/terraform"
	"github.com/yandex-cloud/go-genproto/yandex/cloud/kms/v1"
	kmsv1sdk "github.com/yandex-cloud/go-sdk/services/kms/v1"
	test "github.com/yandex-cloud/terraform-provider-yandex/pkg/testhelpers"
	yandex_framework "github.com/yandex-cloud/terraform-provider-yandex/yandex-framework/provider"
)

// TestMain - add sweepers flag to the go test command
// important for sweepers run.
func TestMain(m *testing.M) {
	resource.TestMain(m)
}

func TestAccKMSSymmetricKey_UpgradeFromSDKv2(t *testing.T) {
	t.Parallel()

	var symmetricKey1 kms.SymmetricKey
	var symmetricKey2 kms.SymmetricKey
	var symmetricKey3 kms.SymmetricKey

	key1Name := fmt.Sprintf("tf-test-%s", acctest.RandString(10))
	key2Name := fmt.Sprintf("tf-test-%s", acctest.RandString(10))
	key3Name := fmt.Sprintf("tf-test-%s", acctest.RandString(10))

	resource.Test(t, resource.TestCase{
		PreCheck:     func() { test.AccPreCheck(t) },
		CheckDestroy: testAccCheckKMSSymmetricKeyDestroy,
		Steps: []resource.TestStep{
			{
				ExternalProviders: map[string]resource.ExternalProvider{
					"yandex": {
						VersionConstraint: "0.150.0",
						Source:            "yandex-cloud/yandex",
					},
				},
				Config: testAccKMSSymmetricKey_basic(key1Name, key2Name, key3Name),
				Check: resource.ComposeTestCheckFunc(
					testAccCheckKMSSymmetricKeyExists(
						"yandex_kms_symmetric_key.key-a", &symmetricKey1),
					testAccCheckKMSSymmetricKeyExists(
						"yandex_kms_symmetric_key.key-b", &symmetricKey2),
					testAccCheckKMSSymmetricKeyExists(
						"yandex_kms_symmetric_key.key-c", &symmetricKey3),
					test.AccCheckDuration("yandex_kms_symmetric_key.key-a", "rotation_period", "24h"),
					test.AccCheckDuration("yandex_kms_symmetric_key.key-b", "rotation_period", "8760h"),
					test.AccCheckDuration("yandex_kms_symmetric_key.key-c", "rotation_period", ""),
					test.AccCheckCreatedAtAttr("yandex_kms_symmetric_key.key-a"),
					test.AccCheckCreatedAtAttr("yandex_kms_symmetric_key.key-b"),
					test.AccCheckCreatedAtAttr("yandex_kms_symmetric_key.key-c"),
				),
			},
			{
				ProtoV6ProviderFactories: test.AccProviderFactories,
				Config:                   testAccKMSSymmetricKey_basic(key1Name, key2Name, key3Name),
				ConfigPlanChecks: resource.ConfigPlanChecks{
					PreApply: []plancheck.PlanCheck{
						plancheck.ExpectEmptyPlan(),
					},
				},
			},
		},
	})
}

func TestAccKMSSymmetricKey_basic(t *testing.T) {
	t.Parallel()

	var symmetricKey1 kms.SymmetricKey
	var symmetricKey2 kms.SymmetricKey
	var symmetricKey3 kms.SymmetricKey

	key1Name := fmt.Sprintf("tf-test-%s", acctest.RandString(10))
	key2Name := fmt.Sprintf("tf-test-%s", acctest.RandString(10))
	key3Name := fmt.Sprintf("tf-test-%s", acctest.RandString(10))

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { test.AccPreCheck(t) },
		ProtoV6ProviderFactories: test.AccProviderFactories,
		CheckDestroy:             testAccCheckKMSSymmetricKeyDestroy,
		Steps: []resource.TestStep{
			{
				Config: testAccKMSSymmetricKey_basic(key1Name, key2Name, key3Name),
				Check: resource.ComposeTestCheckFunc(
					testAccCheckKMSSymmetricKeyExists(
						"yandex_kms_symmetric_key.key-a", &symmetricKey1),
					testAccCheckKMSSymmetricKeyExists(
						"yandex_kms_symmetric_key.key-b", &symmetricKey2),
					testAccCheckKMSSymmetricKeyExists(
						"yandex_kms_symmetric_key.key-c", &symmetricKey3),
					test.AccCheckDuration("yandex_kms_symmetric_key.key-a", "rotation_period", "24h"),
					test.AccCheckDuration("yandex_kms_symmetric_key.key-b", "rotation_period", "8760h"),
					test.AccCheckDuration("yandex_kms_symmetric_key.key-c", "rotation_period", ""),
					test.AccCheckCreatedAtAttr("yandex_kms_symmetric_key.key-a"),
					test.AccCheckCreatedAtAttr("yandex_kms_symmetric_key.key-b"),
					test.AccCheckCreatedAtAttr("yandex_kms_symmetric_key.key-c"),
				),
			},
			{
				ResourceName:      "yandex_kms_symmetric_key.key-a",
				ImportState:       true,
				ImportStateVerify: true,
			},
			{
				ResourceName:      "yandex_kms_symmetric_key.key-b",
				ImportState:       true,
				ImportStateVerify: true,
			},
			{
				ResourceName:      "yandex_kms_symmetric_key.key-c",
				ImportState:       true,
				ImportStateVerify: true,
			},
		},
	})
}

func TestAccKMSSymmetricKey_deletion_protection(t *testing.T) {
	t.Parallel()

	var symmetricKey1 kms.SymmetricKey
	var symmetricKey2 kms.SymmetricKey
	var symmetricKey3 kms.SymmetricKey

	key1Name := fmt.Sprintf("tf-test-%s", acctest.RandString(10))
	key2Name := fmt.Sprintf("tf-test-%s", acctest.RandString(10))
	key3Name := fmt.Sprintf("tf-test-%s", acctest.RandString(10))

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { test.AccPreCheck(t) },
		ProtoV6ProviderFactories: test.AccProviderFactories,
		CheckDestroy:             testAccCheckKMSSymmetricKeyDestroy,

		Steps: []resource.TestStep{
			{
				Config: testAccKMSSymmetricKey_deletion_protection(key1Name, key2Name, key3Name),
				Check: resource.ComposeTestCheckFunc(
					testAccCheckKMSSymmetricKeyExists(
						"yandex_kms_symmetric_key.key-a", &symmetricKey1),
					testAccCheckKMSSymmetricKeyExists(
						"yandex_kms_symmetric_key.key-b", &symmetricKey2),
					testAccCheckKMSSymmetricKeyExists(
						"yandex_kms_symmetric_key.key-c", &symmetricKey3),
					test.AccCheckBoolValue("yandex_kms_symmetric_key.key-a", "deletion_protection", true),
					test.AccCheckBoolValue("yandex_kms_symmetric_key.key-b", "deletion_protection", false),
					test.AccCheckBoolValue("yandex_kms_symmetric_key.key-c", "deletion_protection", false),
					test.AccCheckCreatedAtAttr("yandex_kms_symmetric_key.key-a"),
					test.AccCheckCreatedAtAttr("yandex_kms_symmetric_key.key-b"),
					test.AccCheckCreatedAtAttr("yandex_kms_symmetric_key.key-c"),
				),
			},
			{
				ResourceName:      "yandex_kms_symmetric_key.key-a",
				ImportState:       true,
				ImportStateVerify: true,
			},
			{
				ResourceName:      "yandex_kms_symmetric_key.key-b",
				ImportState:       true,
				ImportStateVerify: true,
			},
			{
				ResourceName:      "yandex_kms_symmetric_key.key-c",
				ImportState:       true,
				ImportStateVerify: true,
			},
			{
				Config: testAccKmsSymmetricKeyDeletionProtection_update(key1Name, false),
				Check: resource.ComposeTestCheckFunc(
					test.AccCheckBoolValue("yandex_kms_symmetric_key.key-a", "deletion_protection", false),
				),
			},
		},
	})
}

func TestAccKMSSymmetricKey_update(t *testing.T) {
	t.Parallel()

	var symmetricKey1 kms.SymmetricKey
	var symmetricKey2 kms.SymmetricKey
	var symmetricKey3 kms.SymmetricKey

	key1Name := acctest.RandomWithPrefix("tf-key-a")
	key2Name := acctest.RandomWithPrefix("tf-key-b")
	key3Name := acctest.RandomWithPrefix("tf-key-c")
	updatedKey1Name := key1Name + "-update"
	updatedKey2Name := key2Name + "-update"
	updatedKey3Name := key3Name + "-update"

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { test.AccPreCheck(t) },
		ProtoV6ProviderFactories: test.AccProviderFactories,
		CheckDestroy:             testAccCheckKMSSymmetricKeyDestroy,
		Steps: []resource.TestStep{
			{
				Config: testAccKMSSymmetricKey_basic(key1Name, key2Name, key3Name),
				Check: resource.ComposeTestCheckFunc(
					testAccCheckKMSSymmetricKeyExists("yandex_kms_symmetric_key.key-a", &symmetricKey1),
					resource.TestCheckResourceAttr("yandex_kms_symmetric_key.key-a", "name", key1Name),
					resource.TestCheckResourceAttr("yandex_kms_symmetric_key.key-a", "description", "description for key-a"),
					resource.TestCheckResourceAttr("yandex_kms_symmetric_key.key-a", "default_algorithm", "AES_128"),
					test.AccCheckDuration("yandex_kms_symmetric_key.key-a", "rotation_period", "24h"),

					testAccCheckKMSSymmetricKeyContainsLabel(&symmetricKey1, "tf-label", "tf-label-value-a"),
					testAccCheckKMSSymmetricKeyContainsLabel(&symmetricKey1, "empty-label", ""),
					test.AccCheckCreatedAtAttr("yandex_kms_symmetric_key.key-a"),

					testAccCheckKMSSymmetricKeyExists("yandex_kms_symmetric_key.key-b", &symmetricKey2),
					resource.TestCheckResourceAttr("yandex_kms_symmetric_key.key-b", "name", key2Name),
					resource.TestCheckResourceAttr("yandex_kms_symmetric_key.key-b", "description", "description for key-b"),
					resource.TestCheckResourceAttr("yandex_kms_symmetric_key.key-b", "default_algorithm", "AES_256"),
					test.AccCheckDuration("yandex_kms_symmetric_key.key-b", "rotation_period", "8760h"),
					testAccCheckKMSSymmetricKeyContainsLabel(&symmetricKey2, "tf-label", "tf-label-value-b"),
					testAccCheckKMSSymmetricKeyContainsLabel(&symmetricKey2, "empty-label", ""),
					test.AccCheckCreatedAtAttr("yandex_kms_symmetric_key.key-b"),

					testAccCheckKMSSymmetricKeyExists("yandex_kms_symmetric_key.key-c", &symmetricKey3),
					resource.TestCheckResourceAttr("yandex_kms_symmetric_key.key-c", "name", key3Name),
					resource.TestCheckResourceAttr("yandex_kms_symmetric_key.key-c", "description", "description for key-c"),
					resource.TestCheckResourceAttr("yandex_kms_symmetric_key.key-c", "default_algorithm", "AES_256"),
					test.AccCheckDuration("yandex_kms_symmetric_key.key-c", "rotation_period", ""),
					testAccCheckKMSSymmetricKeyContainsLabel(&symmetricKey3, "tf-label", "tf-label-value-c"),
					testAccCheckKMSSymmetricKeyContainsLabel(&symmetricKey3, "empty-label", ""),
					test.AccCheckCreatedAtAttr("yandex_kms_symmetric_key.key-c"),
				),
			},
			{
				Config: testAccKMSSymmetricKey_update(updatedKey1Name, updatedKey2Name, updatedKey3Name),
				Check: resource.ComposeTestCheckFunc(
					testAccCheckKMSSymmetricKeyExists("yandex_kms_symmetric_key.key-a", &symmetricKey1),
					resource.TestCheckResourceAttr("yandex_kms_symmetric_key.key-a", "name", updatedKey1Name),
					resource.TestCheckResourceAttr("yandex_kms_symmetric_key.key-a", "default_algorithm", "AES_192"),
					resource.TestCheckResourceAttr("yandex_kms_symmetric_key.key-a", "rotation_period", ""),
					testAccCheckKMSSymmetricKeyContainsLabel(&symmetricKey1, "empty-label", "oh-look-theres-a-label-now"),
					testAccCheckKMSSymmetricKeyContainsLabel(&symmetricKey1, "new-field", "only-shows-up-when-updated"),

					testAccCheckKMSSymmetricKeyExists("yandex_kms_symmetric_key.key-b", &symmetricKey2),
					resource.TestCheckResourceAttr("yandex_kms_symmetric_key.key-b", "name", updatedKey2Name),
					resource.TestCheckResourceAttr("yandex_kms_symmetric_key.key-b", "default_algorithm", "AES_192"),
					resource.TestCheckResourceAttr("yandex_kms_symmetric_key.key-b", "rotation_period", ""),
					testAccCheckKMSSymmetricKeyContainsLabel(&symmetricKey2, "empty-label", "oh-look-theres-a-label-now"),
					testAccCheckKMSSymmetricKeyContainsLabel(&symmetricKey2, "new-field", "only-shows-up-when-updated"),

					testAccCheckKMSSymmetricKeyExists("yandex_kms_symmetric_key.key-c", &symmetricKey3),
					resource.TestCheckResourceAttr("yandex_kms_symmetric_key.key-c", "name", updatedKey3Name),
					resource.TestCheckResourceAttr("yandex_kms_symmetric_key.key-c", "default_algorithm", "AES_192"),
					test.AccCheckDuration("yandex_kms_symmetric_key.key-c", "rotation_period", "8760h"),
					testAccCheckKMSSymmetricKeyContainsLabel(&symmetricKey3, "empty-label", "oh-look-theres-a-label-now"),
					testAccCheckKMSSymmetricKeyContainsLabel(&symmetricKey3, "new-field", "only-shows-up-when-updated"),
				),
			},
			{
				ResourceName:      "yandex_kms_symmetric_key.key-a",
				ImportState:       true,
				ImportStateVerify: true,
				ImportStateCheck:  test.CheckImportFolderID(test.GetExampleFolderID()),
			},
			{
				ResourceName:      "yandex_kms_symmetric_key.key-b",
				ImportState:       true,
				ImportStateVerify: true,
			},
			{
				ResourceName:      "yandex_kms_symmetric_key.key-c",
				ImportState:       true,
				ImportStateVerify: true,
			},
		},
	})
}

func testAccCheckKMSSymmetricKeyDestroy(s *terraform.State) error {
	config := test.AccProvider.(*yandex_framework.Provider).GetConfig()

	for _, rs := range s.RootModule().Resources {
		if rs.Type != "yandex_kms_symmetric_key" {
			continue
		}

		_, err := kmsv1sdk.NewSymmetricKeyClient(config.SDKv2).Get(context.Background(), &kms.GetSymmetricKeyRequest{
			KeyId: rs.Primary.ID,
		})
		if err == nil {
			return fmt.Errorf("KMS Symmetric Key still exists")
		}
	}

	return nil
}

func testAccCheckKMSSymmetricKeyExists(name string, symmetricKey *kms.SymmetricKey) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		rs, ok := s.RootModule().Resources[name]
		if !ok {
			return fmt.Errorf("Not found: %s", name)
		}

		if rs.Primary.ID == "" {
			return fmt.Errorf("No ID is set")
		}

		config := test.AccProvider.(*yandex_framework.Provider).GetConfig()

		found, err := kmsv1sdk.NewSymmetricKeyClient(config.SDKv2).Get(context.Background(), &kms.GetSymmetricKeyRequest{
			KeyId: rs.Primary.ID,
		})
		if err != nil {
			return err
		}

		if found.Id != rs.Primary.ID {
			return fmt.Errorf("KMS Symmetric Key not found")
		}

		*symmetricKey = *found

		return nil
	}
}

func testAccCheckKMSSymmetricKeyContainsLabel(symmetricKey *kms.SymmetricKey, key string, value string) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		v, ok := symmetricKey.Labels[key]
		if !ok {
			return fmt.Errorf("Expected label with key '%s' not found", key)
		}
		if v != value {
			return fmt.Errorf("Incorrect label value for key '%s': expected '%s' but found '%s'", key, value, v)
		}
		return nil
	}
}

//revive:disable:var-naming
func testAccKMSSymmetricKey_basic(key1Name, key2Name, key3Name string) string {
	return fmt.Sprintf(`
resource "yandex_kms_symmetric_key" "key-a" {
  name              = "%s"
  description       = "description for key-a"
  default_algorithm = "AES_128"
  rotation_period   = "24h"

  labels = {
    tf-label    = "tf-label-value-a"
    empty-label = ""
  }
}

resource "yandex_kms_symmetric_key" "key-b" {
  name              = "%s"
  description       = "description for key-b"
  default_algorithm = "AES_256"
  rotation_period   = "8760h"   // equal 1 year

  labels = {
    tf-label    = "tf-label-value-b"
    empty-label = ""
  }
}

resource "yandex_kms_symmetric_key" "key-c" {
  name              = "%s"
  description       = "description for key-c"
  default_algorithm = "AES_256"

  labels = {
    tf-label    = "tf-label-value-c"
    empty-label = ""
  }
}

`, key1Name, key2Name, key3Name)
}

//revive:disable:var-naming
func testAccKMSSymmetricKey_deletion_protection(key1Name, key2Name, key3Name string) string {
	return fmt.Sprintf(`
resource "yandex_kms_symmetric_key" "key-a" {
  name                = "%s"
  description         = "description for key-a"
  deletion_protection = true
}

resource "yandex_kms_symmetric_key" "key-b" {
  name                = "%s"
  description         = "description for key-b"
  deletion_protection = false

}

resource "yandex_kms_symmetric_key" "key-c" {
  name        = "%s"
  description = "description for key-c"
}

`, key1Name, key2Name, key3Name)
}

func testAccKmsSymmetricKeyDeletionProtection_update(keyName string, deletionProtection bool) string {
	return fmt.Sprintf(`
resource "yandex_kms_symmetric_key" "key-a" {
  name                = "%s"
  description         = "update deletion protection for key-a"
  deletion_protection = "%t"
}
`, keyName, deletionProtection)
}

func testAccKMSSymmetricKey_update(key1Name, key2Name, key3Name string) string {
	return fmt.Sprintf(`
resource "yandex_kms_symmetric_key" "key-a" {
  name              = "%s"
  description       = "description with update for key-a"
  default_algorithm = "AES_192"

  labels = {
    empty-label = "oh-look-theres-a-label-now"
    new-field   = "only-shows-up-when-updated"
  }
}

resource "yandex_kms_symmetric_key" "key-b" {
  name              = "%s"
  description       = "description with update for key-b"
  default_algorithm = "AES_192"

  labels = {
    empty-label = "oh-look-theres-a-label-now"
    new-field   = "only-shows-up-when-updated"
  }
}

resource "yandex_kms_symmetric_key" "key-c" {
  name              = "%s"
  description       = "description with update for key-c"
  default_algorithm = "AES_192"
  rotation_period   = "8760h"   // equal 1 year

  labels = {
    empty-label = "oh-look-theres-a-label-now"
    new-field   = "only-shows-up-when-updated"
  }
}
`, key1Name, key2Name, key3Name)
}
