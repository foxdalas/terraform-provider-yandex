package yandex_kms_asymmetric_signature_key_test

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/hashicorp/go-multierror"
	"github.com/hashicorp/terraform-plugin-testing/helper/acctest"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/plancheck"
	"github.com/hashicorp/terraform-plugin-testing/terraform"
	kms "github.com/yandex-cloud/go-genproto/yandex/cloud/kms/v1/asymmetricsignature"
	asymmetricsignaturesdk "github.com/yandex-cloud/go-sdk/services/kms/v1/asymmetricsignature"
	test "github.com/yandex-cloud/terraform-provider-yandex/pkg/testhelpers"
	yandex_framework "github.com/yandex-cloud/terraform-provider-yandex/yandex-framework/provider"
	provider_config "github.com/yandex-cloud/terraform-provider-yandex/yandex-framework/provider/config"
	"google.golang.org/protobuf/types/known/fieldmaskpb"
)

// TestMain - add sweepers flag to the go test command
// important for sweepers run.
func TestMain(m *testing.M) {
	resource.TestMain(m)
}

func init() {
	resource.AddTestSweepers("yandex_kms_asymmetric_signature_key", &resource.Sweeper{
		Name: "yandex_kms_asymmetric_signature_key",
		F:    testSweepKMSAsymmetricSignatureKey,
	})
}

func TestAccKMSAsymmetricSignatureKey_UpgradeFromSDKv2(t *testing.T) {
	t.Parallel()

	key1Name := fmt.Sprintf("tf-test-%s", acctest.RandString(10))
	key2Name := fmt.Sprintf("tf-test-%s", acctest.RandString(10))
	key3Name := fmt.Sprintf("tf-test-%s", acctest.RandString(10))

	resource.Test(t, resource.TestCase{
		PreCheck:     func() { test.AccPreCheck(t) },
		CheckDestroy: testAccCheckKMSAsymmetricSignatureKeyDestroy,
		Steps: []resource.TestStep{
			{
				ExternalProviders: map[string]resource.ExternalProvider{
					"yandex": {
						VersionConstraint: "0.150.0",
						Source:            "yandex-cloud/yandex",
					},
				},
				Config: testAccKMSAsymmetricSignatureKey_basic(key1Name, key2Name, key3Name),
				Check: resource.ComposeTestCheckFunc(
					test.AccCheckCreatedAtAttr("yandex_kms_asymmetric_signature_key.key-a"),
					test.AccCheckCreatedAtAttr("yandex_kms_asymmetric_signature_key.key-b"),
					test.AccCheckCreatedAtAttr("yandex_kms_asymmetric_signature_key.key-c"),
				),
			},
			{
				ProtoV6ProviderFactories: test.AccProviderFactories,
				Config:                   testAccKMSAsymmetricSignatureKey_basic(key1Name, key2Name, key3Name),
				ConfigPlanChecks: resource.ConfigPlanChecks{
					PreApply: []plancheck.PlanCheck{
						plancheck.ExpectEmptyPlan(),
					},
				},
			},
		},
	})
}

func TestAccKMSAsymmetricSignatureKey_basic(t *testing.T) {
	t.Parallel()

	var asymmetricSignatureKey1 kms.AsymmetricSignatureKey
	var asymmetricSignatureKey2 kms.AsymmetricSignatureKey
	var asymmetricSignatureKey3 kms.AsymmetricSignatureKey

	key1Name := fmt.Sprintf("tf-test-%s", acctest.RandString(10))
	key2Name := fmt.Sprintf("tf-test-%s", acctest.RandString(10))
	key3Name := fmt.Sprintf("tf-test-%s", acctest.RandString(10))

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { test.AccPreCheck(t) },
		ProtoV6ProviderFactories: test.AccProviderFactories,
		CheckDestroy:             testAccCheckKMSAsymmetricSignatureKeyDestroy,
		Steps: []resource.TestStep{
			{
				Config: testAccKMSAsymmetricSignatureKey_basic(key1Name, key2Name, key3Name),
				Check: resource.ComposeTestCheckFunc(
					testAccCheckKMSAsymmetricSignatureKeyExists(
						"yandex_kms_asymmetric_signature_key.key-a", &asymmetricSignatureKey1),
					testAccCheckKMSAsymmetricSignatureKeyExists(
						"yandex_kms_asymmetric_signature_key.key-b", &asymmetricSignatureKey2),
					testAccCheckKMSAsymmetricSignatureKeyExists(
						"yandex_kms_asymmetric_signature_key.key-c", &asymmetricSignatureKey3),
					test.AccCheckCreatedAtAttr("yandex_kms_asymmetric_signature_key.key-a"),
					test.AccCheckCreatedAtAttr("yandex_kms_asymmetric_signature_key.key-b"),
					test.AccCheckCreatedAtAttr("yandex_kms_asymmetric_signature_key.key-c"),
				),
			},
			{
				ResourceName:      "yandex_kms_asymmetric_signature_key.key-a",
				ImportState:       true,
				ImportStateVerify: true,
			},
			{
				ResourceName:      "yandex_kms_asymmetric_signature_key.key-b",
				ImportState:       true,
				ImportStateVerify: true,
			},
			{
				ResourceName:      "yandex_kms_asymmetric_signature_key.key-c",
				ImportState:       true,
				ImportStateVerify: true,
			},
		},
	})
}

func TestAccKMSAsymmetricSignatureKey_deletion_protection(t *testing.T) {
	t.Parallel()

	var asymmetricSignatureKey1 kms.AsymmetricSignatureKey
	var asymmetricSignatureKey2 kms.AsymmetricSignatureKey
	var asymmetricSignatureKey3 kms.AsymmetricSignatureKey

	key1Name := fmt.Sprintf("tf-test-%s", acctest.RandString(10))
	key2Name := fmt.Sprintf("tf-test-%s", acctest.RandString(10))
	key3Name := fmt.Sprintf("tf-test-%s", acctest.RandString(10))

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { test.AccPreCheck(t) },
		ProtoV6ProviderFactories: test.AccProviderFactories,
		CheckDestroy:             testAccCheckKMSAsymmetricSignatureKeyDestroy,

		Steps: []resource.TestStep{
			{
				Config: testAccKMSAsymmetricSignatureKey_deletion_protection(key1Name, key2Name, key3Name),
				Check: resource.ComposeTestCheckFunc(
					testAccCheckKMSAsymmetricSignatureKeyExists(
						"yandex_kms_asymmetric_signature_key.key-a", &asymmetricSignatureKey1),
					testAccCheckKMSAsymmetricSignatureKeyExists(
						"yandex_kms_asymmetric_signature_key.key-b", &asymmetricSignatureKey2),
					testAccCheckKMSAsymmetricSignatureKeyExists(
						"yandex_kms_asymmetric_signature_key.key-c", &asymmetricSignatureKey3),
					test.AccCheckBoolValue("yandex_kms_asymmetric_signature_key.key-a", "deletion_protection", true),
					test.AccCheckBoolValue("yandex_kms_asymmetric_signature_key.key-b", "deletion_protection", false),
					test.AccCheckBoolValue("yandex_kms_asymmetric_signature_key.key-c", "deletion_protection", false),
					test.AccCheckCreatedAtAttr("yandex_kms_asymmetric_signature_key.key-a"),
					test.AccCheckCreatedAtAttr("yandex_kms_asymmetric_signature_key.key-b"),
					test.AccCheckCreatedAtAttr("yandex_kms_asymmetric_signature_key.key-c"),
				),
			},
			{
				ResourceName:      "yandex_kms_asymmetric_signature_key.key-a",
				ImportState:       true,
				ImportStateVerify: true,
			},
			{
				ResourceName:      "yandex_kms_asymmetric_signature_key.key-b",
				ImportState:       true,
				ImportStateVerify: true,
			},
			{
				ResourceName:      "yandex_kms_asymmetric_signature_key.key-c",
				ImportState:       true,
				ImportStateVerify: true,
			},
			{
				Config: testAccKmsAsymmetricSignatureKeyDeletionProtection_update(key1Name, false),
				Check: resource.ComposeTestCheckFunc(
					test.AccCheckBoolValue("yandex_kms_asymmetric_signature_key.key-a", "deletion_protection", false),
				),
			},
		},
	})
}

func TestAccKMSAsymmetricSignatureKey_update(t *testing.T) {
	t.Parallel()

	var asymmetricSignatureKey1 kms.AsymmetricSignatureKey
	var asymmetricSignatureKey2 kms.AsymmetricSignatureKey
	var asymmetricSignatureKey3 kms.AsymmetricSignatureKey

	key1Name := acctest.RandomWithPrefix("tf-key-a")
	key2Name := acctest.RandomWithPrefix("tf-key-b")
	key3Name := acctest.RandomWithPrefix("tf-key-c")
	updatedKey1Name := key1Name + "-update"
	updatedKey2Name := key2Name + "-update"
	updatedKey3Name := key3Name + "-update"

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { test.AccPreCheck(t) },
		ProtoV6ProviderFactories: test.AccProviderFactories,
		CheckDestroy:             testAccCheckKMSAsymmetricSignatureKeyDestroy,
		Steps: []resource.TestStep{
			{
				Config: testAccKMSAsymmetricSignatureKey_basic(key1Name, key2Name, key3Name),
				Check: resource.ComposeTestCheckFunc(
					testAccCheckKMSAsymmetricSignatureKeyExists("yandex_kms_asymmetric_signature_key.key-a", &asymmetricSignatureKey1),
					resource.TestCheckResourceAttr("yandex_kms_asymmetric_signature_key.key-a", "name", key1Name),
					resource.TestCheckResourceAttr("yandex_kms_asymmetric_signature_key.key-a", "description", "description for key-a"),
					resource.TestCheckResourceAttr("yandex_kms_asymmetric_signature_key.key-a", "signature_algorithm", "RSA_2048_SIGN_PSS_SHA_256"),

					testAccCheckKMSAsymmetricSignatureKeyContainsLabel(&asymmetricSignatureKey1, "tf-label", "tf-label-value-a"),
					testAccCheckKMSAsymmetricSignatureKeyContainsLabel(&asymmetricSignatureKey1, "empty-label", ""),
					test.AccCheckCreatedAtAttr("yandex_kms_asymmetric_signature_key.key-a"),

					testAccCheckKMSAsymmetricSignatureKeyExists("yandex_kms_asymmetric_signature_key.key-b", &asymmetricSignatureKey2),
					resource.TestCheckResourceAttr("yandex_kms_asymmetric_signature_key.key-b", "name", key2Name),
					resource.TestCheckResourceAttr("yandex_kms_asymmetric_signature_key.key-b", "description", "description for key-b"),
					resource.TestCheckResourceAttr("yandex_kms_asymmetric_signature_key.key-b", "signature_algorithm", "RSA_4096_SIGN_PSS_SHA_256"),
					testAccCheckKMSAsymmetricSignatureKeyContainsLabel(&asymmetricSignatureKey2, "tf-label", "tf-label-value-b"),
					testAccCheckKMSAsymmetricSignatureKeyContainsLabel(&asymmetricSignatureKey2, "empty-label", ""),
					test.AccCheckCreatedAtAttr("yandex_kms_asymmetric_signature_key.key-b"),

					testAccCheckKMSAsymmetricSignatureKeyExists("yandex_kms_asymmetric_signature_key.key-c", &asymmetricSignatureKey3),
					resource.TestCheckResourceAttr("yandex_kms_asymmetric_signature_key.key-c", "name", key3Name),
					resource.TestCheckResourceAttr("yandex_kms_asymmetric_signature_key.key-c", "description", "description for key-c"),
					resource.TestCheckResourceAttr("yandex_kms_asymmetric_signature_key.key-c", "signature_algorithm", "RSA_3072_SIGN_PSS_SHA_256"),
					testAccCheckKMSAsymmetricSignatureKeyContainsLabel(&asymmetricSignatureKey3, "tf-label", "tf-label-value-c"),
					testAccCheckKMSAsymmetricSignatureKeyContainsLabel(&asymmetricSignatureKey3, "empty-label", ""),
					test.AccCheckCreatedAtAttr("yandex_kms_asymmetric_signature_key.key-c"),
				),
			},
			{
				Config: testAccKMSAsymmetricSignatureKey_update(updatedKey1Name, updatedKey2Name, updatedKey3Name),
				Check: resource.ComposeTestCheckFunc(
					testAccCheckKMSAsymmetricSignatureKeyExists("yandex_kms_asymmetric_signature_key.key-a", &asymmetricSignatureKey1),
					resource.TestCheckResourceAttr("yandex_kms_asymmetric_signature_key.key-a", "name", updatedKey1Name),
					resource.TestCheckResourceAttr("yandex_kms_asymmetric_signature_key.key-a", "signature_algorithm", "RSA_2048_SIGN_PSS_SHA_256"),
					testAccCheckKMSAsymmetricSignatureKeyContainsLabel(&asymmetricSignatureKey1, "empty-label", "oh-look-theres-a-label-now"),
					testAccCheckKMSAsymmetricSignatureKeyContainsLabel(&asymmetricSignatureKey1, "new-field", "only-shows-up-when-updated"),

					testAccCheckKMSAsymmetricSignatureKeyExists("yandex_kms_asymmetric_signature_key.key-b", &asymmetricSignatureKey2),
					resource.TestCheckResourceAttr("yandex_kms_asymmetric_signature_key.key-b", "name", updatedKey2Name),
					resource.TestCheckResourceAttr("yandex_kms_asymmetric_signature_key.key-b", "signature_algorithm", "RSA_4096_SIGN_PSS_SHA_256"),
					testAccCheckKMSAsymmetricSignatureKeyContainsLabel(&asymmetricSignatureKey2, "empty-label", "oh-look-theres-a-label-now"),
					testAccCheckKMSAsymmetricSignatureKeyContainsLabel(&asymmetricSignatureKey2, "new-field", "only-shows-up-when-updated"),

					testAccCheckKMSAsymmetricSignatureKeyExists("yandex_kms_asymmetric_signature_key.key-c", &asymmetricSignatureKey3),
					resource.TestCheckResourceAttr("yandex_kms_asymmetric_signature_key.key-c", "name", updatedKey3Name),
					resource.TestCheckResourceAttr("yandex_kms_asymmetric_signature_key.key-c", "signature_algorithm", "RSA_3072_SIGN_PSS_SHA_256"),
					testAccCheckKMSAsymmetricSignatureKeyContainsLabel(&asymmetricSignatureKey3, "empty-label", "oh-look-theres-a-label-now"),
					testAccCheckKMSAsymmetricSignatureKeyContainsLabel(&asymmetricSignatureKey3, "new-field", "only-shows-up-when-updated"),
				),
			},
			{
				ResourceName:      "yandex_kms_asymmetric_signature_key.key-a",
				ImportState:       true,
				ImportStateVerify: true,
				ImportStateCheck:  test.CheckImportFolderID(test.GetExampleFolderID()),
			},
			{
				ResourceName:      "yandex_kms_asymmetric_signature_key.key-b",
				ImportState:       true,
				ImportStateVerify: true,
			},
			{
				ResourceName:      "yandex_kms_asymmetric_signature_key.key-c",
				ImportState:       true,
				ImportStateVerify: true,
			},
		},
	})
}

func testAccCheckKMSAsymmetricSignatureKeyDestroy(s *terraform.State) error {
	config := test.AccProvider.(*yandex_framework.Provider).GetConfig()

	for _, rs := range s.RootModule().Resources {
		if rs.Type != "yandex_kms_asymmetric_signature_key" {
			continue
		}
		_, err := asymmetricsignaturesdk.NewAsymmetricSignatureKeyClient(config.SDKv2).Get(context.Background(), &kms.GetAsymmetricSignatureKeyRequest{
			KeyId: rs.Primary.ID,
		})
		if err == nil {
			return fmt.Errorf("KMS AsymmetricSignatureKey still exists")
		}
	}

	return nil
}

func testAccCheckKMSAsymmetricSignatureKeyExists(name string, asymmetricSignatureKey *kms.AsymmetricSignatureKey) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		rs, ok := s.RootModule().Resources[name]
		if !ok {
			return fmt.Errorf("Not found: %s", name)
		}

		if rs.Primary.ID == "" {
			return fmt.Errorf("No ID is set")
		}

		config := test.AccProvider.(*yandex_framework.Provider).GetConfig()

		found, err := asymmetricsignaturesdk.NewAsymmetricSignatureKeyClient(config.SDKv2).Get(context.Background(), &kms.GetAsymmetricSignatureKeyRequest{
			KeyId: rs.Primary.ID,
		})
		if err != nil {
			return err
		}

		if found.Id != rs.Primary.ID {
			return fmt.Errorf("KMS AsymmetricSignatureKey not found")
		}

		*asymmetricSignatureKey = *found

		return nil
	}
}

func testAccCheckKMSAsymmetricSignatureKeyContainsLabel(asymmetricSignatureKey *kms.AsymmetricSignatureKey, key string, value string) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		v, ok := asymmetricSignatureKey.Labels[key]
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
func testAccKMSAsymmetricSignatureKey_basic(key1Name, key2Name, key3Name string) string {
	return fmt.Sprintf(`
resource "yandex_kms_asymmetric_signature_key" "key-a" {
  name              = "%s"
  description       = "description for key-a"
  signature_algorithm = "RSA_2048_SIGN_PSS_SHA_256"

  labels = {
    tf-label    = "tf-label-value-a"
    empty-label = ""
  }
}

resource "yandex_kms_asymmetric_signature_key" "key-b" {
  name              = "%s"
  description       = "description for key-b"
  signature_algorithm = "RSA_4096_SIGN_PSS_SHA_256"

  labels = {
    tf-label    = "tf-label-value-b"
    empty-label = ""
  }
}

resource "yandex_kms_asymmetric_signature_key" "key-c" {
  name              = "%s"
  description       = "description for key-c"
  signature_algorithm = "RSA_3072_SIGN_PSS_SHA_256"

  labels = {
    tf-label    = "tf-label-value-c"
    empty-label = ""
  }
}

`, key1Name, key2Name, key3Name)
}

//revive:disable:var-naming
func testAccKMSAsymmetricSignatureKey_deletion_protection(key1Name, key2Name, key3Name string) string {
	return fmt.Sprintf(`
resource "yandex_kms_asymmetric_signature_key" "key-a" {
  name                = "%s"
  description         = "description for key-a"
  deletion_protection = true
}

resource "yandex_kms_asymmetric_signature_key" "key-b" {
  name                = "%s"
  description         = "description for key-b"
  deletion_protection = false

}

resource "yandex_kms_asymmetric_signature_key" "key-c" {
  name        = "%s"
  description = "description for key-c"
}

`, key1Name, key2Name, key3Name)
}

func testAccKmsAsymmetricSignatureKeyDeletionProtection_update(keyName string, deletionProtection bool) string {
	return fmt.Sprintf(`
resource "yandex_kms_asymmetric_signature_key" "key-a" {
  name                = "%s"
  description         = "update deletion protection for key-a"
  deletion_protection = "%t"
}
`, keyName, deletionProtection)
}

func testAccKMSAsymmetricSignatureKey_update(key1Name, key2Name, key3Name string) string {
	return fmt.Sprintf(`
resource "yandex_kms_asymmetric_signature_key" "key-a" {
  name              = "%s"
  description       = "description with update for key-a"

  labels = {
    empty-label = "oh-look-theres-a-label-now"
    new-field   = "only-shows-up-when-updated"
  }
}

resource "yandex_kms_asymmetric_signature_key" "key-b" {
  name              = "%s"
  description       = "description with update for key-b"
  signature_algorithm = "RSA_4096_SIGN_PSS_SHA_256"

  labels = {
    empty-label = "oh-look-theres-a-label-now"
    new-field   = "only-shows-up-when-updated"
  }
}

resource "yandex_kms_asymmetric_signature_key" "key-c" {
  name              = "%s"
  description       = "description with update for key-c"
  signature_algorithm = "RSA_3072_SIGN_PSS_SHA_256"

  labels = {
    empty-label = "oh-look-theres-a-label-now"
    new-field   = "only-shows-up-when-updated"
  }
}
`, key1Name, key2Name, key3Name)
}

func testSweepKMSAsymmetricSignatureKey(_ string) error {
	conf, err := test.ConfigForSweepers()
	if err != nil {
		return fmt.Errorf("error getting client: %s", err)
	}

	req := &kms.ListAsymmetricSignatureKeysRequest{FolderId: conf.ProviderState.FolderID.ValueString()}
	resp, err := asymmetricsignaturesdk.NewAsymmetricSignatureKeyClient(conf.SDKv2).List(context.Background(), req)
	if err != nil {
		return fmt.Errorf("error getting keys: %s", err)
	}

	result := &multierror.Error{}
	for _, k := range resp.Keys {
		id := k.GetId()
		if !test.SweepWithRetry(sweepKMSAsymmetricSignatureKeyOnce, conf, "KMS Asymmetric Signature Key", id) {
			result = multierror.Append(result, fmt.Errorf("failed to sweep KSMS Asymmetric Signature Key %q", id))
		}
	}

	return result.ErrorOrNil()
}

func sweepKMSAsymmetricSignatureKeyOnce(conf *provider_config.Config, id string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Minute)
	defer cancel()

	op, err := asymmetricsignaturesdk.NewAsymmetricSignatureKeyClient(conf.SDKv2).Update(ctx, &kms.UpdateAsymmetricSignatureKeyRequest{
		KeyId:              id,
		DeletionProtection: false,
		UpdateMask: &fieldmaskpb.FieldMask{
			Paths: []string{"deletion_protection"},
		},
	})
	if err != nil {
		return err
	}
	if _, err = op.Wait(ctx); err != nil {
		return err
	}

	opDelete, err := asymmetricsignaturesdk.NewAsymmetricSignatureKeyClient(conf.SDKv2).Delete(ctx, &kms.DeleteAsymmetricSignatureKeyRequest{
		KeyId: id,
	})
	if err != nil {
		return err
	}
	_, err = opDelete.Wait(ctx)
	return err
}
