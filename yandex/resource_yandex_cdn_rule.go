package yandex

import (
	"fmt"
	"log"
	"regexp"
	"strconv"
	"time"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/validation"
	"github.com/yandex-cloud/go-genproto/yandex/cloud/cdn/v1"
)

func resourceYandexCDNRule() *schema.Resource {
	return &schema.Resource{
		Create: resourceYandexCDNRuleCreate,
		Read:   resourceYandexCDNRuleRead,
		Update: resourceYandexCDNRuleUpdate,
		Delete: resourceYandexCDNRuleDelete,
		Importer: &schema.ResourceImporter{
			State: resourceYandexCDNRuleImport,
		},

		Timeouts: &schema.ResourceTimeout{
			Create: schema.DefaultTimeout(5 * time.Minute),
			Read:   schema.DefaultTimeout(5 * time.Minute),
			Update: schema.DefaultTimeout(5 * time.Minute),
			Delete: schema.DefaultTimeout(5 * time.Minute),
		},

		SchemaVersion: 0,

		Schema: map[string]*schema.Schema{
			"resource_id": {
				Type:        schema.TypeString,
				Required:    true,
				ForceNew:    true,
				Description: "CDN Resource ID to attach the rule to",
			},

			"name": {
				Type:         schema.TypeString,
				Required:     true,
				ValidateFunc: validation.StringLenBetween(1, 50),
				Description:  "Rule name (max 50 characters)",
			},

			"rule_pattern": {
				Type:         schema.TypeString,
				Required:     true,
				ValidateFunc: validateCDNRulePattern,
				Description:  "Rule pattern - must be a valid regular expression (max 100 characters)",
			},

			"weight": {
				Type:         schema.TypeInt,
				Optional:     true,
				Default:      0,
				ValidateFunc: validation.IntBetween(0, 9999),
				Description:  "Rule weight (0-9999) - rules with lower weights execute first",
			},

			"options": cdnResourceOptionsSchema(),

			// Computed fields
			"rule_id": {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "Rule ID (stored as string to avoid int64 precision loss)",
			},
		},
	}
}

// validateCDNRulePattern validates that the pattern is a valid regex
func validateCDNRulePattern(v interface{}, k string) (warns []string, errs []error) {
	value := v.(string)
	
	if len(value) > 100 {
		errs = append(errs, fmt.Errorf("rule pattern must be 100 characters or less"))
		return
	}
	
	if len(value) == 0 {
		errs = append(errs, fmt.Errorf("rule pattern must not be empty"))
		return
	}
	
	// Try to compile the regex to validate it
	_, err := regexp.Compile(value)
	if err != nil {
		errs = append(errs, fmt.Errorf("rule pattern must be a valid regular expression: %v", err))
	}
	
	return
}

// cdnResourceOptionsSchema returns the schema for CDN options
// This is extracted to be shared between CDN Resource and CDN Rule
func cdnResourceOptionsSchema() *schema.Schema {
	return &schema.Schema{
		Type:     schema.TypeList,
		Optional: true,
		MaxItems: 1,
		Elem: &schema.Resource{
			Schema: cdnOptionsSchemaFields(),
		},
	}
}

// cdnOptionsSchemaFields returns the actual fields for CDN options
// This allows reuse between resources
func cdnOptionsSchemaFields() map[string]*schema.Schema {
	return map[string]*schema.Schema{
		"disable_cache": {
			Type:     schema.TypeBool,
			Optional: true,
		},
		"edge_cache_settings": {
			Type:     schema.TypeList,
			Optional: true,
			MaxItems: 1,
			Elem: &schema.Resource{
				Schema: map[string]*schema.Schema{
					"enabled": {
						Type:     schema.TypeBool,
						Optional: true,
						Default:  true,
					},
					"default_value": {
						Type:         schema.TypeInt,
						Optional:     true,
						ValidateFunc: validation.IntBetween(0, 31536000), // 365 days in seconds
					},
					"custom_values": {
						Type:     schema.TypeMap,
						Optional: true,
						Elem:     &schema.Schema{Type: schema.TypeString},
					},
				},
			},
		},
		"browser_cache_settings": {
			Type:         schema.TypeInt,
			Optional:     true,
			ValidateFunc: validation.IntBetween(0, 31536000), // 365 days in seconds
		},
		"cache_http_headers": {
			Type:     schema.TypeSet,
			Optional: true,
			Elem:     &schema.Schema{Type: schema.TypeString},
			Set:      schema.HashString,
		},
		"query_params_whitelist": {
			Type:          schema.TypeSet,
			Optional:      true,
			Elem:          &schema.Schema{Type: schema.TypeString},
			Set:           schema.HashString,
			ConflictsWith: []string{"options.0.query_params_blacklist"},
		},
		"query_params_blacklist": {
			Type:          schema.TypeSet,
			Optional:      true,
			Elem:          &schema.Schema{Type: schema.TypeString},
			Set:           schema.HashString,
			ConflictsWith: []string{"options.0.query_params_whitelist"},
		},
		"ignore_cookie": {
			Type:     schema.TypeBool,
			Optional: true,
		},
		"ignore_query_params": {
			Type:     schema.TypeBool,
			Optional: true,
		},
		"static_request_headers": {
			Type:     schema.TypeMap,
			Optional: true,
			Elem:     &schema.Schema{Type: schema.TypeString},
		},
		"static_response_headers": {
			Type:             schema.TypeMap,
			Optional:         true,
			Elem:             &schema.Schema{Type: schema.TypeString},
			// Static response headers validation is handled by expandCDNResourceOptions
		},
		"custom_server_name": {
			Type:     schema.TypeString,
			Optional: true,
		},
		"custom_host_header": {
			Type:     schema.TypeString,
			Optional: true,
		},
		"forward_host_header": {
			Type:     schema.TypeBool,
			Optional: true,
		},
		"slice": {
			Type:     schema.TypeBool,
			Optional: true,
		},
		"fetched_compressed": {
			Type:          schema.TypeBool,
			Optional:      true,
			ConflictsWith: []string{"options.0.gzip_on"},
		},
		"gzip_on": {
			Type:          schema.TypeBool,
			Optional:      true,
			ConflictsWith: []string{"options.0.fetched_compressed"},
		},
		"redirect_http_to_https": {
			Type:          schema.TypeBool,
			Optional:      true,
			ConflictsWith: []string{"options.0.redirect_https_to_http"},
		},
		"redirect_https_to_http": {
			Type:          schema.TypeBool,
			Optional:      true,
			ConflictsWith: []string{"options.0.redirect_http_to_https"},
		},
		"allowed_http_methods": {
			Type:     schema.TypeSet,
			Optional: true,
			Elem: &schema.Schema{
				Type: schema.TypeString,
				ValidateFunc: validation.StringInSlice([]string{
					"GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "TRACE", "CONNECT",
				}, false),
			},
			Set: schema.HashString,
		},
		"proxy_cache_methods_set": {
			Type:     schema.TypeBool,
			Optional: true,
		},
		"disable_proxy_force_ranges": {
			Type:     schema.TypeBool,
			Optional: true,
		},
		"cors": {
			Type:     schema.TypeSet,
			Optional: true,
			Elem:     &schema.Schema{Type: schema.TypeString},
			Set:      schema.HashString,
		},
		"host_header": {
			Type:     schema.TypeString,
			Optional: true,
		},
		"static_headers": {
			Type:     schema.TypeMap,
			Optional: true,
			Elem:     &schema.Schema{Type: schema.TypeString},
		},
		"secure_key": {
			Type:     schema.TypeList,
			Optional: true,
			MaxItems: 1,
			Elem: &schema.Resource{
				Schema: map[string]*schema.Schema{
					"enabled": {
						Type:     schema.TypeBool,
						Required: true,
					},
					"key": {
						Type:      schema.TypeString,
						Required:  true,
						Sensitive: true,
					},
					"type": {
						Type:     schema.TypeString,
						Required: true,
						ValidateFunc: validation.StringInSlice([]string{
							"enable_ip_signing",
							"enable_ip_and_uri_signing",
							"enable_ip_and_uri_signing_in_cookie",
						}, false),
					},
				},
			},
		},
		"enable_ip_url_signing": {
			Type:     schema.TypeList,
			Optional: true,
			MaxItems: 1,
			Elem: &schema.Resource{
				Schema: map[string]*schema.Schema{
					"enabled": {
						Type:     schema.TypeBool,
						Required: true,
					},
					"key": {
						Type:      schema.TypeString,
						Required:  true,
						Sensitive: true,
					},
					"type": {
						Type:     schema.TypeString,
						Required: true,
						ValidateFunc: validation.StringInSlice([]string{
							"enable_ip_signing",
							"enable_ip_and_uri_signing",
							"enable_ip_and_uri_signing_in_cookie",
						}, false),
					},
				},
			},
		},
		"ip_address_acl": {
			Type:     schema.TypeList,
			Optional: true,
			MaxItems: 1,
			Elem: &schema.Resource{
				Schema: map[string]*schema.Schema{
					"enabled": {
						Type:     schema.TypeBool,
						Required: true,
					},
					"policy_type": {
						Type:     schema.TypeString,
						Required: true,
						ValidateFunc: validation.StringInSlice([]string{
							"allow",
							"deny",
						}, false),
					},
					"excepted_values": {
						Type:     schema.TypeSet,
						Required: true,
						Elem:     &schema.Schema{Type: schema.TypeString},
						Set:      schema.HashString,
					},
				},
			},
		},
	}
}

func resourceYandexCDNRuleCreate(d *schema.ResourceData, meta interface{}) error {
	config := meta.(*Config)

	log.Printf("[DEBUG] Creating CDN Rule %q for resource %q", d.Get("name").(string), d.Get("resource_id").(string))

	ctx, cancel := config.ContextWithTimeout(d.Timeout(schema.TimeoutCreate))
	defer cancel()

	options, err := expandCDNResourceOptions(d, true)
	if err != nil {
		return err
	}

	request := &cdn.CreateResourceRuleRequest{
		ResourceId:  d.Get("resource_id").(string),
		Name:        d.Get("name").(string),
		RulePattern: d.Get("rule_pattern").(string),
		Weight:      int64(d.Get("weight").(int)),
		Options:     options,
	}

	operation, err := config.sdk.WrapOperation(
		config.sdk.CDN().ResourceRules().Create(ctx, request),
	)

	if err != nil {
		return fmt.Errorf("error while requesting API to create CDN Rule: %s", err)
	}

	protoMetadata, err := operation.Metadata()
	if err != nil {
		return fmt.Errorf("error while get CDN Rule create operation metadata: %s", err)
	}

	md, ok := protoMetadata.(*cdn.CreateResourceRuleMetadata)
	if !ok {
		return fmt.Errorf("could not get CDN Rule ID from create operation metadata")
	}

	// Store as composite ID: resource_id/rule_id
	d.SetId(fmt.Sprintf("%s/%d", md.ResourceId, md.RuleId))

	err = operation.Wait(ctx)
	if err != nil {
		return fmt.Errorf("error while waiting for operation to create CDN Rule: %s", err)
	}

	if _, err := operation.Response(); err != nil {
		return fmt.Errorf("error while getting operation response of CDN Rule create: %s", err)
	}

	log.Printf("[DEBUG] Finished creating CDN Rule %q", d.Id())

	return resourceYandexCDNRuleRead(d, meta)
}

func resourceYandexCDNRuleRead(d *schema.ResourceData, meta interface{}) error {
	config := meta.(*Config)

	log.Printf("[DEBUG] Reading CDN Rule %q", d.Id())

	ctx, cancel := config.ContextWithTimeout(d.Timeout(schema.TimeoutRead))
	defer cancel()

	resourceID, ruleID, err := parseCDNRuleID(d.Id())
	if err != nil {
		return err
	}

	rule, err := config.sdk.CDN().ResourceRules().Get(ctx, &cdn.GetResourceRuleRequest{
		ResourceId: resourceID,
		RuleId:     ruleID,
	})

	if err != nil {
		return handleNotFoundError(err, d, fmt.Sprintf("CDN Rule %q", d.Id()))
	}

	return flattenCDNRule(d, rule, resourceID)
}

func resourceYandexCDNRuleUpdate(d *schema.ResourceData, meta interface{}) error {
	config := meta.(*Config)

	log.Printf("[DEBUG] Updating CDN Rule %q", d.Id())

	ctx, cancel := config.ContextWithTimeout(d.Timeout(schema.TimeoutUpdate))
	defer cancel()

	resourceID, ruleID, err := parseCDNRuleID(d.Id())
	if err != nil {
		return err
	}

	options, err := expandCDNResourceOptions(d, false)
	if err != nil {
		return err
	}

	request := &cdn.UpdateResourceRuleRequest{
		ResourceId:  resourceID,
		RuleId:      ruleID,
		Name:        d.Get("name").(string),
		RulePattern: d.Get("rule_pattern").(string),
		Options:     options,
	}

	// Weight is optional in update (uses pointer)
	if d.HasChange("weight") {
		weight := int64(d.Get("weight").(int))
		request.Weight = &weight
	}

	operation, err := config.sdk.WrapOperation(
		config.sdk.CDN().ResourceRules().Update(ctx, request),
	)

	if err != nil {
		return fmt.Errorf("error while requesting API to update CDN Rule: %s", err)
	}

	err = operation.Wait(ctx)
	if err != nil {
		return fmt.Errorf("error while waiting for operation to update CDN Rule: %s", err)
	}

	if _, err := operation.Response(); err != nil {
		return fmt.Errorf("error while getting operation response of CDN Rule update: %s", err)
	}

	log.Printf("[DEBUG] Finished updating CDN Rule %q", d.Id())

	return resourceYandexCDNRuleRead(d, meta)
}

func resourceYandexCDNRuleDelete(d *schema.ResourceData, meta interface{}) error {
	config := meta.(*Config)

	log.Printf("[DEBUG] Deleting CDN Rule %q", d.Id())

	ctx, cancel := config.ContextWithTimeout(d.Timeout(schema.TimeoutDelete))
	defer cancel()

	resourceID, ruleID, err := parseCDNRuleID(d.Id())
	if err != nil {
		return err
	}

	operation, err := config.sdk.WrapOperation(
		config.sdk.CDN().ResourceRules().Delete(ctx, &cdn.DeleteResourceRuleRequest{
			ResourceId: resourceID,
			RuleId:     ruleID,
		}),
	)

	if err != nil {
		return handleNotFoundError(err, d, fmt.Sprintf("CDN Rule %q", d.Id()))
	}

	err = operation.Wait(ctx)
	if err != nil {
		return handleNotFoundError(err, d, fmt.Sprintf("CDN Rule %q", d.Id()))
	}

	if _, err := operation.Response(); err != nil {
		return handleNotFoundError(err, d, fmt.Sprintf("CDN Rule %q", d.Id()))
	}

	log.Printf("[DEBUG] Finished deleting CDN Rule %q", d.Id())
	return nil
}

func resourceYandexCDNRuleImport(d *schema.ResourceData, meta interface{}) ([]*schema.ResourceData, error) {
	// Import format: resource_id/rule_id
	resourceID, ruleID, err := parseCDNRuleID(d.Id())
	if err != nil {
		return nil, fmt.Errorf("invalid import ID format, expected: resource_id/rule_id")
	}

	// Set the resource_id field
	d.Set("resource_id", resourceID)
	d.Set("rule_id", strconv.FormatInt(ruleID, 10))

	return []*schema.ResourceData{d}, resourceYandexCDNRuleRead(d, meta)
}

// parseCDNRuleID parses composite ID format: resource_id/rule_id
func parseCDNRuleID(id string) (string, int64, error) {
	parts := regexp.MustCompile(`^([^/]+)/(\d+)$`).FindStringSubmatch(id)
	if len(parts) != 3 {
		return "", 0, fmt.Errorf("invalid CDN Rule ID format: %s", id)
	}

	ruleID, err := strconv.ParseInt(parts[2], 10, 64)
	if err != nil {
		return "", 0, fmt.Errorf("invalid rule ID in CDN Rule ID: %s", id)
	}

	return parts[1], ruleID, nil
}

// flattenCDNRule sets Terraform state from API response
func flattenCDNRule(d *schema.ResourceData, rule *cdn.Rule, resourceID string) error {
	d.Set("resource_id", resourceID)
	d.Set("rule_id", strconv.FormatInt(rule.Id, 10))
	d.Set("name", rule.Name)
	d.Set("rule_pattern", rule.RulePattern)
	d.Set("weight", rule.Weight)

	if rule.Options != nil {
		options := flattenYandexCDNResourceOptions(rule.Options)
		if err := d.Set("options", options); err != nil {
			return err
		}
	}

	return nil
}