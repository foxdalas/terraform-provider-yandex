package cdn_rule

import (
	"context"
	"fmt"

	"github.com/yandex-cloud/go-genproto/yandex/cloud/cdn/v1"
	provider_config "github.com/yandex-cloud/terraform-provider-yandex/yandex-framework/provider/config"
)

// ruleBackend isolates the Yandex SDK calls used by the cdn_rule resource and
// data source. Mutation methods own operation polling so the resource code
// stays focused on Terraform-side logic. Create and Update both unpack the
// metadata that carries the rule ID, because the CDN API's Update is a
// "clone with new ID" operation — the returned ruleID is typically different
// from the one in the request and represents the freshly-rebuilt rule. The
// resource is expected to delete the old rule after a renumbering Update.
type ruleBackend interface {
	Create(ctx context.Context, req *cdn.CreateResourceRuleRequest) (ruleID int64, err error)
	Update(ctx context.Context, req *cdn.UpdateResourceRuleRequest) (newRuleID int64, err error)
	Delete(ctx context.Context, req *cdn.DeleteResourceRuleRequest) error
	Get(ctx context.Context, req *cdn.GetResourceRuleRequest) (*cdn.Rule, error)
	List(ctx context.Context, req *cdn.ListResourceRulesRequest) (*cdn.ListResourceRulesResponse, error)
}

type sdkBackend struct {
	cfg *provider_config.Config
}

func newSDKBackend(cfg *provider_config.Config) *sdkBackend {
	return &sdkBackend{cfg: cfg}
}

func (b *sdkBackend) Create(ctx context.Context, req *cdn.CreateResourceRuleRequest) (int64, error) {
	op, err := b.cfg.SDK.WrapOperation(b.cfg.SDK.CDN().ResourceRules().Create(ctx, req))
	if err != nil {
		return 0, err
	}
	if err := op.Wait(ctx); err != nil {
		return 0, err
	}
	md, err := op.Metadata()
	if err != nil {
		return 0, fmt.Errorf("get operation metadata: %w", err)
	}
	meta, ok := md.(*cdn.CreateResourceRuleMetadata)
	if !ok {
		return 0, fmt.Errorf("unexpected operation metadata type: %T", md)
	}
	return meta.RuleId, nil
}

func (b *sdkBackend) Update(ctx context.Context, req *cdn.UpdateResourceRuleRequest) (int64, error) {
	op, err := b.cfg.SDK.WrapOperation(b.cfg.SDK.CDN().ResourceRules().Update(ctx, req))
	if err != nil {
		return 0, err
	}
	if err := op.Wait(ctx); err != nil {
		return 0, err
	}
	md, err := op.Metadata()
	if err != nil {
		return 0, fmt.Errorf("get operation metadata: %w", err)
	}
	meta, ok := md.(*cdn.UpdateResourceRuleMetadata)
	if !ok {
		return 0, fmt.Errorf("unexpected operation metadata type: %T", md)
	}
	return meta.RuleId, nil
}

func (b *sdkBackend) Delete(ctx context.Context, req *cdn.DeleteResourceRuleRequest) error {
	op, err := b.cfg.SDK.WrapOperation(b.cfg.SDK.CDN().ResourceRules().Delete(ctx, req))
	if err != nil {
		return err
	}
	return op.Wait(ctx)
}

func (b *sdkBackend) Get(ctx context.Context, req *cdn.GetResourceRuleRequest) (*cdn.Rule, error) {
	return b.cfg.SDK.CDN().ResourceRules().Get(ctx, req)
}

func (b *sdkBackend) List(ctx context.Context, req *cdn.ListResourceRulesRequest) (*cdn.ListResourceRulesResponse, error) {
	return b.cfg.SDK.CDN().ResourceRules().List(ctx, req)
}
