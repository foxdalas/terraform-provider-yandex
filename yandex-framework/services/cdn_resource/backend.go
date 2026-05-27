package cdn_resource

import (
	"context"
	"fmt"

	"github.com/yandex-cloud/go-genproto/yandex/cloud/cdn/v1"
	provider_config "github.com/yandex-cloud/terraform-provider-yandex/yandex-framework/provider/config"
)

// resourceBackend isolates the Yandex SDK calls used by the cdn_resource
// resource and data source. Mutation methods own operation polling so the
// resource code stays focused on Terraform-side logic. Create unpacks the
// metadata that carries the freshly-assigned resource ID. Shielding lives
// behind the same interface because it is a sibling API surface that the
// resource Create/Update flow has to coordinate with.
type resourceBackend interface {
	Create(ctx context.Context, req *cdn.CreateResourceRequest) (resourceID string, err error)
	Get(ctx context.Context, req *cdn.GetResourceRequest) (*cdn.Resource, error)
	Update(ctx context.Context, req *cdn.UpdateResourceRequest) error
	Delete(ctx context.Context, req *cdn.DeleteResourceRequest) error
	List(ctx context.Context, req *cdn.ListResourcesRequest) ([]*cdn.Resource, error)

	OriginGroupList(ctx context.Context, req *cdn.ListOriginGroupsRequest) ([]*cdn.OriginGroup, error)

	// ShieldingGet returns nil details (no error) when the API answers NotFound,
	// because "shielding not configured" is not an error to the caller.
	ShieldingGet(ctx context.Context, req *cdn.GetShieldingDetailsRequest) (*cdn.ShieldingDetails, error)
	ShieldingActivate(ctx context.Context, req *cdn.ActivateShieldingRequest) error
	ShieldingDeactivate(ctx context.Context, req *cdn.DeactivateShieldingRequest) error
}

type sdkBackend struct {
	cfg *provider_config.Config
}

func newSDKBackend(cfg *provider_config.Config) *sdkBackend {
	return &sdkBackend{cfg: cfg}
}

func (b *sdkBackend) Create(ctx context.Context, req *cdn.CreateResourceRequest) (string, error) {
	op, err := b.cfg.SDK.WrapOperation(b.cfg.SDK.CDN().Resource().Create(ctx, req))
	if err != nil {
		return "", err
	}
	if err := op.Wait(ctx); err != nil {
		return "", err
	}
	md, err := op.Metadata()
	if err != nil {
		return "", fmt.Errorf("get operation metadata: %w", err)
	}
	meta, ok := md.(*cdn.CreateResourceMetadata)
	if !ok {
		return "", fmt.Errorf("unexpected operation metadata type: %T", md)
	}
	return meta.ResourceId, nil
}

func (b *sdkBackend) Get(ctx context.Context, req *cdn.GetResourceRequest) (*cdn.Resource, error) {
	return b.cfg.SDK.CDN().Resource().Get(ctx, req)
}

func (b *sdkBackend) Update(ctx context.Context, req *cdn.UpdateResourceRequest) error {
	op, err := b.cfg.SDK.WrapOperation(b.cfg.SDK.CDN().Resource().Update(ctx, req))
	if err != nil {
		return err
	}
	return op.Wait(ctx)
}

func (b *sdkBackend) Delete(ctx context.Context, req *cdn.DeleteResourceRequest) error {
	op, err := b.cfg.SDK.WrapOperation(b.cfg.SDK.CDN().Resource().Delete(ctx, req))
	if err != nil {
		return err
	}
	return op.Wait(ctx)
}

// List paginates through ResourceIterator so callers receive the full
// flattened slice. Pulling pages here keeps the iterator type out of the
// backend interface, which would otherwise leak SDK-internal types into
// tests.
func (b *sdkBackend) List(ctx context.Context, req *cdn.ListResourcesRequest) ([]*cdn.Resource, error) {
	it := b.cfg.SDK.CDN().Resource().ResourceIterator(ctx, req)
	var out []*cdn.Resource
	for it.Next() {
		out = append(out, it.Value())
	}
	if err := it.Error(); err != nil {
		return nil, err
	}
	return out, nil
}

func (b *sdkBackend) OriginGroupList(ctx context.Context, req *cdn.ListOriginGroupsRequest) ([]*cdn.OriginGroup, error) {
	it := b.cfg.SDK.CDN().OriginGroup().OriginGroupIterator(ctx, req)
	var out []*cdn.OriginGroup
	for it.Next() {
		out = append(out, it.Value())
	}
	if err := it.Error(); err != nil {
		return nil, err
	}
	return out, nil
}

func (b *sdkBackend) ShieldingGet(ctx context.Context, req *cdn.GetShieldingDetailsRequest) (*cdn.ShieldingDetails, error) {
	return b.cfg.SDK.CDN().Shielding().Get(ctx, req)
}

func (b *sdkBackend) ShieldingActivate(ctx context.Context, req *cdn.ActivateShieldingRequest) error {
	op, err := b.cfg.SDK.WrapOperation(b.cfg.SDK.CDN().Shielding().Activate(ctx, req))
	if err != nil {
		return err
	}
	return op.Wait(ctx)
}

func (b *sdkBackend) ShieldingDeactivate(ctx context.Context, req *cdn.DeactivateShieldingRequest) error {
	op, err := b.cfg.SDK.WrapOperation(b.cfg.SDK.CDN().Shielding().Deactivate(ctx, req))
	if err != nil {
		return err
	}
	return op.Wait(ctx)
}
