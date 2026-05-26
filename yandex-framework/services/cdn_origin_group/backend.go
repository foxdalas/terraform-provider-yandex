package cdn_origin_group

import (
	"context"
	"fmt"

	"github.com/yandex-cloud/go-genproto/yandex/cloud/cdn/v1"
	provider_config "github.com/yandex-cloud/terraform-provider-yandex/yandex-framework/provider/config"
)

// originGroupBackend isolates the Yandex SDK calls used by the cdn_origin_group
// resource and data source. Mutation methods own the operation polling so the
// resource code does not deal with the SDK's WrapOperation machinery; Create
// also unpacks the metadata that carries the freshly-allocated group ID.
//
// ListAll loads every origin group in the folder into memory — the SDK exposes
// a page-aware iterator, but callers want a slice for searching by name.
type originGroupBackend interface {
	Create(ctx context.Context, req *cdn.CreateOriginGroupRequest) (id int64, err error)
	Update(ctx context.Context, req *cdn.UpdateOriginGroupRequest) error
	Delete(ctx context.Context, req *cdn.DeleteOriginGroupRequest) error
	Get(ctx context.Context, req *cdn.GetOriginGroupRequest) (*cdn.OriginGroup, error)
	ListAll(ctx context.Context, req *cdn.ListOriginGroupsRequest) ([]*cdn.OriginGroup, error)
}

type sdkBackend struct {
	cfg *provider_config.Config
}

func newSDKBackend(cfg *provider_config.Config) *sdkBackend {
	return &sdkBackend{cfg: cfg}
}

func (b *sdkBackend) Create(ctx context.Context, req *cdn.CreateOriginGroupRequest) (int64, error) {
	op, err := b.cfg.SDK.WrapOperation(b.cfg.SDK.CDN().OriginGroup().Create(ctx, req))
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
	meta, ok := md.(*cdn.CreateOriginGroupMetadata)
	if !ok {
		return 0, fmt.Errorf("unexpected operation metadata type: %T", md)
	}
	return meta.OriginGroupId, nil
}

func (b *sdkBackend) Update(ctx context.Context, req *cdn.UpdateOriginGroupRequest) error {
	op, err := b.cfg.SDK.WrapOperation(b.cfg.SDK.CDN().OriginGroup().Update(ctx, req))
	if err != nil {
		return err
	}
	return op.Wait(ctx)
}

func (b *sdkBackend) Delete(ctx context.Context, req *cdn.DeleteOriginGroupRequest) error {
	op, err := b.cfg.SDK.WrapOperation(b.cfg.SDK.CDN().OriginGroup().Delete(ctx, req))
	if err != nil {
		return err
	}
	return op.Wait(ctx)
}

func (b *sdkBackend) Get(ctx context.Context, req *cdn.GetOriginGroupRequest) (*cdn.OriginGroup, error) {
	return b.cfg.SDK.CDN().OriginGroup().Get(ctx, req)
}

func (b *sdkBackend) ListAll(ctx context.Context, req *cdn.ListOriginGroupsRequest) ([]*cdn.OriginGroup, error) {
	return b.cfg.SDK.CDN().OriginGroup().OriginGroupIterator(ctx, req).TakeAll()
}
