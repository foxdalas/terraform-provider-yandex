package cdn_raw_log

import (
	"context"

	"github.com/yandex-cloud/go-genproto/yandex/cloud/cdn/v1"
	provider_config "github.com/yandex-cloud/terraform-provider-yandex/yandex-framework/provider/config"
)

// rawLogsBackend isolates the Yandex SDK calls used by the cdn_raw_log resource.
// Activate/Update/Deactivate include operation polling so the resource code does not
// have to deal with the SDK's operation-wrapping machinery; this also makes the
// resource straightforward to unit-test against a fake backend.
type rawLogsBackend interface {
	Activate(ctx context.Context, req *cdn.ActivateRawLogsRequest) error
	Deactivate(ctx context.Context, req *cdn.DeactivateRawLogsRequest) error
	Update(ctx context.Context, req *cdn.UpdateRawLogsRequest) error
	Get(ctx context.Context, req *cdn.GetRawLogsRequest) (*cdn.GetRawLogsResponse, error)
}

type sdkBackend struct {
	cfg *provider_config.Config
}

func newSDKBackend(cfg *provider_config.Config) *sdkBackend {
	return &sdkBackend{cfg: cfg}
}

func (b *sdkBackend) Activate(ctx context.Context, req *cdn.ActivateRawLogsRequest) error {
	op, err := b.cfg.SDK.WrapOperation(b.cfg.SDK.CDN().RawLogs().Activate(ctx, req))
	if err != nil {
		return err
	}
	return op.Wait(ctx)
}

func (b *sdkBackend) Deactivate(ctx context.Context, req *cdn.DeactivateRawLogsRequest) error {
	op, err := b.cfg.SDK.WrapOperation(b.cfg.SDK.CDN().RawLogs().Deactivate(ctx, req))
	if err != nil {
		return err
	}
	return op.Wait(ctx)
}

func (b *sdkBackend) Update(ctx context.Context, req *cdn.UpdateRawLogsRequest) error {
	op, err := b.cfg.SDK.WrapOperation(b.cfg.SDK.CDN().RawLogs().Update(ctx, req))
	if err != nil {
		return err
	}
	return op.Wait(ctx)
}

func (b *sdkBackend) Get(ctx context.Context, req *cdn.GetRawLogsRequest) (*cdn.GetRawLogsResponse, error) {
	return b.cfg.SDK.CDN().RawLogs().Get(ctx, req)
}
