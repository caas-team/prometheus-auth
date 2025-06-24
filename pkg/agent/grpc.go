package agent

import (
	"context"

	grpcproxy "github.com/mwitkow/grpc-proxy/proxy"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func (a *agent) grpcBackend() grpc.StreamHandler {
	return grpcproxy.TransparentHandler(func(ctx context.Context, _ string) (context.Context, *grpc.ClientConn, error) {
		con, err := grpc.NewClient(a.cfg.proxyURL.String())
		if err != nil {
			return ctx, nil, status.Errorf(codes.Unavailable, "Unavailable endpoint")
		}
		return ctx, con, nil
	})
}
