package suite

import (
	"context"
	"net"
	"sso/internal/config"
	"strconv"
	"testing"

	ssov1 "github.com/grpc-svc/protos/gen/go/sso"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

const grpcHost = "localhost"

type Suite struct {
	*testing.T
	Cfg        *config.Config
	AuthClient ssov1.AuthClient
}

func New(t *testing.T) (context.Context, *Suite) {
	t.Helper()
	t.Parallel()

	cfg := config.MustLoadByPath("../config/local.yaml")

	ctx, cancelCtx := context.WithTimeout(context.Background(), cfg.GRPC.Timeout)

	cc, err := grpc.NewClient(
		grpcAddress(cfg),
		grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatalf("failed to create grpc client: %v", err)
	}

	t.Cleanup(func() {
		t.Helper()
		cancelCtx()
		if err := cc.Close(); err != nil {
			t.Errorf("failed to close grpc connection: %v", err)
		}
	})

	return ctx, &Suite{
		T:          t,
		Cfg:        cfg,
		AuthClient: ssov1.NewAuthClient(cc),
	}
}

func grpcAddress(cfg *config.Config) string {
	return net.JoinHostPort(grpcHost, strconv.Itoa(cfg.GRPC.Port))
}
