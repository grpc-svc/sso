package app

import (
	"log/slog"
	grpcapp "sso/internal/app/grpc"
	"sso/internal/lib/jwt"
	"sso/internal/services/auth"
	"time"
)

type App struct {
	GRPCSrv *grpcapp.App
}

func New(log *slog.Logger,
	userProvider auth.UserProvider,
	appProvider auth.AppProvider,
	grpcPort int,
	tokenTTL time.Duration,
	operationTimeout time.Duration,
) *App {
	jwtProvider := jwt.New(log)

	authService := auth.New(log, userProvider, appProvider, jwtProvider, tokenTTL)

	grpcApp := grpcapp.New(log, authService, grpcPort, operationTimeout)

	return &App{
		GRPCSrv: grpcApp,
	}
}

// Stop gracefully stops the application.
func (a *App) Stop() {
	a.GRPCSrv.Stop()
}
