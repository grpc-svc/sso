package app

import (
	"io"
	"log/slog"
	grpcapp "sso/internal/app/grpc"
	"sso/internal/services/auth"
	"sso/internal/storage"
	"sso/internal/storage/sqlite"
	"time"
)

type App struct {
	GRPCSrv *grpcapp.App
	storage io.Closer
}

func New(log *slog.Logger,
	grpcPort int,
	storagePath string,
	tokenTTL time.Duration,
	operationTimeout time.Duration,
) *App {
	var storageInstance storage.Storage
	storageInstance, err := sqlite.New(storagePath)
	if err != nil {
		panic(err)
	}

	authService := auth.New(log, storageInstance, tokenTTL)

	grpcApp := grpcapp.New(log, authService, grpcPort, operationTimeout)

	return &App{
		GRPCSrv: grpcApp,
		storage: storageInstance,
	}
}

// Stop gracefully stops the application.
func (a *App) Stop() {
	a.GRPCSrv.Stop()

	if err := a.storage.Close(); err != nil {
		// Log error but don't panic during shutdown
		slog.Error("failed to close storage", slog.String("error", err.Error()))
	}
}
