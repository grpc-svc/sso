package main

import (
	"log/slog"
	"os"
	"os/signal"
	"sso/internal/app"
	"sso/internal/config"
	"sso/internal/lib/logger/slogcute"
	"sso/internal/storage/sqlite"
	"syscall"
)

const (
	envLocal = "local"
	envDev   = "dev"
	envProd  = "prod"
)

func main() {
	cfg := config.MustLoad()

	log := setupLogger(cfg.Env)

	log.Info("Application started", slog.String("env", cfg.Env))

	storage, err := sqlite.New(cfg.StoragePath)
	if err != nil {
		log.Error("failed to init storage", slog.String("error", err.Error()))
		os.Exit(1)
	}
	log.Info("storage initialized", slog.String("path", cfg.StoragePath))

	application := app.New(
		log,
		storage,
		storage,
		cfg.GRPC.Port,
		cfg.TokenTTL,
		cfg.GRPC.Timeout,
	)

	go application.GRPCSrv.MustRun()

	// Graceful shutdown
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGTERM, syscall.SIGINT)

	<-stop

	application.Stop()

	if err = storage.Close(); err != nil {
		log.Error("failed to close storage", slog.String("error", err.Error()))
	}

	log.Info("Gracefully stopped")
}

func setupLogger(env string) *slog.Logger {
	switch env {
	case envLocal:
		return setupCuteSlog()
	case envDev:
		return slog.New(
			slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}),
		)
	case envProd:
		return slog.New(
			slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}),
		)
	default:
		panic("unknown environment: " + env)
	}
}

func setupCuteSlog() *slog.Logger {
	opts := slogcute.CuteHandlerOptions{
		SlogOptions: &slog.HandlerOptions{
			Level: slog.LevelDebug,
		},
	}

	handler := opts.NewCuteHandler(os.Stdout)

	return slog.New(handler)
}
