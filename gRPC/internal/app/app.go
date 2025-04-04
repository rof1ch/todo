package app

import (
	"log/slog"
	"time"
	grpcapp "todo-grpc/internal/app/grpc"
	"todo-grpc/internal/services/auth"
	"todo-grpc/internal/storage/sqlite"
)

type App struct {
	GRPCSrv *grpcapp.App
}

func New(
	log *slog.Logger,
	grpcPort int,
	storagePath string,
	tokenTTL time.Duration,
) *App {
	storage, err := sqlite.New(storagePath)
	if err != nil {
		panic(err)
	}

	aithService := auth.New(log, storage, storage, storage, tokenTTL)

	grpcApp := grpcapp.New(log, aithService, grpcPort)
	return &App{
		GRPCSrv: grpcApp,
	}
}
