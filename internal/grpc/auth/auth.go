package auth

import (
	"context"
	"errors"
	"sso/internal/services/auth"
	"time"

	ssov1 "github.com/grpc-svc/protos/gen/go/sso"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type serverAPI struct {
	ssov1.UnimplementedAuthServer
	auth             auth.Service
	operationTimeout time.Duration
}

func Register(gRPC *grpc.Server, authService auth.Service, operationTimeout time.Duration) {
	ssov1.RegisterAuthServer(gRPC, &serverAPI{
		auth:             authService,
		operationTimeout: operationTimeout,
	})
}

func (s *serverAPI) Login(
	ctx context.Context,
	req *ssov1.LoginRequest,
) (*ssov1.LoginResponse, error) {
	if req.GetEmail() == "" {
		return nil, status.Error(codes.InvalidArgument, "email is required")
	}

	if req.GetPassword() == "" {
		return nil, status.Error(codes.InvalidArgument, "password is required")
	}

	if req.GetAppId() == 0 {
		return nil, status.Error(codes.InvalidArgument, "app_id is required")
	}

	// Create context with timeout for database operations
	opCtx, cancel := context.WithTimeout(ctx, s.operationTimeout)
	defer cancel()

	token, err := s.auth.Login(opCtx, req.GetEmail(), req.GetPassword(), int(req.GetAppId()))
	if err != nil {
		if errors.Is(err, auth.ErrInvalidCredentials) {
			return nil, status.Error(codes.InvalidArgument, "invalid credentials")
		}
		if errors.Is(err, auth.ErrInvalidAppID) {
			return nil, status.Error(codes.InvalidArgument, "invalid app id")
		}
		if errors.Is(err, context.DeadlineExceeded) {
			return nil, status.Error(codes.DeadlineExceeded, "operation timeout")
		}
		return nil, status.Error(codes.Internal, "failed to login")
	}

	return &ssov1.LoginResponse{
		Token: token,
	}, nil
}

func (s *serverAPI) Register(
	ctx context.Context,
	req *ssov1.RegisterRequest,
) (*ssov1.RegisterResponse, error) {
	if req.GetEmail() == "" {
		return nil, status.Error(codes.InvalidArgument, "email is required")
	}

	if req.GetPassword() == "" {
		return nil, status.Error(codes.InvalidArgument, "password is required")
	}

	// Create context with timeout for database operations
	opCtx, cancel := context.WithTimeout(ctx, s.operationTimeout)
	defer cancel()

	userID, err := s.auth.Register(opCtx, req.GetEmail(), req.GetPassword())
	if err != nil {
		if errors.Is(err, auth.ErrUserExists) {
			return nil, status.Error(codes.AlreadyExists, "user already exists")
		}
		if errors.Is(err, context.DeadlineExceeded) {
			return nil, status.Error(codes.DeadlineExceeded, "operation timeout")
		}
		return nil, status.Error(codes.Internal, "failed to register user")
	}

	return &ssov1.RegisterResponse{
		UserId: userID,
	}, nil
}

func (s *serverAPI) IsAdmin(
	ctx context.Context,
	req *ssov1.IsAdminRequest,
) (*ssov1.IsAdminResponse, error) {
	if req.GetUserId() == 0 {
		return nil, status.Error(codes.InvalidArgument, "user_id is required")
	}

	// Create context with timeout for database operations
	opCtx, cancel := context.WithTimeout(ctx, s.operationTimeout)
	defer cancel()

	isAdmin, err := s.auth.IsAdmin(opCtx, req.GetUserId())
	if err != nil {
		if errors.Is(err, auth.ErrUserNotFound) {
			return nil, status.Error(codes.NotFound, "user not found")
		}
		if errors.Is(err, context.DeadlineExceeded) {
			return nil, status.Error(codes.DeadlineExceeded, "operation timeout")
		}
		return nil, status.Error(codes.Internal, "failed to check admin status")
	}
	return &ssov1.IsAdminResponse{
		IsAdmin: isAdmin,
	}, nil
}
