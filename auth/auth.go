package auth

import (
	"context"
	"database/sql"
	"encoding/base64"
	"fmt"
	"net/http"
	"time"

	"github.com/immanuel-254/myauth-backend/auth/models"
)

var (
	LoginView = View{
		Route:   "/api/login",
		Handler: http.HandlerFunc(Login),
	}

	LogoutView = View{
		Route:   "/api/logout",
		Handler: http.HandlerFunc(Logout),
	}

	SignupView = View{
		Route:   "/api/signup",
		Handler: http.HandlerFunc(Signup),
	}

	ActivateEmailView = View{
		Route:   "/api/activate",
		Handler: http.HandlerFunc(ActivateEmail),
	}

	UserReadView = View{
		Route:       "/api/read",
		Middlewares: []func(http.Handler) http.Handler{RequireAdmin},
		Handler:     http.HandlerFunc(UserRead),
	}

	UserListView = View{
		Route:       "/api/list",
		Middlewares: []func(http.Handler) http.Handler{RequireAdmin},
		Handler:     http.HandlerFunc(UserList),
	}

	ChangeEmailRequestView = View{
		Route:       "/api/change-email-request",
		Middlewares: []func(http.Handler) http.Handler{RequireAuth},
		Handler:     http.HandlerFunc(ChangeEmailRequest),
	}

	ChangeEmailView = View{
		Route: "/api/change-email",
		// Middlewares: []func(http.Handler) http.Handler{auth.RequireAuth},
		Handler: http.HandlerFunc(ChangeEmail),
	}

	ChangePasswordRequestView = View{
		Route:       "/api/change-password-request",
		Middlewares: []func(http.Handler) http.Handler{RequireAuth},
		Handler:     http.HandlerFunc(ChangePasswordRequest),
	}

	ChangePasswordView = View{
		Route: "/api/change-password",
		// Middlewares: []func(http.Handler) http.Handler{auth.RequireAuth},
		Handler: http.HandlerFunc(ChangePassword),
	}

	ResetPasswordRequestView = View{
		Route:       "/api/reset-password-request",
		Middlewares: []func(http.Handler) http.Handler{RequireAuth},
		Handler:     http.HandlerFunc(ResetPasswordRequest),
	}

	ResetPasswordView = View{
		Route: "/api/reset-password",
		// Middlewares: []func(http.Handler) http.Handler{auth.RequireAuth},
		Handler: http.HandlerFunc(ResetPassword),
	}

	DeleteUserRequestView = View{
		Route:       "/api/delete-user-request",
		Middlewares: []func(http.Handler) http.Handler{RequireAuth},
		Handler:     http.HandlerFunc(DeleteUserRequest),
	}

	DeleteUserView = View{
		Route: "/api/delete-user",
		// Middlewares: []func(http.Handler) http.Handler{auth.RequireAuth},
		Handler: http.HandlerFunc(DeleteUser),
	}

	IsActiveChangeView = View{
		Route:       "/api/isactive",
		Middlewares: []func(http.Handler) http.Handler{RequireAdmin},
		Handler:     http.HandlerFunc(IsActiveChange),
	}

	IsStaffChangeView = View{
		Route:       "/api/isstaff",
		Middlewares: []func(http.Handler) http.Handler{RequireAdmin},
		Handler:     http.HandlerFunc(IsStaffChange),
	}

	SessionListView = View{
		Route:       "/api/session/list",
		Middlewares: []func(http.Handler) http.Handler{RequireAdmin},
		Handler:     http.HandlerFunc(SessionList),
	}

	LogListView = View{
		Route:       "/api/log/list",
		Middlewares: []func(http.Handler) http.Handler{RequireAdmin},
		Handler:     http.HandlerFunc(LogList),
	}
)

func AuthLogin(queries *models.Queries, ctx context.Context, data map[string]string) (string, int, error) {
	user, err := queries.UserLoginRead(ctx, data["email"])

	if err != nil {
		return "", http.StatusInternalServerError, fmt.Errorf("%s, (%s)", data["email"], err.Error())
	}

	err = queries.LogCreate(ctx, models.LogCreateParams{
		DbTable:   "user",
		Action:    "read",
		ObjectID:  user.ID,
		UserID:    0,
		CreatedAt: sql.NullTime{Time: time.Now(), Valid: true},
	})

	if err != nil {
		return "", http.StatusInternalServerError, err
	}

	check := CheckPasswordHash(data["password"], user.Password)

	if !check {
		return "", http.StatusBadRequest, fmt.Errorf("invalid credentials")
	}

	// create key
	key := base64.StdEncoding.EncodeToString(GenerateAESKey())

	// create session

	session, err := queries.SessionCreate(ctx, models.SessionCreateParams{
		Key:       key,
		UserID:    user.ID,
		CreatedAt: sql.NullTime{Time: time.Now(), Valid: true},
	})

	if err != nil {
		return "", http.StatusInternalServerError, err
	}

	err = queries.LogCreate(ctx, models.LogCreateParams{
		DbTable:   "session",
		Action:    "create",
		ObjectID:  session.ID,
		UserID:    session.UserID,
		CreatedAt: sql.NullTime{Time: time.Now(), Valid: true},
	})

	if err != nil {
		return "", http.StatusInternalServerError, err
	}

	return key, http.StatusOK, nil
}
