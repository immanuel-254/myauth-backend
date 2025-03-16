package cmd

import (
	"fmt"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/immanuel-254/myauth-backend/auth"
)

var AuthViews = []auth.View{
	auth.LoginView,
	auth.LogoutView,
	auth.SignupView,
	auth.ActivateEmailView,
	auth.UserReadView,
	auth.UserListView,
	auth.ChangeEmailRequestView,
	auth.ChangeEmailView,
	auth.ChangePasswordRequestView,
	auth.ChangePasswordView,
	auth.ResetPasswordRequestView,
	auth.ResetPasswordView,
	auth.DeleteUserRequestView,
	auth.DeleteUserView,
	auth.IsActiveChangeView,
	auth.IsStaffChangeView,

	auth.SessionListView,

	auth.LogListView,
}

func Server() {
	mux := http.NewServeMux()

	auth.Routes(mux, AuthViews)

	server := &http.Server{
		Addr: fmt.Sprintf(":%s", os.Getenv("PORT")), // Custom port
		//Handler:      internal.LoggingMiddleware(internal.Cors(internal.New(internal.ConfigDefault)(mux))), // Attach the mux as the handler
		Handler:      auth.LoggingMiddleware(mux),
		ReadTimeout:  10 * time.Second, // Set read timeout
		WriteTimeout: 10 * time.Second, // Set write timeout
		IdleTimeout:  30 * time.Second, // Set idle timeout
	}

	if err := server.ListenAndServe(); err != nil {
		log.Println("Error starting server:", err)
	}
}
