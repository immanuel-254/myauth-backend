package auth

import (
	"context"
	"log"
	"net/http"
	"time"

	"github.com/immanuel-254/myauth-backend/auth/models"
	"github.com/immanuel-254/myauth-backend/database"
)

type currentUser string

const Current_user currentUser = "Current_user"

func ReadUser(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		queries := models.New(database.DB)
		ctx := r.Context()

		token := r.Header.Get("auth") // 1. Check for token in Authorization header
		if token == "" {              // 2. If no token found in either place, return error
			ctx = context.WithValue(ctx, Current_user, models.AuthUserReadRow{ID: 0}) // Store user in context
			r = r.WithContext(ctx)
			next.ServeHTTP(w, r)
			return
		}

		session, err := queries.SessionRead(ctx, token)
		err = SqlErrorHandler(err, w, r)
		if err != nil {
			return
		}
		if session.CreatedAt.Time.AddDate(0, 0, 30).Unix() < time.Now().Unix() {
			SendData(http.StatusBadRequest, [][]string{{"error"}, {"session has expired"}}, w, r)
			return
		}

		user, err := queries.AuthUserRead(ctx, session.UserID)
		err = SqlErrorHandler(err, w, r)
		if err != nil {
			return
		}

		if !user.Isactive.Bool {
			SendData(http.StatusForbidden, [][]string{{"error"}, {"inactive user"}}, w, r)
			return
		}

		ctx = context.WithValue(ctx, Current_user, user) // Store user in context
		r = r.WithContext(ctx)
		next.ServeHTTP(w, r)
	})
}

func RequireAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		queries := models.New(database.DB)
		ctx := r.Context()

		token := r.Header.Get("auth") // 1. Check for token in Authorization header
		if token == "" {              // 2. If no token found in either place, return error
			SendData(http.StatusForbidden, [][]string{{"error"}, {"missing auth token"}}, w, r)
			return
		}

		session, err := queries.SessionRead(ctx, token)
		err = SqlErrorHandler(err, w, r)
		if err != nil {
			return
		}
		if session.CreatedAt.Time.AddDate(0, 0, 30).Unix() < time.Now().Unix() {
			SendData(http.StatusBadRequest, [][]string{{"error"}, {"session has expired"}}, w, r)
			return
		}

		user, err := queries.AuthUserRead(ctx, session.UserID)
		err = SqlErrorHandler(err, w, r)
		if err != nil {
			return
		}
		if !user.Isactive.Bool {
			SendData(http.StatusForbidden, [][]string{{"error"}, {"inactive user"}}, w, r)
			return
		}

		ctx = context.WithValue(ctx, Current_user, user) // Store user in context
		r = r.WithContext(ctx)
		next.ServeHTTP(w, r)
	})
}

func RequireStaff(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		queries := models.New(database.DB)
		ctx := r.Context()

		token := r.Header.Get("auth") // 1. Check for token in Authorization header
		if token == "" {              // 2. If no token found in either place, return error
			SendData(http.StatusForbidden, [][]string{{"error"}, {"missing auth token"}}, w, r)
			return
		}

		session, err := queries.SessionRead(ctx, r.Header.Get("auth"))
		err = SqlErrorHandler(err, w, r)
		if err != nil {
			return
		}
		if session.CreatedAt.Time.AddDate(0, 0, 30).Unix() < time.Now().Unix() {
			SendData(http.StatusBadRequest, [][]string{{"error"}, {"session has expired"}}, w, r)
			return
		}

		user, err := queries.AuthUserRead(ctx, session.UserID)
		err = SqlErrorHandler(err, w, r)
		if err != nil {
			return
		}

		if !user.Isactive.Bool {
			SendData(http.StatusForbidden, [][]string{{"error"}, {"invalid user"}}, w, r)
			return
		}
		if !user.Isstaff.Bool && !user.Isadmin.Bool {
			SendData(http.StatusForbidden, [][]string{{"error"}, {"invalid user"}}, w, r)
			return
		}

		ctx = context.WithValue(ctx, Current_user, user) // Store user in context
		r = r.WithContext(ctx)
		next.ServeHTTP(w, r)
	})
}

func RequireAdmin(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		queries := models.New(database.DB)
		ctx := r.Context()

		token := r.Header.Get("auth") // 1. Check for token in Authorization header
		if token == "" {              // 2. If no token found in either place, return error
			SendData(http.StatusForbidden, [][]string{{"error"}, {"missing auth token"}}, w, r)
			return
		}

		session, err := queries.SessionRead(ctx, token)
		err = SqlErrorHandler(err, w, r)
		if err != nil {
			return
		}
		if session.CreatedAt.Time.AddDate(0, 0, 30).Unix() < time.Now().Unix() {
			SendData(http.StatusBadRequest, [][]string{{"error"}, {"session has expired"}}, w, r)
			return
		}

		user, err := queries.AuthUserRead(ctx, session.UserID)
		err = SqlErrorHandler(err, w, r)
		if err != nil {
			return
		}

		if !user.Isactive.Bool {
			SendData(http.StatusForbidden, [][]string{{"error"}, {"invalid user"}}, w, r)
			return
		}
		if !user.Isadmin.Bool {
			SendData(http.StatusForbidden, [][]string{{"error"}, {"invalid user"}}, w, r)
			return
		}

		ctx = context.WithValue(ctx, Current_user, user) // Store user in context
		r = r.WithContext(ctx)
		next.ServeHTTP(w, r)
	})
}

func LoggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		// Custom response writer to capture status code
		lrw := &loggingResponseWriter{ResponseWriter: w, statusCode: http.StatusOK}
		next.ServeHTTP(lrw, r)
		// Log details
		log.Printf("%s %s %d %s", r.Method, r.URL.Path, lrw.statusCode, time.Since(start))
	})
}

// loggingResponseWriter captures the response status code
type loggingResponseWriter struct {
	http.ResponseWriter
	statusCode int
}

// Override WriteHeader to capture status code
func (lrw *loggingResponseWriter) WriteHeader(code int) {
	lrw.statusCode = code
	lrw.ResponseWriter.WriteHeader(code)
}
