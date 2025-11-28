package main

import (
	"bufio"
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"encoding/csv"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	_ "github.com/joho/godotenv/autoload"

	"github.com/a-h/templ"
	db_data "github.com/immanuel-254/myauth-backend/data"
	"github.com/pressly/goose/v3"
	"github.com/resend/resend-go/v2"
	"golang.org/x/crypto/bcrypt"
	"golang.org/x/term"
	_ "modernc.org/sqlite"
)

var DB *sql.DB

/* Models */
func GenerateAESKey() []byte {
	key := make([]byte, 32) // AES-256 requires a 32-byte key
	_, err := rand.Read(key)
	if err != nil {
		panic(err.Error())
	}
	return key
}

type TokenStatus struct {
	Token     string
	Used      bool
	ExpiresAt time.Time
	sub       uint
}

var (
	tokenStore = make(map[string]*TokenStatus) // Token storage
	mu         sync.Mutex                      // To protect the map from concurrent access
)

// GenerateOneTimeToken generates a random token and stores its metadata
func GenerateOneTimeToken(length int, sub uint) (string, error) {
	// Create a slice to store random bytes
	token := make([]byte, length)
	_, err := rand.Read(token) // Fill the slice with random data
	if err != nil {
		return "", err
	}

	// Encode the random bytes to base64
	encodedToken := base64.URLEncoding.EncodeToString(token)

	// Store the token with metadata (used = false, expires in ttl)
	mu.Lock()
	defer mu.Unlock()

	tokenStore[encodedToken] = &TokenStatus{
		Token:     encodedToken,
		Used:      false,
		ExpiresAt: time.Now().Add(time.Minute * 15),
		sub:       sub,
	}

	return encodedToken, nil
}

// VerifyToken checks if the token is valid and not used yet
func VerifyToken(token string) (uint, error) {
	mu.Lock()
	defer mu.Unlock()

	// Check if the token exists
	tokenData, exists := tokenStore[token]
	if !exists {
		return 0, errors.New("token does not exist")
	}

	// Check if the token is expired
	if time.Now().After(tokenData.ExpiresAt) {
		return 0, errors.New("token has expired")
	}

	// Check if the token has already been used
	if tokenData.Used {
		return 0, errors.New("token has already been used")
	}

	// Mark the token as used
	tokenData.Used = true

	return tokenData.sub, nil
}

func HashPassword(password string) (string, error) {
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return "", err
	}
	return string(hash), err
}

func CheckPasswordHash(password string, hash string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	return err == nil
}

/* Views */
type View struct {
	Route       string
	Middlewares []func(http.Handler) http.Handler
	Handler     http.Handler
}

// Middleware chaining
func chainMiddlewares(handler http.Handler, middlewares []func(http.Handler) http.Handler) http.Handler {
	if len(middlewares) != 0 {
		for i := 0; i < len(middlewares); i++ { // Apply middlewares in normal order
			handler = middlewares[i](handler)
		}
		return handler
	}
	return handler
}

// Routes function
func Routes(mux *http.ServeMux, views []View) {
	for _, view := range views {
		handlerWithMiddlewares := chainMiddlewares(view.Handler, view.Middlewares)
		mux.HandleFunc(view.Route, func(w http.ResponseWriter, r *http.Request) {
			handlerWithMiddlewares.ServeHTTP(w, r)
		})

	}
}

func GetData(data *map[string]string, w http.ResponseWriter, r *http.Request) error {
	data_, err := csv.NewReader(r.Body).ReadAll()

	if err != nil {
		SendData(http.StatusInternalServerError, [][]string{{"error"}, {strings.ToLower(err.Error())}}, w, r)
		return err
	}

	if data_ == nil { // Check if the decoded data is empty
		SendData(http.StatusBadRequest, [][]string{{"error"}, {strings.ToLower("no data provided")}}, w, r)
		return errors.New("no data provided")
	}

	authdata := make(map[string]string)
	headers := data_[0]
	values := data_[1]

	for i, header := range headers {
		// Ensure index is valid before accessing values
		if i < len(values) {
			authdata[header] = values[i]
		}
	}

	*data = authdata

	return nil
}

func SendData(status int, data [][]string, w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(status)
	w.Header().Set("Content-Type", "text/csv")
	writer := csv.NewWriter(w)
	_ = writer.WriteAll(data)
	writer.Flush()
}

func SendEmail(email, subject, link string, template func(route string) string, w http.ResponseWriter, r *http.Request) error {
	client := resend.NewClient(os.Getenv("RESENDAPIKEY"))

	params := &resend.SendEmailRequest{
		From:    os.Getenv("RESENDEMAIL"),
		To:      []string{email},
		Html:    template(link),
		Subject: subject,
	}

	_, err := client.Emails.Send(params)
	if err != nil {
		SendData(http.StatusInternalServerError, [][]string{{"error"}, {strings.ToLower(err.Error())}}, w, r)
		return err
	}

	return err
}

func Logging(queries *db_data.Queries, ctx context.Context, dbtable, action string, objectId, userId int64, w http.ResponseWriter, r *http.Request) error {
	err := queries.LogCreate(ctx, db_data.LogCreateParams{
		DbTable:   dbtable,
		Action:    action,
		ObjectID:  objectId,
		UserID:    userId,
		CreatedAt: sql.NullTime{Time: time.Now(), Valid: true},
	})
	err = SqlErrorHandler(err, w, r)
	if err != nil {
		return err
	}

	return nil
}

func AuthLogin(queries *db_data.Queries, ctx context.Context, data map[string]string) (string, int, error) {
	user, err := queries.UserLoginRead(ctx, data["email"])
	if err != nil {
		return "", http.StatusInternalServerError, err
	}

	err = queries.LogCreate(ctx, db_data.LogCreateParams{
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
	session, err := queries.SessionCreate(ctx, db_data.SessionCreateParams{
		Key:       key,
		UserID:    user.ID,
		CreatedAt: sql.NullTime{Time: time.Now(), Valid: true},
	})
	if err != nil {
		return "", http.StatusInternalServerError, err
	}

	err = queries.LogCreate(ctx, db_data.LogCreateParams{
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

func AuthLogout(queries *db_data.Queries, ctx context.Context, w http.ResponseWriter, r *http.Request) error {
	session, err := queries.SessionRead(ctx, r.Header.Get("auth"))
	err = SqlErrorHandler(err, w, r)
	if err != nil {
		return err
	}

	err = queries.SessionDelete(ctx, r.Header.Get("auth")) // delete session
	err = SqlErrorHandler(err, w, r)
	if err != nil {
		return err
	}

	err = queries.LogCreate(ctx, db_data.LogCreateParams{
		DbTable:   "session",
		Action:    "delete",
		ObjectID:  session.ID,
		UserID:    session.UserID,
		CreatedAt: sql.NullTime{Time: time.Now(), Valid: true},
	})
	err = SqlErrorHandler(err, w, r)
	if err != nil {
		return err
	}

	return nil
}

func InternalServerErrorHandler(err error, w http.ResponseWriter, r *http.Request) error {
	if err != nil {
		SendData(http.StatusInternalServerError, [][]string{{"error"}, {err.Error()}}, w, r)
		return err
	}

	return nil
}

func SqlErrorHandler(err error, w http.ResponseWriter, r *http.Request) error {
	if err != nil {
		switch err {
		case sql.ErrNoRows:
			SendData(http.StatusNoContent, [][]string{{"error"}, {"no data"}}, w, r)
			return err
		default:
			SendData(http.StatusInternalServerError, [][]string{{"error"}, {strings.ToLower(err.Error())}}, w, r)
			return err
		}
	}
	return nil
}

func Signup(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		SendData(http.StatusMethodNotAllowed, [][]string{{"error"}, {"method not allowed"}}, w, r)
		return
	}

	queries := db_data.New(DB)
	ctx := r.Context()

	data := make(map[string]string)
	err := GetData(&data, w, r) // get data
	if err != nil {
		return
	}

	if data["password"] != data["confirm-password"] { // check if password match
		SendData(http.StatusBadRequest, [][]string{{"error"}, {"invalid password"}}, w, r)
		return
	}

	hash, err := HashPassword(data["password"]) // hash password
	err = InternalServerErrorHandler(err, w, r)
	if err != nil {
		return
	}

	user, err := queries.UserCreate(ctx, db_data.UserCreateParams{ // create user
		Email:     data["email"],
		Password:  hash,
		Isactive:  sql.NullBool{Bool: false, Valid: true},
		Isstaff:   sql.NullBool{Bool: false, Valid: true},
		Isadmin:   sql.NullBool{Bool: false, Valid: true},
		CreatedAt: sql.NullTime{Time: time.Now(), Valid: true},
	})
	err = SqlErrorHandler(err, w, r)
	if err != nil {
		return
	}

	err = Logging(queries, ctx, "user", "create", user.ID, 0, w, r)
	if err != nil {
		return
	}

	one_time, err := GenerateOneTimeToken(32, uint(user.ID))
	err = InternalServerErrorHandler(err, w, r)
	if err != nil {
		return
	}

	err = SendEmail(user.Email, "Activate Your Email", fmt.Sprintf("%s/activate/?token=%s", os.Getenv("DOMAIN"), one_time), EmailVerificationTemplate, w, r) // send email
	if err != nil {
		return
	}

	resp := [][]string{{"message"}, {"signup successful"}}
	SendData(http.StatusOK, resp, w, r)

}

func ActivateEmail(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		SendData(http.StatusMethodNotAllowed, [][]string{{"error"}, {"method not allowed"}}, w, r)
		return
	}

	queryParams := r.URL.Query()
	token := queryParams.Get("token")
	user_id, err := VerifyToken(token) // verify token
	if err != nil {
		SendData(http.StatusBadRequest, [][]string{{"error"}, {"invalid auth token"}}, w, r)
		return
	}

	queries := db_data.New(DB)
	ctx := r.Context()

	user, err := queries.UserUpdateIsActive(ctx, db_data.UserUpdateIsActiveParams{ // activate user
		ID:        int64(user_id),
		Isactive:  sql.NullBool{Bool: true, Valid: true},
		UpdatedAt: sql.NullTime{Time: time.Now(), Valid: true},
	})
	err = SqlErrorHandler(err, w, r)
	if err != nil {
		return
	}

	err = Logging(queries, ctx, "user", "update", user.ID, int64(user_id), w, r)
	if err != nil {
		return
	}

	resp := [][]string{{"message"}, {"email has been verified"}}
	SendData(http.StatusOK, resp, w, r)
}

func UserRead(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		SendData(http.StatusMethodNotAllowed, [][]string{{"error"}, {"method not allowed"}}, w, r)
		return
	}

	queryParams := r.URL.Query()
	user_id, err := strconv.ParseInt(queryParams.Get("user"), 10, 64)
	err = InternalServerErrorHandler(err, w, r)
	if err != nil {
		return
	}

	if user_id == 0 {
		SendData(http.StatusNotFound, [][]string{{"error"}, {"user not found"}}, w, r)
		return
	}

	queries := db_data.New(DB)
	ctx := r.Context()
	auth := ctx.Value(Current_user)
	if auth == nil {
		SendData(http.StatusInternalServerError, [][]string{{"error"}, {"there is no current user"}}, w, r)
		return
	}

	authUser := auth.(db_data.AuthUserReadRow)

	user, err := queries.UserRead(ctx, user_id)
	err = SqlErrorHandler(err, w, r)
	if err != nil {
		return
	}

	userdata := [][]string{{"id", "email", "created_at", "updated_at"}, {
		strconv.FormatInt(user.ID, 10),
		user.Email,
		user.CreatedAt.Time.String(),
		user.UpdatedAt.Time.String(),
	}}

	err = Logging(queries, ctx, "user", "read", user.ID, authUser.ID, w, r)
	if err != nil {
		return
	}

	SendData(http.StatusOK, userdata, w, r)
}

func AuthUserRead(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		SendData(http.StatusMethodNotAllowed, [][]string{{"error"}, {"method not allowed"}}, w, r)
		return
	}

	ctx := r.Context()
	auth := ctx.Value(Current_user)
	if auth == nil {
		SendData(http.StatusNotFound, [][]string{{"error"}, {"there is no current user"}}, w, r)
		return
	}

	user := auth.(db_data.AuthUserReadRow)
	userdata := [][]string{{"id", "email", "is_active", "is_staff", "is_admin", "created_at", "updated_at"}, {
		strconv.FormatInt(user.ID, 10),
		user.Email,
		strconv.FormatBool(user.Isactive.Bool),
		strconv.FormatBool(user.Isstaff.Bool),
		strconv.FormatBool(user.Isadmin.Bool),
		user.CreatedAt.Time.String(),
		user.UpdatedAt.Time.String(),
	}}

	SendData(http.StatusOK, userdata, w, r)
}

func UserList(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		SendData(http.StatusMethodNotAllowed, [][]string{{"error"}, {"method not allowed"}}, w, r)
		return
	}

	queries := db_data.New(DB)
	ctx := r.Context()
	auth := ctx.Value(Current_user)
	if auth == nil {
		SendData(http.StatusInternalServerError, [][]string{{"error"}, {"there is no current user"}}, w, r)
		return
	}

	authUser := auth.(db_data.AuthUserReadRow)

	users, err := queries.UserList(ctx)
	err = SqlErrorHandler(err, w, r)
	if err != nil {
		return
	}

	var user_s [][]string
	header := []string{"id", "email", "is_active", "is_staff", "is_admin", "created_at", "updated_at"}

	user_s = append(user_s, header)
	for _, user := range users {
		row := []string{
			strconv.FormatInt(user.ID, 10),
			user.Email,
			strconv.FormatBool(user.Isactive.Bool),
			strconv.FormatBool(user.Isstaff.Bool),
			strconv.FormatBool(user.Isadmin.Bool),
			user.CreatedAt.Time.String(),
			user.UpdatedAt.Time.String(),
		}
		user_s = append(user_s, row)
	}

	err = Logging(queries, ctx, "user", "list", 0, authUser.ID, w, r)
	if err != nil {
		return
	}

	SendData(http.StatusOK, user_s, w, r)
}

func ChangeEmailRequest(w http.ResponseWriter, r *http.Request) { // Require auth
	if r.Method != http.MethodPost {
		SendData(http.StatusMethodNotAllowed, [][]string{{"error"}, {"method not allowed"}}, w, r)
		return
	}

	data := make(map[string]string)
	err := GetData(&data, w, r) // get data
	if err != nil {
		return
	}

	ctx := r.Context()
	auth := ctx.Value(Current_user)
	if auth == nil {
		SendData(http.StatusInternalServerError, [][]string{{"error"}, {"there is no current user"}}, w, r)
		return
	}

	authUser := auth.(db_data.AuthUserReadRow)

	if data["email"] != authUser.Email {
		SendData(http.StatusBadRequest, [][]string{{"error"}, {"invalid email"}}, w, r)
		return
	}

	queries := db_data.New(DB)

	one_time, err := GenerateOneTimeToken(32, uint(authUser.ID))
	err = InternalServerErrorHandler(err, w, r)
	if err != nil {
		return
	}

	err = SendEmail(data["email"], "Change Your Email", fmt.Sprintf("%s/change-email/?token=%s", os.Getenv("DOMAIN"), one_time), ChangeEmailVerificationTemplate, w, r) // send email
	if err != nil {
		return
	}

	err = AuthLogout(queries, ctx, w, r)
	if err != nil {
		return
	}

	SendData(http.StatusOK, [][]string{{"message"}, {"email sent"}}, w, r)
}

func ChangeEmail(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPut {
		SendData(http.StatusMethodNotAllowed, [][]string{{"error"}, {"method not allowed"}}, w, r)
		return
	}

	queryParams := r.URL.Query()
	token := queryParams.Get("token")
	user_id, err := VerifyToken(token) // verify token
	if err != nil {
		SendData(http.StatusBadRequest, [][]string{{"error"}, {"invalid auth token"}}, w, r)
		return
	}

	queries := db_data.New(DB)
	ctx := r.Context()

	data := make(map[string]string)
	err = GetData(&data, w, r) // get data
	if err != nil {
		return
	}

	usercheck, _ := queries.UserLoginRead(ctx, data["email"])
	if data["email"] == usercheck.Email {
		SendData(http.StatusBadRequest, [][]string{{"error"}, {"email already exists"}}, w, r)
		return
	}

	user, err := queries.UserUpdateEmail(ctx, db_data.UserUpdateEmailParams{
		ID:        int64(user_id),
		Email:     data["email"],
		UpdatedAt: sql.NullTime{Time: time.Now(), Valid: true},
	})
	err = SqlErrorHandler(err, w, r)
	if err != nil {
		return
	}

	_, err = queries.UserUpdateIsActive(ctx, db_data.UserUpdateIsActiveParams{
		ID:        int64(user_id),
		Isactive:  sql.NullBool{Bool: false, Valid: false},
		UpdatedAt: sql.NullTime{Time: time.Now(), Valid: true},
	})
	err = SqlErrorHandler(err, w, r)
	if err != nil {
		return
	}

	one_time, err := GenerateOneTimeToken(32, uint(user.ID))
	err = InternalServerErrorHandler(err, w, r)
	if err != nil {
		return
	}

	err = SendEmail(user.Email, "Activate Your Email", fmt.Sprintf("%s/activate/?token=%s", os.Getenv("DOMAIN"), one_time), EmailVerificationTemplate, w, r)
	if err != nil {
		return
	}

	err = Logging(queries, ctx, "user", "update", user.ID, int64(user_id), w, r)
	if err != nil {
		return
	}

	SendData(http.StatusOK, [][]string{{"message"}, {"email updated successfully"}}, w, r)
}

func ChangePasswordRequest(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		SendData(http.StatusMethodNotAllowed, [][]string{{"error"}, {"method not allowed"}}, w, r)
		return
	}

	ctx := r.Context()
	auth := ctx.Value(Current_user)
	if auth == nil {
		SendData(http.StatusInternalServerError, [][]string{{"error"}, {"there is no current user"}}, w, r)
		return
	}

	authUser := auth.(db_data.AuthUserReadRow)

	one_time, err := GenerateOneTimeToken(32, uint(authUser.ID))
	err = InternalServerErrorHandler(err, w, r)
	if err != nil {
		return
	}

	err = SendEmail(authUser.Email, "Change Your Password", fmt.Sprintf("%s/change-password/?token=%s", os.Getenv("DOMAIN"), one_time), ChangePasswordVerificationTemplate, w, r) // send email
	if err != nil {
		return
	}
	queries := db_data.New(DB)

	err = AuthLogout(queries, ctx, w, r)
	if err != nil {
		return
	}

	SendData(http.StatusOK, [][]string{{"message"}, {"email sent"}}, w, r)
}

func ChangePassword(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPut {
		SendData(http.StatusMethodNotAllowed, [][]string{{"error"}, {"method not allowed"}}, w, r)
		return
	}

	queryParams := r.URL.Query()
	token := queryParams.Get("token")
	user_id, err := VerifyToken(token) // verify token
	if err != nil {
		SendData(http.StatusBadRequest, [][]string{{"error"}, {"invalid auth token"}}, w, r)
		return
	}

	queries := db_data.New(DB)
	ctx := r.Context()
	u, err := queries.UserRead(ctx, int64(user_id))
	err = SqlErrorHandler(err, w, r)
	if err != nil {
		return
	}

	user, err := queries.UserLoginRead(ctx, u.Email)
	err = SqlErrorHandler(err, w, r)
	if err != nil {
		return
	}

	data := make(map[string]string)
	err = GetData(&data, w, r) // get data
	if err != nil {
		return
	}

	check := CheckPasswordHash(data["old_password"], user.Password)
	if !check {
		SendData(http.StatusBadRequest, [][]string{{"error"}, {"invalid password"}}, w, r)
		return
	}

	if data["new_password"] != data["confirm_password"] {
		SendData(http.StatusBadRequest, [][]string{{"error"}, {"invalid password"}}, w, r)
		return
	}

	hash, err := HashPassword(data["new_password"])
	err = InternalServerErrorHandler(err, w, r)
	if err != nil {
		return
	}

	_, err = queries.UserUpdatePassword(ctx, db_data.UserUpdatePasswordParams{
		ID:        int64(user_id),
		Password:  hash,
		UpdatedAt: sql.NullTime{Time: time.Now(), Valid: true},
	})
	err = SqlErrorHandler(err, w, r)
	if err != nil {
		return
	}

	err = Logging(queries, ctx, "user", "update", user.ID, int64(user_id), w, r)
	if err != nil {
		return
	}

	SendData(http.StatusOK, [][]string{{"message"}, {"password updated successfully"}}, w, r)
}

func ResetPasswordRequest(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		SendData(http.StatusMethodNotAllowed, [][]string{{"error"}, {"method not allowed"}}, w, r)
		return
	}

	ctx := r.Context()
	auth := ctx.Value(Current_user)
	if auth == nil {
		SendData(http.StatusInternalServerError, [][]string{{"error"}, {"there is no current user"}}, w, r)
		return
	}

	authUser := auth.(db_data.AuthUserReadRow)

	one_time, err := GenerateOneTimeToken(32, uint(authUser.ID))
	err = InternalServerErrorHandler(err, w, r)
	if err != nil {
		return
	}

	err = SendEmail(authUser.Email, "Reset Your Password", fmt.Sprintf("%s/reset-password/?token=%s", os.Getenv("DOMAIN"), one_time), ResetPasswordVerificationTemplate, w, r) // send email
	if err != nil {
		return
	}

	queries := db_data.New(DB)
	err = AuthLogout(queries, ctx, w, r)
	if err != nil {
		return
	}

	SendData(http.StatusOK, [][]string{{"message"}, {"email sent"}}, w, r)
}

func ResetPassword(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPut {
		SendData(http.StatusMethodNotAllowed, [][]string{{"error"}, {"method not allowed"}}, w, r)
		return
	}

	queryParams := r.URL.Query()
	token := queryParams.Get("token")
	user_id, err := VerifyToken(token) // verify token
	if err != nil {
		SendData(http.StatusBadRequest, [][]string{{"error"}, {"invalid auth token"}}, w, r)
		return
	}

	queries := db_data.New(DB)
	ctx := r.Context()

	u, err := queries.UserRead(ctx, int64(user_id))
	err = SqlErrorHandler(err, w, r)
	if err != nil {
		return
	}

	user, err := queries.UserLoginRead(ctx, u.Email)
	err = SqlErrorHandler(err, w, r)
	if err != nil {
		return
	}

	data := make(map[string]string)
	err = GetData(&data, w, r) // get data
	if err != nil {
		return
	}

	if data["new_password"] != data["confirm_password"] {
		SendData(http.StatusBadRequest, [][]string{{"error"}, {"invalid password"}}, w, r)
		return
	}

	hash, err := HashPassword(data["new_password"])
	err = InternalServerErrorHandler(err, w, r)
	if err != nil {
		return
	}

	_, err = queries.UserUpdatePassword(ctx, db_data.UserUpdatePasswordParams{
		ID:        int64(user_id),
		Password:  hash,
		UpdatedAt: sql.NullTime{Time: time.Now(), Valid: true},
	})
	err = SqlErrorHandler(err, w, r)
	if err != nil {
		return
	}

	err = Logging(queries, ctx, "user", "update", user.ID, int64(user_id), w, r)
	if err != nil {
		return
	}

	SendData(http.StatusOK, [][]string{{"message"}, {"password updated successfully"}}, w, r)
}

func DeleteUserRequest(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		SendData(http.StatusMethodNotAllowed, [][]string{{"error"}, {"method not allowed"}}, w, r)
		return
	}

	ctx := r.Context()
	auth := ctx.Value(Current_user)
	if auth == nil {
		SendData(http.StatusInternalServerError, [][]string{{"error"}, {"there is no current user"}}, w, r)
		return
	}

	authUser := auth.(db_data.AuthUserReadRow)

	// send email
	one_time, err := GenerateOneTimeToken(32, uint(authUser.ID))
	err = InternalServerErrorHandler(err, w, r)
	if err != nil {
		return
	}

	err = SendEmail(authUser.Email, "Delete User Account", fmt.Sprintf("%s/delete-user/?token=%s", os.Getenv("DOMAIN"), one_time), DeleteUserVerificationTemplate, w, r)
	if err != nil {
		return
	}

	queries := db_data.New(DB)
	err = AuthLogout(queries, ctx, w, r)
	if err != nil {
		return
	}

	SendData(http.StatusOK, [][]string{{"message"}, {"email sent"}}, w, r)
}

func DeleteUser(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodDelete {
		SendData(http.StatusMethodNotAllowed, [][]string{{"error"}, {"method not allowed"}}, w, r)
		return
	}

	queryParams := r.URL.Query()
	token := queryParams.Get("token")
	user_id, err := VerifyToken(token) // verify token
	if err != nil {
		SendData(http.StatusBadRequest, [][]string{{"error"}, {"invalid auth token"}}, w, r)
		return
	}

	queries := db_data.New(DB)
	ctx := r.Context()

	err = queries.UserDelete(ctx, int64(user_id))
	err = SqlErrorHandler(err, w, r)
	if err != nil {
		return
	}

	err = Logging(queries, ctx, "user", "delete", 0, int64(user_id), w, r)
	if err != nil {
		return
	}

	SendData(http.StatusOK, [][]string{{"error"}, {"user account deleted"}}, w, r)
}

// require admin
func IsActiveChange(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPut {
		SendData(http.StatusMethodNotAllowed, [][]string{{"error"}, {"method not allowed"}}, w, r)
		return
	}

	queryParams := r.URL.Query()
	user_id, err := strconv.ParseInt(queryParams.Get("user"), 10, 64)
	err = InternalServerErrorHandler(err, w, r)
	if err != nil {
		return
	}

	queries := db_data.New(DB)
	ctx := r.Context()
	auth := ctx.Value(Current_user)
	if auth == nil {
		SendData(http.StatusInternalServerError, [][]string{{"error"}, {"there is no current user"}}, w, r)
		return
	}

	authUser := auth.(db_data.AuthUserReadRow)

	// get data
	data := make(map[string]string)
	err = GetData(&data, w, r)
	if err != nil {
		return
	}

	status, err := strconv.ParseBool(data["active"])
	err = InternalServerErrorHandler(err, w, r)
	if err != nil {
		return
	}

	user, err := queries.UserUpdateIsActive(ctx, db_data.UserUpdateIsActiveParams{
		ID:        user_id,
		Isactive:  sql.NullBool{Bool: status, Valid: true},
		UpdatedAt: sql.NullTime{Time: time.Now(), Valid: true},
	})
	err = SqlErrorHandler(err, w, r)
	if err != nil {
		return
	}

	err = Logging(queries, ctx, "user", "update", user.ID, authUser.ID, w, r)
	if err != nil {
		return
	}

	SendData(http.StatusOK, [][]string{{"error"}, {"user active status updated successfully"}}, w, r)
}

func IsStaffChange(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPut {
		SendData(http.StatusMethodNotAllowed, [][]string{{"error"}, {"method not allowed"}}, w, r)
		return
	}

	queryParams := r.URL.Query()
	user_id, err := strconv.ParseInt(queryParams.Get("user"), 10, 64)
	err = InternalServerErrorHandler(err, w, r)
	if err != nil {
		return
	}

	queries := db_data.New(DB)
	ctx := r.Context()

	auth := ctx.Value(Current_user)
	if auth == nil {
		SendData(http.StatusInternalServerError, [][]string{{"error"}, {"there is no current user"}}, w, r)
		return
	}

	authUser := auth.(db_data.AuthUserReadRow)

	// get data
	data := make(map[string]string)
	err = GetData(&data, w, r)
	if err != nil {
		return
	}

	status, err := strconv.ParseBool(data["staff"])
	err = InternalServerErrorHandler(err, w, r)
	if err != nil {
		return
	}

	user, err := queries.UserUpdateIsStaff(ctx, db_data.UserUpdateIsStaffParams{
		ID:        user_id,
		Isstaff:   sql.NullBool{Bool: status, Valid: true},
		UpdatedAt: sql.NullTime{Time: time.Now(), Valid: true},
	})
	err = SqlErrorHandler(err, w, r)
	if err != nil {
		return
	}

	err = Logging(queries, ctx, "user", "update", user.ID, authUser.ID, w, r)
	if err != nil {
		return
	}

	SendData(http.StatusOK, [][]string{{"message"}, {"user staff status updated successfully"}}, w, r)
}

func Login(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		SendData(http.StatusMethodNotAllowed, [][]string{{"error"}, {"method not allowed"}}, w, r)
		return
	}

	queries := db_data.New(DB)
	ctx := r.Context()

	data := make(map[string]string) // get data
	err := GetData(&data, w, r)
	if err != nil {
		return
	}

	key, code, err := AuthLogin(queries, ctx, data)
	if code != http.StatusInternalServerError && err != nil {
		SendData(code, [][]string{{"error"}, {strings.ToLower(err.Error())}}, w, r)
		return
	} else {
		err = SqlErrorHandler(err, w, r)
		if err != nil {
			return
		}
	}

	resp := [][]string{{"auth"}, {key}}
	SendData(http.StatusOK, resp, w, r)
}

func Logout(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		SendData(http.StatusMethodNotAllowed, [][]string{{"error"}, {"method not allowed"}}, w, r)
		return
	}

	queries := db_data.New(DB)
	ctx := r.Context()
	err := AuthLogout(queries, ctx, w, r)
	if err != nil {
		return
	}

	resp := [][]string{{"message"}, {"user logged out"}}
	SendData(http.StatusOK, resp, w, r)
}

func SessionList(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		SendData(http.StatusMethodNotAllowed, [][]string{{"error"}, {"method not allowed"}}, w, r)
		return
	}

	queries := db_data.New(DB)
	ctx := r.Context()
	auth := ctx.Value(Current_user)
	if auth == nil {
		SendData(http.StatusInternalServerError, [][]string{{"error"}, {"there is no current user"}}, w, r)
		return
	}

	authUser := auth.(db_data.AuthUserReadRow)

	sessions, err := queries.SessionList(ctx)
	err = SqlErrorHandler(err, w, r)
	if err != nil {
		return
	}

	var session_s [][]string
	header := []string{"id", "key", "user_id", "created_at"}

	session_s = append(session_s, header)
	for _, s := range sessions {
		row := []string{
			strconv.FormatInt(s.ID, 10),
			s.Key,
			strconv.FormatInt(s.UserID, 10),
			s.CreatedAt.Time.Format("01-02-2006 15:04:05"),
		}
		session_s = append(session_s, row)
	}

	err = Logging(queries, ctx, "session", "list", 0, authUser.ID, w, r)
	if err != nil {
		return
	}

	SendData(http.StatusOK, session_s, w, r)
}

func LogList(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		SendData(http.StatusMethodNotAllowed, [][]string{{"error"}, {"method not allowed"}}, w, r)
		return
	}

	queries := db_data.New(DB)
	ctx := r.Context()
	auth := ctx.Value(Current_user)
	if auth == nil {
		SendData(http.StatusInternalServerError, [][]string{{"error"}, {"there is no current user"}}, w, r)
		return
	}

	authUser := auth.(db_data.AuthUserReadRow)

	logs, err := queries.LogList(ctx)
	err = SqlErrorHandler(err, w, r)
	if err != nil {
		return
	}

	var log_s [][]string
	header := []string{"id", "db_table", "action", "user_id", "object_id", "created_at"}

	log_s = append(log_s, header)
	for _, l := range logs {
		row := []string{
			strconv.FormatInt(l.ID, 10),
			l.DbTable,
			l.Action,
			strconv.FormatInt(l.UserID, 10),
			strconv.FormatInt(l.ObjectID, 10),
			l.CreatedAt.Time.Format("01-02-2006 15:04:05"),
		}
		log_s = append(log_s, row)
	}

	err = Logging(queries, ctx, "log", "list", 0, authUser.ID, w, r)
	if err != nil {
		return
	}

	SendData(http.StatusOK, log_s, w, r)
}

type currentUser string

const Current_user currentUser = "Current_user"

func ReadUser(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		queries := db_data.New(DB)
		ctx := r.Context()

		token := r.Header.Get("auth") // 1. Check for token in Authorization header
		if token == "" {              // 2. If no token found in either place, return error
			ctx = context.WithValue(ctx, Current_user, db_data.AuthUserReadRow{ID: 0}) // Store user in context
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
		queries := db_data.New(DB)
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
		queries := db_data.New(DB)
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
		queries := db_data.New(DB)
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
		Middlewares: []func(http.Handler) http.Handler{RequireAuth},
		Handler:     http.HandlerFunc(UserRead),
	}

	AuthUserReadView = View{
		Route:       "/api/current-user",
		Middlewares: []func(http.Handler) http.Handler{RequireAuth},
		Handler:     http.HandlerFunc(AuthUserRead),
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

var AuthViews = []View{
	LoginView,
	LogoutView,
	SignupView,
	ActivateEmailView,
	UserReadView,
	UserListView,
	ChangeEmailRequestView,
	ChangeEmailView,
	ChangePasswordRequestView,
	ChangePasswordView,
	ResetPasswordRequestView,
	ResetPasswordView,
	DeleteUserRequestView,
	DeleteUserView,
	IsActiveChangeView,
	IsStaffChangeView,

	SessionListView,

	LogListView,
}

/* Templates */
func base(title, link string, template func(route string) templ.Component) string {
	component := EmailBaseTemplate(title, template(link))
	htmlString, err := templ.ToGoHTML(context.Background(), component)
	if err != nil {
		panic(err)
	}

	// htmlString now holds your component as a string
	stringValue := string(htmlString)

	return stringValue
}

func EmailVerificationTemplate(route string) string {
	return base("Verify Email", route, EmailVerification)
}

func ChangeEmailVerificationTemplate(route string) string {
	return base("Change Email", route, ChangeEmailVerification)
}

func ChangePasswordVerificationTemplate(route string) string {
	return base("Change Password", route, ChangePasswordVerifcation)
}

func ResetPasswordVerificationTemplate(route string) string {
	return base("Reset Password", route, ResetPasswordVerification)
}

func DeleteUserVerificationTemplate(route string) string {
	return base("Delete User", route, DeleteUserVerification)
}

func Server() {
	mux := http.NewServeMux()

	Routes(mux, AuthViews)

	server := &http.Server{
		Addr: fmt.Sprintf(":%s", os.Getenv("PORT")), // Custom port
		//Handler:      internal.LoggingMiddleware(internal.Cors(internal.New(internal.ConfigDefault)(mux))), // Attach the mux as the handler
		Handler:      LoggingMiddleware(mux),
		ReadTimeout:  10 * time.Second, // Set read timeout
		WriteTimeout: 10 * time.Second, // Set write timeout
		IdleTimeout:  30 * time.Second, // Set idle timeout
	}

	if err := server.ListenAndServe(); err != nil {
		log.Println("Error starting server:", err)
	}
}

func CreateAdminUser() {
	reader := bufio.NewReader(os.Stdin)

	fmt.Print("Email: ")
	email, err := reader.ReadString('\n')
	if err != nil {
		fmt.Printf("Error reading email: %v\n", err)
		return
	}
	email = email[:len(email)-1] // Remove the trailing newline
	email = strings.TrimSuffix(email, "\r")

	fmt.Print("Password (input will be hidden): ")
	bytePassword, err := term.ReadPassword(int(syscall.Stdin))
	if err != nil {
		fmt.Printf("Error reading password: %v\n", err)
		return
	}
	fmt.Println() // Print a newline after password input

	password := string(bytePassword)

	hash, err := HashPassword(password)
	if err != nil {
		panic(err)
	}

	queries := db_data.New(DB)
	ctx := context.Background()

	user, err := queries.UserCreate(ctx, db_data.UserCreateParams{
		Email:     email,
		Password:  hash,
		Isactive:  sql.NullBool{Bool: true, Valid: true},
		Isstaff:   sql.NullBool{Bool: true, Valid: true},
		Isadmin:   sql.NullBool{Bool: true, Valid: true},
		CreatedAt: sql.NullTime{Time: time.Now(), Valid: true},
	})
	if err != nil {
		panic(err)
	}

	err = queries.LogCreate(ctx, db_data.LogCreateParams{
		DbTable:   "user",
		Action:    "create",
		ObjectID:  user.ID,
		UserID:    0,
		CreatedAt: sql.NullTime{Time: time.Now(), Valid: true},
	})

	if err != nil {
		panic(err)
	}
}

func main() {
	// connect to db
	db, err := sql.Open("sqlite", os.Getenv("DB"))
	if err != nil {
		log.Fatalf("%s", err.Error())
	}
	defer func() {
		if closeError := db.Close(); closeError != nil {
			fmt.Println("Error closing database", closeError)
			if err == nil {
				err = closeError
			}
		}
	}()

	DB = db

	// migrate to database
	goose.SetDialect("sqlite3")

	// Apply all "up" migrations
	err = goose.Up(DB, "migrations")
	if err != nil {
		log.Fatalf("Failed to auth apply migrations: %v", err)
	}

	log.Println("Migrations applied successfully!")

	if len(os.Args) < 1 {
		panic("There has to be exactly one argument")
	} else {
		if os.Args[1] == "createadmin" {
			CreateAdminUser()
		} else if os.Args[1] == "runserver" {
			Server()
		} else {
			panic("Invalid Argument")
		}
	}

}
