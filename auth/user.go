package auth

import (
	"database/sql"
	"fmt"
	"net/http"
	"os"
	"strconv"
	"time"

	"github.com/immanuel-254/myauth-backend/auth/models"
	"github.com/immanuel-254/myauth-backend/database"
)

func Signup(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		SendData(http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"}, w, r)
		return
	}

	queries := models.New(database.DB)
	ctx := r.Context()

	// get data
	data := make(map[string]string)
	code, errstring := GetData(&data, w, r)
	if code != http.StatusOK {
		SendData(code, map[string]string{"error": errstring}, w, r)
		return
	}

	// check if password match
	if data["password"] != data["confirm-password"] {
		SendData(http.StatusBadRequest, map[string]string{"error": "invalid password"}, w, r)
		return
	}

	// hash password
	hash, err := HashPassword(data["password"])

	code, errstring = InternalServerErrorHandler(err, w, r)
	if code != http.StatusOK {
		SendData(code, map[string]string{"error": errstring}, w, r)
		return
	}

	// create user
	user, err := queries.UserCreate(ctx, models.UserCreateParams{
		Email:     data["email"],
		Password:  hash,
		Isactive:  sql.NullBool{Bool: false, Valid: true},
		Isstaff:   sql.NullBool{Bool: false, Valid: true},
		Isadmin:   sql.NullBool{Bool: false, Valid: true},
		CreatedAt: sql.NullTime{Time: time.Now(), Valid: true},
	})

	code, errstring = SqlErrorHandler(err, w, r)
	if code != http.StatusOK {
		SendData(code, map[string]string{"error": errstring}, w, r)
		return
	}

	status := Logging(queries, ctx, "user", "create", user.ID, 0, w, r)

	if status != http.StatusOK {
		return
	}

	// send email
	one_time, err := GenerateOneTimeToken(32, uint(user.ID))

	code, errstring = InternalServerErrorHandler(err, w, r)
	if code != http.StatusOK {
		SendData(code, map[string]string{"error": errstring}, w, r)
		return
	}

	status = SendEmail(user.Email, "Activate Your Email", fmt.Sprintf("%s/activate/?token=%s", os.Getenv("DOMAIN"), one_time), EmailVerificationTemplate, w, r)

	if status != http.StatusOK {
		return
	}

	resp := map[string]interface{}{"message": "signup successful"}
	SendData(status, resp, w, r)

}

func ActivateEmail(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		SendData(http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"}, w, r)
		return
	}

	queryParams := r.URL.Query()

	token := queryParams.Get("token")

	// verify token
	user_id, err := VerifyToken(token)

	if err != nil {
		SendData(http.StatusBadRequest, map[string]string{"error": "invalid auth token"}, w, r)
		return
	}

	queries := models.New(database.DB)
	ctx := r.Context()

	// activate user
	user, err := queries.UserUpdateIsActive(ctx, models.UserUpdateIsActiveParams{
		ID:        int64(user_id),
		Isactive:  sql.NullBool{Bool: true, Valid: true},
		UpdatedAt: sql.NullTime{Time: time.Now(), Valid: true},
	})

	code, errstring := SqlErrorHandler(err, w, r)
	if code != http.StatusOK {
		SendData(code, map[string]string{"error": errstring}, w, r)
		return
	}

	status := Logging(queries, ctx, "user", "update", user.ID, int64(user_id), w, r)
	if status != http.StatusOK {
		return
	}

	resp := map[string]interface{}{"message": "email has been verified"}
	SendData(http.StatusOK, resp, w, r)
}

func UserRead(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		SendData(http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"}, w, r)
		return
	}

	queryParams := r.URL.Query()

	user_id, err := strconv.ParseInt(queryParams.Get("user"), 10, 64)

	code, errstring := InternalServerErrorHandler(err, w, r)
	if code != http.StatusOK {
		SendData(code, map[string]string{"error": errstring}, w, r)
		return
	}

	if user_id == 0 {
		SendData(http.StatusNotFound, map[string]string{"error": "user not found"}, w, r)
		return
	}

	queries := models.New(database.DB)
	ctx := r.Context()

	auth := ctx.Value(Current_user)

	if auth == nil {
		SendData(http.StatusInternalServerError, map[string]string{"error": "there is no current user"}, w, r)
		return
	}

	authUser := auth.(models.AuthUserReadRow)

	user, err := queries.UserRead(ctx, user_id)

	code, errstring = SqlErrorHandler(err, w, r)
	if code != http.StatusOK {
		SendData(code, map[string]string{"error": errstring}, w, r)
		return
	}

	status := Logging(queries, ctx, "user", "read", user.ID, authUser.ID, w, r)

	if status != http.StatusOK {
		return
	}

	SendData(http.StatusOK, map[string]interface{}{"user": user}, w, r)
}

func AuthUserRead(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		SendData(http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"}, w, r)
		return
	}

	ctx := r.Context()

	auth := ctx.Value(Current_user)

	if auth == nil {
		SendData(http.StatusNotFound, map[string]string{"error": "there is no current user"}, w, r)
		return
	}

	authUser := auth.(models.AuthUserReadRow)

	SendData(http.StatusOK, map[string]interface{}{"current_user": authUser}, w, r)
}

func UserList(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		SendData(http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"}, w, r)
		return
	}

	queries := models.New(database.DB)

	ctx := r.Context()

	auth := ctx.Value(Current_user)

	if auth == nil {
		SendData(http.StatusInternalServerError, map[string]string{"error": "there is no current user"}, w, r)
		return
	}

	authUser := auth.(models.AuthUserReadRow)

	users, err := queries.UserList(ctx)

	code, errstring := SqlErrorHandler(err, w, r)
	if code != http.StatusOK {
		SendData(code, map[string]string{"error": errstring}, w, r)
		return
	}

	status := Logging(queries, ctx, "user", "list", 0, authUser.ID, w, r)
	if status != http.StatusOK {
		return
	}

	SendData(http.StatusOK, map[string]interface{}{"users": users}, w, r)
}

// Require auth
func ChangeEmailRequest(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		SendData(http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"}, w, r)
		return
	}

	// get data
	data := make(map[string]string)
	code, errstring := GetData(&data, w, r)
	if code != http.StatusOK {
		SendData(code, map[string]string{"error": errstring}, w, r)
		return
	}

	ctx := r.Context()

	auth := ctx.Value(Current_user)

	if auth == nil {
		SendData(http.StatusInternalServerError, map[string]string{"error": "there is no current user"}, w, r)
		return
	}

	authUser := auth.(models.AuthUserReadRow)

	if data["email"] != authUser.Email {
		SendData(http.StatusBadRequest, map[string]string{"error": "invalid email"}, w, r)
		return
	}
	queries := models.New(database.DB)

	// send email
	one_time, err := GenerateOneTimeToken(32, uint(authUser.ID))

	code, errstring = InternalServerErrorHandler(err, w, r)
	if code != http.StatusOK {
		SendData(code, map[string]string{"error": errstring}, w, r)
		return
	}

	status := SendEmail(data["email"], "Change Your Email", fmt.Sprintf("%s/change-email/?token=%s", os.Getenv("DOMAIN"), one_time), ChangeEmailVerificationTemplate, w, r)

	if status != http.StatusOK {
		return
	}
	code, errstring = AuthLogout(queries, ctx, w, r)
	if code != http.StatusOK {
		SendData(code, map[string]string{"error": errstring}, w, r)
		return
	}

	SendData(status, map[string]interface{}{"message": "email sent"}, w, r)

}

func ChangeEmail(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPut {
		SendData(http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"}, w, r)
		return
	}

	queryParams := r.URL.Query()

	token := queryParams.Get("token")

	// verify token
	user_id, err := VerifyToken(token)

	if err != nil {
		SendData(http.StatusBadRequest, map[string]string{"error": "invalid auth token"}, w, r)
		return
	}

	queries := models.New(database.DB)
	ctx := r.Context()

	// get data
	data := make(map[string]string)
	code, errstring := GetData(&data, w, r)
	if code != http.StatusOK {
		SendData(code, map[string]string{"error": errstring}, w, r)
		return
	}

	usercheck, _ := queries.UserLoginRead(ctx, data["email"])

	if data["email"] == usercheck.Email {
		SendData(http.StatusBadRequest, map[string]string{"error": "email already exists"}, w, r)
		return
	}

	user, err := queries.UserUpdateEmail(ctx, models.UserUpdateEmailParams{
		ID:        int64(user_id),
		Email:     data["email"],
		UpdatedAt: sql.NullTime{Time: time.Now(), Valid: true},
	})

	code, errstring = SqlErrorHandler(err, w, r)
	if code != http.StatusOK {
		SendData(code, map[string]string{"error": errstring}, w, r)
		return
	}

	_, err = queries.UserUpdateIsActive(ctx, models.UserUpdateIsActiveParams{
		ID:        int64(user_id),
		Isactive:  sql.NullBool{Bool: false, Valid: false},
		UpdatedAt: sql.NullTime{Time: time.Now(), Valid: true},
	})

	code, errstring = SqlErrorHandler(err, w, r)
	if code != http.StatusOK {
		SendData(code, map[string]string{"error": errstring}, w, r)
		return
	}

	one_time, err := GenerateOneTimeToken(32, uint(user.ID))

	code, errstring = InternalServerErrorHandler(err, w, r)
	if code != http.StatusOK {
		SendData(code, map[string]string{"error": errstring}, w, r)
		return
	}

	status := SendEmail(user.Email, "Activate Your Email", fmt.Sprintf("%s/activate/?token=%s", os.Getenv("DOMAIN"), one_time), EmailVerificationTemplate, w, r)

	if status != http.StatusOK {
		return
	}

	status = Logging(queries, ctx, "user", "update", user.ID, int64(user_id), w, r)
	if status != http.StatusOK {
		return
	}

	SendData(http.StatusOK, map[string]interface{}{"message": "email updated successfully"}, w, r)
}

func ChangePasswordRequest(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		SendData(http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"}, w, r)
		return
	}

	ctx := r.Context()

	auth := ctx.Value(Current_user)

	if auth == nil {
		SendData(http.StatusInternalServerError, map[string]string{"error": "there is no current user"}, w, r)
		return
	}

	authUser := auth.(models.AuthUserReadRow)

	// send email
	one_time, err := GenerateOneTimeToken(32, uint(authUser.ID))

	code, errstring := InternalServerErrorHandler(err, w, r)
	if code != http.StatusOK {
		SendData(code, map[string]string{"error": errstring}, w, r)
		return
	}

	status := SendEmail(authUser.Email, "Change Your Password", fmt.Sprintf("%s/change-password/?token=%s", os.Getenv("DOMAIN"), one_time), ChangePasswordVerificationTemplate, w, r)

	if status != http.StatusOK {
		return
	}
	queries := models.New(database.DB)

	code, errstring = AuthLogout(queries, ctx, w, r)
	if code != http.StatusOK {
		SendData(code, map[string]string{"error": errstring}, w, r)
		return
	}

	SendData(status, map[string]interface{}{"message": "email sent"}, w, r)

}

func ChangePassword(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPut {
		SendData(http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"}, w, r)
		return
	}

	queryParams := r.URL.Query()

	token := queryParams.Get("token")

	// verify token
	user_id, err := VerifyToken(token)

	if err != nil {
		SendData(http.StatusBadRequest, map[string]string{"error": "invalid auth token"}, w, r)
		return
	}

	queries := models.New(database.DB)
	ctx := r.Context()

	u, err := queries.UserRead(ctx, int64(user_id))

	code, errstring := SqlErrorHandler(err, w, r)
	if code != http.StatusOK {
		SendData(code, map[string]string{"error": errstring}, w, r)
		return
	}

	user, err := queries.UserLoginRead(ctx, u.Email)

	code, errstring = SqlErrorHandler(err, w, r)
	if code != http.StatusOK {
		SendData(code, map[string]string{"error": errstring}, w, r)
		return
	}

	// get data
	data := make(map[string]string)
	code, errstring = GetData(&data, w, r)
	if code != http.StatusOK {
		SendData(code, map[string]string{"error": errstring}, w, r)
		return
	}

	check := CheckPasswordHash(data["old_password"], user.Password)

	if !check {
		SendData(http.StatusBadRequest, map[string]string{"error": "invalid password"}, w, r)
		return
	}

	if data["new_password"] != data["confirm_password"] {
		SendData(http.StatusBadRequest, map[string]string{"error": "invalid password"}, w, r)
		return
	}

	hash, err := HashPassword(data["new_password"])

	code, errstring = InternalServerErrorHandler(err, w, r)
	if code != http.StatusOK {
		SendData(code, map[string]string{"error": errstring}, w, r)
		return
	}

	_, err = queries.UserUpdatePassword(ctx, models.UserUpdatePasswordParams{
		ID:        int64(user_id),
		Password:  hash,
		UpdatedAt: sql.NullTime{Time: time.Now(), Valid: true},
	})

	code, errstring = SqlErrorHandler(err, w, r)
	if code != http.StatusOK {
		SendData(code, map[string]string{"error": errstring}, w, r)
		return
	}

	status := Logging(queries, ctx, "user", "update", user.ID, int64(user_id), w, r)
	if status != http.StatusOK {
		return
	}

	SendData(http.StatusOK, map[string]interface{}{"message": "password updated successfully"}, w, r)
}

func ResetPasswordRequest(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		SendData(http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"}, w, r)
		return
	}

	ctx := r.Context()

	auth := ctx.Value(Current_user)

	if auth == nil {
		SendData(http.StatusInternalServerError, map[string]string{"error": "there is no current user"}, w, r)
		return
	}

	authUser := auth.(models.AuthUserReadRow)

	// send email
	one_time, err := GenerateOneTimeToken(32, uint(authUser.ID))

	code, errstring := InternalServerErrorHandler(err, w, r)
	if code != http.StatusOK {
		SendData(code, map[string]string{"error": errstring}, w, r)
		return
	}

	status := SendEmail(authUser.Email, "Reset Your Password", fmt.Sprintf("%s/reset-password/?token=%s", os.Getenv("DOMAIN"), one_time), ResetPasswordVerificationTemplate, w, r)

	if status != http.StatusOK {
		return
	}
	queries := models.New(database.DB)
	code, errstring = AuthLogout(queries, ctx, w, r)
	if code != http.StatusOK {
		SendData(code, map[string]string{"error": errstring}, w, r)
		return
	}
	SendData(status, map[string]interface{}{"message": "email sent"}, w, r)
}

func ResetPassword(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPut {
		SendData(http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"}, w, r)
		return
	}

	queryParams := r.URL.Query()

	token := queryParams.Get("token")

	// verify token
	user_id, err := VerifyToken(token)

	if err != nil {
		SendData(http.StatusBadRequest, map[string]string{"error": "invalid auth token"}, w, r)
		return
	}

	queries := models.New(database.DB)
	ctx := r.Context()

	u, err := queries.UserRead(ctx, int64(user_id))

	code, errstring := SqlErrorHandler(err, w, r)
	if code != http.StatusOK {
		SendData(code, map[string]string{"error": errstring}, w, r)
		return
	}

	user, err := queries.UserLoginRead(ctx, u.Email)

	code, errstring = SqlErrorHandler(err, w, r)
	if code != http.StatusOK {
		SendData(code, map[string]string{"error": errstring}, w, r)
		return
	}

	// get data
	data := make(map[string]string)
	code, errstring = GetData(&data, w, r)
	if code != http.StatusOK {
		SendData(code, map[string]string{"error": errstring}, w, r)
		return
	}

	if data["new_password"] != data["confirm_password"] {
		SendData(http.StatusBadRequest, map[string]string{"error": "invalid password"}, w, r)
		return
	}

	hash, err := HashPassword(data["new_password"])

	code, errstring = InternalServerErrorHandler(err, w, r)
	if code != http.StatusOK {
		SendData(code, map[string]string{"error": errstring}, w, r)
		return
	}

	_, err = queries.UserUpdatePassword(ctx, models.UserUpdatePasswordParams{
		ID:        int64(user_id),
		Password:  hash,
		UpdatedAt: sql.NullTime{Time: time.Now(), Valid: true},
	})

	code, errstring = SqlErrorHandler(err, w, r)
	if code != http.StatusOK {
		SendData(code, map[string]string{"error": errstring}, w, r)
		return
	}

	status := Logging(queries, ctx, "user", "update", user.ID, int64(user_id), w, r)
	if status != http.StatusOK {
		return
	}

	SendData(http.StatusOK, map[string]interface{}{"message": "password updated successfully"}, w, r)
}

func DeleteUserRequest(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		SendData(http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"}, w, r)
		return
	}

	ctx := r.Context()

	auth := ctx.Value(Current_user)

	if auth == nil {
		SendData(http.StatusInternalServerError, map[string]string{"error": "there is no current user"}, w, r)
		return
	}

	authUser := auth.(models.AuthUserReadRow)

	// send email
	one_time, err := GenerateOneTimeToken(32, uint(authUser.ID))

	code, errstring := InternalServerErrorHandler(err, w, r)
	if code != http.StatusOK {
		SendData(code, map[string]string{"error": errstring}, w, r)
		return
	}

	status := SendEmail(authUser.Email, "Delete User Account", fmt.Sprintf("%s/delete-user/?token=%s", os.Getenv("DOMAIN"), one_time), DeleteUserVerificationTemplate, w, r)

	if status != http.StatusOK {
		return
	}
	queries := models.New(database.DB)
	code, errstring = AuthLogout(queries, ctx, w, r)
	if code != http.StatusOK {
		SendData(code, map[string]string{"error": errstring}, w, r)
		return
	}
	SendData(status, map[string]interface{}{"message": "email sent"}, w, r)
}

func DeleteUser(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodDelete {
		SendData(http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"}, w, r)
		return
	}

	queryParams := r.URL.Query()

	token := queryParams.Get("token")

	// verify token
	user_id, err := VerifyToken(token)

	if err != nil {
		SendData(http.StatusBadRequest, map[string]string{"error": "invalid auth token"}, w, r)
		return
	}

	queries := models.New(database.DB)
	ctx := r.Context()

	err = queries.UserDelete(ctx, int64(user_id))

	code, errstring := SqlErrorHandler(err, w, r)
	if code != http.StatusOK {
		SendData(code, map[string]string{"error": errstring}, w, r)
		return
	}

	status := Logging(queries, ctx, "user", "delete", 0, int64(user_id), w, r)
	if status != http.StatusOK {
		return
	}

	SendData(http.StatusOK, map[string]interface{}{"message": "user account deleted"}, w, r)
}

// require admin
func IsActiveChange(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPut {
		SendData(http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"}, w, r)
		return
	}

	queryParams := r.URL.Query()

	user_id, err := strconv.ParseInt(queryParams.Get("user"), 10, 64)

	code, errstring := InternalServerErrorHandler(err, w, r)
	if code != http.StatusOK {
		SendData(code, map[string]string{"error": errstring}, w, r)
		return
	}

	queries := models.New(database.DB)
	ctx := r.Context()

	auth := ctx.Value(Current_user)

	if auth == nil {
		SendData(http.StatusInternalServerError, map[string]string{"error": "there is no current user"}, w, r)
		return
	}

	authUser := auth.(models.AuthUserReadRow)

	// get data
	data := make(map[string]string)
	code, errstring = GetData(&data, w, r)
	if code != http.StatusOK {
		SendData(code, map[string]string{"error": errstring}, w, r)
		return
	}

	status, err := strconv.ParseBool(data["active"])

	code, errstring = InternalServerErrorHandler(err, w, r)
	if code != http.StatusOK {
		SendData(code, map[string]string{"error": errstring}, w, r)
		return
	}

	user, err := queries.UserUpdateIsActive(ctx, models.UserUpdateIsActiveParams{
		ID:        user_id,
		Isactive:  sql.NullBool{Bool: status, Valid: true},
		UpdatedAt: sql.NullTime{Time: time.Now(), Valid: true},
	})

	code, errstring = SqlErrorHandler(err, w, r)
	if code != http.StatusOK {
		SendData(code, map[string]string{"error": errstring}, w, r)
		return
	}

	code = Logging(queries, ctx, "user", "update", user.ID, authUser.ID, w, r)

	if code != http.StatusOK {
		return
	}

	SendData(http.StatusOK, map[string]interface{}{"message": "user active status updated successfully"}, w, r)
}

func IsStaffChange(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPut {
		SendData(http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"}, w, r)
		return
	}

	queryParams := r.URL.Query()

	user_id, err := strconv.ParseInt(queryParams.Get("user"), 10, 64)

	code, errstring := InternalServerErrorHandler(err, w, r)
	if code != http.StatusOK {
		SendData(code, map[string]string{"error": errstring}, w, r)
		return
	}

	queries := models.New(database.DB)
	ctx := r.Context()

	auth := ctx.Value(Current_user)

	if auth == nil {
		SendData(http.StatusInternalServerError, map[string]string{"error": "there is no current user"}, w, r)
		return
	}

	authUser := auth.(models.AuthUserReadRow)

	// get data
	data := make(map[string]string)
	code, errstring = GetData(&data, w, r)
	if code != http.StatusOK {
		SendData(code, map[string]string{"error": errstring}, w, r)
		return
	}

	status, err := strconv.ParseBool(data["staff"])

	code, errstring = InternalServerErrorHandler(err, w, r)
	if code != http.StatusOK {
		SendData(code, map[string]string{"error": errstring}, w, r)
		return
	}

	user, err := queries.UserUpdateIsStaff(ctx, models.UserUpdateIsStaffParams{
		ID:        user_id,
		Isstaff:   sql.NullBool{Bool: status, Valid: true},
		UpdatedAt: sql.NullTime{Time: time.Now(), Valid: true},
	})

	code, errstring = SqlErrorHandler(err, w, r)
	if code != http.StatusOK {
		SendData(code, map[string]string{"error": errstring}, w, r)
		return
	}

	code = Logging(queries, ctx, "user", "update", user.ID, authUser.ID, w, r)
	if code != http.StatusOK {
		return
	}

	SendData(http.StatusOK, map[string]interface{}{"message": "user staff status updated successfully"}, w, r)
}
