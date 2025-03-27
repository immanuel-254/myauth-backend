package auth

import (
	"net/http"
	"strings"

	"github.com/immanuel-254/myauth-backend/auth/models"
	"github.com/immanuel-254/myauth-backend/database"
)

func Login(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		SendData(http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"}, w, r)
		return
	}

	queries := models.New(database.DB)
	ctx := r.Context()

	data := make(map[string]string) // get data
	err := GetData(&data, w, r)
	if err != nil {
		return
	}

	key, code, err := AuthLogin(queries, ctx, data)
	if code != http.StatusInternalServerError && err != nil {
		SendData(code, map[string]string{"error": strings.ToLower(err.Error())}, w, r)
		return
	} else {
		err = SqlErrorHandler(err, w, r)
		if err != nil {
			return
		}
	}

	resp := map[string]interface{}{"auth": key}
	SendData(http.StatusOK, resp, w, r)
}

func Logout(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		SendData(http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"}, w, r)
		return
	}

	queries := models.New(database.DB)
	ctx := r.Context()
	err := AuthLogout(queries, ctx, w, r)
	if err != nil {
		return
	}

	resp := map[string]interface{}{"message": "user logged out"}
	SendData(http.StatusOK, resp, w, r)
}

func SessionList(w http.ResponseWriter, r *http.Request) {
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

	sessions, err := queries.SessionList(ctx)
	err = SqlErrorHandler(err, w, r)
	if err != nil {
		return
	}

	err = Logging(queries, ctx, "session", "list", 0, authUser.ID, w, r)
	if err != nil {
		return
	}

	SendData(http.StatusOK, map[string]interface{}{"sessions": sessions}, w, r)
}
