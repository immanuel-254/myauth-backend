package auth

import (
	"net/http"

	"github.com/immanuel-254/myauth-backend/auth/models"
	"github.com/immanuel-254/myauth-backend/database"
)

func Login(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		SendData(http.StatusMethodNotAllowed, map[string]string{"error": "Method Not Allowed"}, w, r)

		return
	}

	queries := models.New(database.DB)
	ctx := r.Context()

	// get data
	data := make(map[string]string)
	GetData(&data, w, r)

	key, code, err := AuthLogin(queries, ctx, data)

	if err != nil {
		//println(err.Error())
		http.Error(w, err.Error(), code)
		return
	}

	resp := map[string]interface{}{"auth": key}
	SendData(http.StatusOK, resp, w, r)
}

func Logout(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		SendData(http.StatusMethodNotAllowed, map[string]string{"error": "Method Not Allowed"}, w, r)

		return
	}

	queries := models.New(database.DB)
	ctx := r.Context()

	AuthLogout(queries, ctx, w, r)
	resp := map[string]interface{}{"message": "user logged out"}
	SendData(http.StatusOK, resp, w, r)
}

func SessionList(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		SendData(http.StatusMethodNotAllowed, map[string]string{"error": "Method Not Allowed"}, w, r)

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

	if err != nil {
		SendData(http.StatusInternalServerError, map[string]string{"error": err.Error()}, w, r)
		return
	}

	Logging(queries, ctx, "session", "list", 0, authUser.ID, w, r)

	SendData(http.StatusOK, map[string]interface{}{"sessions": sessions}, w, r)
}
