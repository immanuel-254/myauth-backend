package auth

import (
	"net/http"

	"github.com/immanuel-254/myauth-backend/auth/models"
	"github.com/immanuel-254/myauth-backend/database"
)

func LogList(w http.ResponseWriter, r *http.Request) {
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

	logs, err := queries.LogList(ctx)

	if err != nil {
		SendData(http.StatusInternalServerError, map[string]string{"error": err.Error()}, w, r)
		return
	}

	Logging(queries, ctx, "log", "list", 0, authUser.ID, w, r)

	SendData(http.StatusOK, map[string]interface{}{"logs": logs}, w, r)
}
