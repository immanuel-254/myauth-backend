package auth

import (
	"net/http"
	"strconv"

	"github.com/immanuel-254/myauth-backend/auth/models"
	"github.com/immanuel-254/myauth-backend/database"
)

func LogList(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		SendData(http.StatusMethodNotAllowed, [][]string{{"error"}, {"method not allowed"}}, w, r)
		return
	}

	queries := models.New(database.DB)
	ctx := r.Context()
	auth := ctx.Value(Current_user)
	if auth == nil {
		SendData(http.StatusInternalServerError, [][]string{{"error"}, {"there is no current user"}}, w, r)
		return
	}

	authUser := auth.(models.AuthUserReadRow)

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
