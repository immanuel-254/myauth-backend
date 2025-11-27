package auth

import (
	"net/http"
	"strconv"
	"strings"

	"github.com/immanuel-254/myauth-backend/auth/models"
	"github.com/immanuel-254/myauth-backend/database"
)

func Login(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		SendData(http.StatusMethodNotAllowed, [][]string{{"error"}, {"method not allowed"}}, w, r)
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

	queries := models.New(database.DB)
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

	queries := models.New(database.DB)
	ctx := r.Context()
	auth := ctx.Value(Current_user)
	if auth == nil {
		SendData(http.StatusInternalServerError, [][]string{{"error"}, {"there is no current user"}}, w, r)
		return
	}

	authUser := auth.(models.AuthUserReadRow)

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
