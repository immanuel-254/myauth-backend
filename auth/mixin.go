package auth

import (
	"context"
	"database/sql"
	"encoding/json"
	"net/http"
	"os"
	"time"

	"github.com/immanuel-254/myauth-backend/auth/models"
	"github.com/resend/resend-go/v2"
)

func GetData(data *map[string]string, w http.ResponseWriter, r *http.Request) {
	if err := json.NewDecoder(r.Body).Decode(&data); err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusNotFound)
		json.NewEncoder(w).Encode(err)
		return
	}
}

func SendData(status int, data any, w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(status)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(data)
}

func SendEmail(email, subject, link string, template func(route string) string, w http.ResponseWriter, r *http.Request) int {
	// send email
	client := resend.NewClient(os.Getenv("RESENDAPIKEY"))

	params := &resend.SendEmailRequest{
		From:    os.Getenv("RESENDEMAIL"),
		To:      []string{email},
		Html:    template(link),
		Subject: subject,
	}

	_, err := client.Emails.Send(params)
	if err != nil {
		SendData(http.StatusInternalServerError, map[string]string{"error": err.Error()}, w, r)
		return http.StatusInternalServerError
	}

	return http.StatusOK
}

func Logging(queries *models.Queries, ctx context.Context, dbtable, action string, objectId, userId int64, w http.ResponseWriter, r *http.Request) {
	err := queries.LogCreate(ctx, models.LogCreateParams{
		DbTable:   dbtable,
		Action:    action,
		ObjectID:  objectId,
		UserID:    userId,
		CreatedAt: sql.NullTime{Time: time.Now(), Valid: true},
	})

	if err != nil {
		SendData(http.StatusInternalServerError, map[string]string{"error": err.Error()}, w, r)
		return
	}
}

func AuthLogout(queries *models.Queries, ctx context.Context, w http.ResponseWriter, r *http.Request) {
	session, err := queries.SessionRead(ctx, r.Header.Get("auth"))

	if err != nil {
		if err == sql.ErrNoRows {
			SendData(http.StatusNotFound, map[string]string{"error": "session not found"}, w, r)
			return
		}
		SendData(http.StatusInternalServerError, map[string]string{"error": err.Error()}, w, r)
		return
	}

	// delete session
	err = queries.SessionDelete(ctx, r.Header.Get("auth"))

	if err != nil {
		SendData(http.StatusInternalServerError, map[string]string{"error": err.Error()}, w, r)
		return
	}

	err = queries.LogCreate(ctx, models.LogCreateParams{
		DbTable:   "session",
		Action:    "delete",
		ObjectID:  session.ID,
		UserID:    session.UserID,
		CreatedAt: sql.NullTime{Time: time.Now(), Valid: true},
	})

	if err != nil {
		SendData(http.StatusInternalServerError, map[string]string{"error": err.Error()}, w, r)
		return
	}

}
