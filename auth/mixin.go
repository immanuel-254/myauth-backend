package auth

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/immanuel-254/myauth-backend/auth/models"
	"github.com/resend/resend-go/v2"
)

func GetData(data *map[string]string, w http.ResponseWriter, r *http.Request) error {
	if err := json.NewDecoder(r.Body).Decode(&data); err != nil {
		if errors.Is(err, io.EOF) {
			SendData(http.StatusBadRequest, map[string]string{"error": "empty request body"}, w, r)
			return err
		}
		if _, ok := err.(*json.SyntaxError); ok {
			SendData(http.StatusBadRequest, map[string]string{"error": "invalid json syntax"}, w, r)
			return err
		}
		SendData(http.StatusBadRequest, map[string]string{"error": strings.ToLower(err.Error())}, w, r)
		return err
	}

	if data == nil || len(*data) == 0 { // Check if the decoded data is empty
		SendData(http.StatusBadRequest, map[string]string{"error": strings.ToLower("no data provided")}, w, r)
		return errors.New("no data provided")
	}

	return nil
}

func SendData(status int, data any, w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(status)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(data)
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
		SendData(http.StatusInternalServerError, map[string]string{"error": strings.ToLower(err.Error())}, w, r)
		return err
	}

	return err
}

func Logging(queries *models.Queries, ctx context.Context, dbtable, action string, objectId, userId int64, w http.ResponseWriter, r *http.Request) error {
	err := queries.LogCreate(ctx, models.LogCreateParams{
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

func AuthLogout(queries *models.Queries, ctx context.Context, w http.ResponseWriter, r *http.Request) error {
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

	err = queries.LogCreate(ctx, models.LogCreateParams{
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
		SendData(http.StatusInternalServerError, map[string]string{"error": err.Error()}, w, r)
		return err
	}

	return nil
}

func SqlErrorHandler(err error, w http.ResponseWriter, r *http.Request) error {
	if err != nil {
		switch err {
		case sql.ErrNoRows:
			SendData(http.StatusNoContent, map[string]string{"error": "no data"}, w, r)
			return err
		default:
			SendData(http.StatusInternalServerError, map[string]string{"error": strings.ToLower(err.Error())}, w, r)
			return err
		}
	}
	return nil
}
