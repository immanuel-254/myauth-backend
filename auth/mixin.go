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

func GetData(data *map[string]string, w http.ResponseWriter, r *http.Request) (int, string) {
	if err := json.NewDecoder(r.Body).Decode(&data); err != nil {
		if errors.Is(err, io.EOF) {
			return http.StatusBadRequest, "empty request body"
		}
		if _, ok := err.(*json.SyntaxError); ok {
			return http.StatusBadRequest, "invalid json syntax"
		}
		return http.StatusBadRequest, strings.ToLower(err.Error())
	}

	// Check if the decoded data is empty
	if data == nil || len(*data) == 0 {
		return http.StatusBadRequest, strings.ToLower("no data provided")
	}

	return http.StatusOK, ""
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
		SendData(http.StatusInternalServerError, map[string]string{"error": strings.ToLower(err.Error())}, w, r)
		return http.StatusInternalServerError
	}

	return http.StatusOK
}

func Logging(queries *models.Queries, ctx context.Context, dbtable, action string, objectId, userId int64, w http.ResponseWriter, r *http.Request) int {
	err := queries.LogCreate(ctx, models.LogCreateParams{
		DbTable:   dbtable,
		Action:    action,
		ObjectID:  objectId,
		UserID:    userId,
		CreatedAt: sql.NullTime{Time: time.Now(), Valid: true},
	})

	code, errstring := SqlErrorHandler(err, w, r)
	if code != http.StatusOK {
		SendData(code, map[string]string{"error": errstring}, w, r)
		return code
	}

	return http.StatusOK
}

func AuthLogout(queries *models.Queries, ctx context.Context, w http.ResponseWriter, r *http.Request) (int, string) {
	session, err := queries.SessionRead(ctx, r.Header.Get("auth"))

	code, errstring := SqlErrorHandler(err, w, r)
	if code != http.StatusOK {
		return code, errstring
	}

	// delete session
	err = queries.SessionDelete(ctx, r.Header.Get("auth"))

	code, errstring = SqlErrorHandler(err, w, r)
	if code != http.StatusOK {
		return code, errstring
	}

	err = queries.LogCreate(ctx, models.LogCreateParams{
		DbTable:   "session",
		Action:    "delete",
		ObjectID:  session.ID,
		UserID:    session.UserID,
		CreatedAt: sql.NullTime{Time: time.Now(), Valid: true},
	})

	code, errstring = SqlErrorHandler(err, w, r)
	if code != http.StatusOK {
		return code, errstring
	}

	return http.StatusOK, ""

}

func InternalServerErrorHandler(err error, w http.ResponseWriter, r *http.Request) (int, string) {
	if err != nil {
		return http.StatusInternalServerError, err.Error()
	}

	return http.StatusOK, ""
}

func SqlErrorHandler(err error, w http.ResponseWriter, r *http.Request) (int, string) {
	if err != nil {
		switch err {
		case sql.ErrNoRows:
			return http.StatusNoContent, "no data"
		case sql.ErrConnDone:
			return http.StatusInternalServerError, err.Error()
		case sql.ErrTxDone:
			return http.StatusInternalServerError, err.Error()
		default:
			return http.StatusInternalServerError, err.Error()
		}
	}

	return http.StatusOK, ""
}
