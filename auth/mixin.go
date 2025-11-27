package auth

import (
	"context"
	"database/sql"
	"encoding/csv"
	"errors"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/immanuel-254/myauth-backend/auth/models"
	"github.com/resend/resend-go/v2"
)

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
