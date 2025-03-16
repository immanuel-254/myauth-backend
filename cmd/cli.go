package cmd

import (
	"bufio"
	"context"
	"database/sql"
	"fmt"
	"os"
	"strings"
	"syscall"
	"time"

	"github.com/immanuel-254/myauth-backend/auth"
	"github.com/immanuel-254/myauth-backend/auth/models"
	"github.com/immanuel-254/myauth-backend/database"
	"golang.org/x/term"
)

func CreateAdminUser() {
	reader := bufio.NewReader(os.Stdin)

	fmt.Print("Email: ")
	email, err := reader.ReadString('\n')
	if err != nil {
		fmt.Printf("Error reading email: %v\n", err)
		return
	}
	email = email[:len(email)-1] // Remove the trailing newline
	email = strings.TrimSuffix(email, "\r")

	fmt.Print("Password (input will be hidden): ")
	bytePassword, err := term.ReadPassword(int(syscall.Stdin))
	if err != nil {
		fmt.Printf("Error reading password: %v\n", err)
		return
	}
	fmt.Println() // Print a newline after password input

	password := string(bytePassword)

	hash, err := auth.HashPassword(password)
	if err != nil {
		panic(err)
	}

	queries := models.New(database.DB)
	ctx := context.Background()

	user, err := queries.UserCreate(ctx, models.UserCreateParams{
		Email:     email,
		Password:  hash,
		Isactive:  sql.NullBool{Bool: true, Valid: true},
		Isstaff:   sql.NullBool{Bool: true, Valid: true},
		Isadmin:   sql.NullBool{Bool: true, Valid: true},
		CreatedAt: sql.NullTime{Time: time.Now(), Valid: true},
	})
	if err != nil {
		panic(err)
	}

	err = queries.LogCreate(ctx, models.LogCreateParams{
		DbTable:   "user",
		Action:    "create",
		ObjectID:  user.ID,
		UserID:    0,
		CreatedAt: sql.NullTime{Time: time.Now(), Valid: true},
	})

	if err != nil {
		panic(err)
	}
}
