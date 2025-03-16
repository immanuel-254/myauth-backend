package auth

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"sync"
	"time"
)

type TokenStatus struct {
	Token     string
	Used      bool
	ExpiresAt time.Time
	sub       uint
}

var (
	tokenStore = make(map[string]*TokenStatus) // Token storage
	mu         sync.Mutex                      // To protect the map from concurrent access
)

// GenerateOneTimeToken generates a random token and stores its metadata
func GenerateOneTimeToken(length int, sub uint) (string, error) {
	// Create a slice to store random bytes
	token := make([]byte, length)
	_, err := rand.Read(token) // Fill the slice with random data
	if err != nil {
		return "", err
	}

	// Encode the random bytes to base64
	encodedToken := base64.URLEncoding.EncodeToString(token)

	// Store the token with metadata (used = false, expires in ttl)
	mu.Lock()
	defer mu.Unlock()

	tokenStore[encodedToken] = &TokenStatus{
		Token:     encodedToken,
		Used:      false,
		ExpiresAt: time.Now().Add(time.Minute * 15),
		sub:       sub,
	}

	return encodedToken, nil
}

// VerifyToken checks if the token is valid and not used yet
func VerifyToken(token string) (uint, error) {
	mu.Lock()
	defer mu.Unlock()

	// Check if the token exists
	tokenData, exists := tokenStore[token]
	if !exists {
		return 0, errors.New("token does not exist")
	}

	// Check if the token is expired
	if time.Now().After(tokenData.ExpiresAt) {
		return 0, errors.New("token has expired")
	}

	// Check if the token has already been used
	if tokenData.Used {
		return 0, errors.New("token has already been used")
	}

	// Mark the token as used
	tokenData.Used = true

	return tokenData.sub, nil
}
