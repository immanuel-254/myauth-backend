package auth

import (
	"crypto/rand"
)

func GenerateAESKey() []byte {
	key := make([]byte, 32) // AES-256 requires a 32-byte key
	_, err := rand.Read(key)
	if err != nil {
		panic(err.Error())
	}
	return key
}
