package main

// SA-GO-07: Cryptographically secure random token generation
import "crypto/rand"

func generateToken() (string, error) {
	token := make([]byte, 32)
	if _, err := rand.Read(token); err != nil {
		return "", err
	}
	return hex.EncodeToString(token), nil
}
