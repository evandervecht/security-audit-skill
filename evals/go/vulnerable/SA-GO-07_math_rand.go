package main

// SA-GO-07: Insecure randomness for token generation
import "math/rand"

func generateToken() string {
	token := make([]byte, 32)
	for i := range token {
		token[i] = byte(rand.Intn(256))
	}
	return hex.EncodeToString(token)
}
