package main

import (
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// Secret key used to sign the JWT token
var jwtKey = []byte("my_secret_key")

// Claims struct for custom claims in JWT
type Claims struct {
	Username string `json:"username"`
	jwt.RegisteredClaims
}

// Function to create a JWT token
func createJWT(username string) (string, error) {
	// Set token claims
	claims := &Claims{
		Username: username,
		RegisteredClaims: jwt.RegisteredClaims{
			// Set the expiration time of the token
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(5 * time.Minute)),
			Issuer:    "my_app",
		},
	}

	// Create the token with the specified algorithm and claims
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	// Sign the token with the secret key
	tokenString, err := token.SignedString(jwtKey)
	if err != nil {
		return "", err
	}

	return tokenString, nil
}

// Function to decode a JWT token
func decodeJWT(tokenStr string) (*Claims, error) {
	claims := &Claims{}

	// Parse the token
	token, err := jwt.ParseWithClaims(tokenStr, claims, func(token *jwt.Token) (interface{}, error) {
		return jwtKey, nil
	})

	if err != nil {
		return nil, err
	}

	if !token.Valid {
		return nil, fmt.Errorf("invalid token")
	}

	return claims, nil
}

func main() {
	// Create a new JWT token
	token, err := createJWT("john_doe")
	if err != nil {
		fmt.Println("Error creating token:", err)
		return
	}
	fmt.Println("Generated Token:", token)

	// Decode the token
	decodedClaims, err := decodeJWT(token)
	if err != nil {
		fmt.Println("Error decoding token:", err)
		return
	}
	fmt.Printf("Decoded Claims: %+v\n", decodedClaims)
}
