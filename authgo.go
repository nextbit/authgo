package authgo

import (
	"bytes"
	"crypto/rand"
	"fmt"
	"log"

	"golang.org/x/crypto/scrypt"
)

const (
	SaltLength = 64
	HashLength = 64
)

type PasswordSalt struct {
	Hash string
	Salt string
}

//Create the salt to be used on generating password hash
func generateSalt() string {
	data := make([]byte, SaltLength)
	_, err := rand.Read(data)
	if err != nil {
		log.Println(err.Error())
	}

	return fmt.Sprintf("%x", data)
}

//Prepend the generated salt with the raw password passed by the user
func prependSalt(salt, rawPass string) string {
	var buffer bytes.Buffer
	buffer.WriteString(salt)
	buffer.WriteString(rawPass)
	return buffer.String()
}

//Hash the password using the scrypt
func hashPassword(salt, rawPass string) string {
	hash, err := scrypt.Key([]byte(rawPass), []byte(salt), 16384, 8, 1, HashLength)
	if err != nil {
		log.Println(err.Error())
	}
	return fmt.Sprintf("%x", hash)
}

//Return a PasswordSalt struct with the hash and salt values
func CreatePassword(rawPass string) PasswordSalt {
	salt := generateSalt()
	hash := hashPassword(salt, rawPass)
	passwordSalt := PasswordSalt{Hash: hash, Salt: salt}

	return passwordSalt
}

//Test if the the given password match the real user password
func PasswordMatch(rawPass string, pwSalt PasswordSalt) bool {
	hash := hashPassword(pwSalt.Salt, rawPass)
	return pwSalt.Hash == hash
}
