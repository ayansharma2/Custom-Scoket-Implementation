package main

import (
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
)

var key = []byte("asuperstrong32bitpasswordgohere!")

func encrypt(message string) (encoded string, err error) {
	plainText := []byte(message)

	block, err := aes.NewCipher(key)

	if err != nil {
		return
	}

	cipherText := make([]byte, aes.BlockSize+len(plainText))

	iv := cipherText[:aes.BlockSize]
	if _, err = io.ReadFull(rand.Reader, iv); err != nil {
		return
	}

	stream := cipher.NewCFBEncrypter(block, iv)
	stream.XORKeyStream(cipherText[aes.BlockSize:], plainText)

	return base64.RawStdEncoding.EncodeToString(cipherText), err
}

var keypair *rsa.PrivateKey

func initKeyPair() {
	keypair, _ = rsa.GenerateKey(rand.Reader, 2048)
}

func getEncryptedKey(data string, publicKey string) string {
	res, _ := encrypt(data)
	key, err := ParseRsaPublicKeyFromPemStr(publicKey)
	if err != nil {
		fmt.Println("Get Encrypted Key Error" + err.Error())
	}
	encryptedString, _ := rsa.EncryptOAEP(sha256.New(), rand.Reader, key, []byte(res), nil)
	return base64.StdEncoding.EncodeToString(encryptedString)
}

func getDecryptedAuthToken(token []byte) string {
	decryptedBytes, _ := keypair.Decrypt(nil, []byte(token), &rsa.OAEPOptions{Hash: crypto.SHA256})
	return string(decryptedBytes)
}

func ParseRsaPublicKeyFromPemStr(pubPEM string) (*rsa.PublicKey, error) {
	block, _ := pem.Decode([]byte(pubPEM))
	if block == nil {
		return nil, errors.New("failed to parse PEM block containing the key")
	}

	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	switch pub := pub.(type) {
	case *rsa.PublicKey:
		return pub, nil
	default:
		break // fall through
	}
	return nil, errors.New("Key type is not RSA")
}

func ExportRsaPublicKeyAsPemStr(pubkey *rsa.PublicKey) (string, error) {
	pubkey_bytes, err := x509.MarshalPKIXPublicKey(pubkey)
	if err != nil {
		return "", err
	}
	pubkey_pem := pem.EncodeToMemory(
		&pem.Block{
			Type:  "RSA PUBLIC KEY",
			Bytes: pubkey_bytes,
		},
	)

	return string(pubkey_pem), nil
}

func parseAuthKey(authToken string) string {
	dec, _ := base64.StdEncoding.DecodeString(authToken)
	return getDecryptedAuthToken(dec)
}
